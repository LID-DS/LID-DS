import os
import csv
import json
import hashlib
import random
#import pcapkit
import zipfile
from dataloader.base_recording import BaseRecording

from dataloader.direction import Direction
from dataloader.syscall import Syscall
from dataloader.resource_statistic import ResourceStatistic
from dataloader.syscall_2021 import Syscall2021


class Recording2021(BaseRecording):
    """

        Single recording captured in 4 ways
        class provides functions to handle every type of recording
            --> syscall text file
            --> pcap packets
            --> json describing recording
            --> statistics of resources

        Args:
        path (str): path of recording
        name (str): name of file without extension

    """

    def __init__(self, path: str, name: str, direction: Direction, cache_lines: bool = False,
                 permute_seed: int = None):
        self.path = path
        self.name = name
        self._direction = direction
        self._cache_lines = cache_lines
        self._cached_lines = None
        self._metadata_cache = None
        self._permute_seed = permute_seed
        self._permuted_tids = None
        self._pair_tids = None          # pairwise shuffled TIDs (direction=BOTH)
        self._num_pairs = None          # number of entry-exit pairs (direction=BOTH)
        self._paired_open_pos = None    # set of 1-based line_ids that are OPEN
        self._paired_close_pos = None   # set of 1-based line_ids that are CLOSE
        self._pair_idx_from_open_line = None  # map: open_line_id -> pair_idx
        self.check_recording()

    def _build_permuted_tids(self, line_source):
        """Collect thread IDs in entry-exit pairs for Direction.BOTH mode.

        When direction=BOTH, each syscall appears as entry (>) followed by exit (<)
        in the stream. Both must receive the SAME permuted TID because they
        represent the same syscall in the same thread.

        Algorithm (FIFO queue per (tid, name)):
        1. For each OPEN: append its index to the queue for (tid, name)
        2. For each CLOSE: if queue is non-empty, pop from front (FIFO) and pair
        3. Collect one TID per pair, shuffle them

        For direction=OPEN or direction=CLOSE: original single-syscall behavior.

        line_source: iterable of line strings (cached list or generator).
        """
        if self._direction != Direction.BOTH:
            # Original single-syscall shuffle logic (OPEN or CLOSE only — no pairs)
            tids = []
            for line in line_source:
                sc = Syscall2021(self.path, line, line_id=-1)
                if sc.direction() == self._direction:
                    tids.append(sc.thread_id())
            seed_str = f"{self._permute_seed}_{self.path}::{self.name}"
            derived_seed = int(hashlib.md5(seed_str.encode('utf-8')).hexdigest(), 16) % (2**32)
            random.Random(derived_seed).shuffle(tids)
            return tids

        # Direction.BOTH: pairwise shuffle
        # Parse all syscalls (skip switch)
        lines = list(line_source)
        syscalls = []
        for line in lines:
            sc = Syscall2021(self.path, line, line_id=-1)
            syscalls.append(sc)

        # Forward pass: FIFO per (tid, name)
        pending_opens = {}   # (tid, name) -> list of syscall indices
        pairs = []           # (open_idx, close_idx, tid, name)
        for i, sc in enumerate(syscalls):
            key = (sc.thread_id(), sc.name())
            if sc.direction() == Direction.OPEN:
                if key not in pending_opens:
                    pending_opens[key] = []
                pending_opens[key].append(i)
            else:  # Direction.CLOSE
                if key in pending_opens and pending_opens[key]:
                    open_idx = pending_opens[key].pop(0)
                    pairs.append((open_idx, i, sc.thread_id(), sc.name()))
                # else: unpaired CLOSE

        # Collect shuffled TIDs — one per pair
        open_tids = [p[2] for p in pairs]
        seed_str = f"{self._permute_seed}_{self.path}::{self.name}"
        derived_seed = int(hashlib.md5(seed_str.encode('utf-8')).hexdigest(), 16) % (2**32)
        rng = random.Random(derived_seed)
        rng.shuffle(open_tids)

        pair_tids = list(open_tids)
        open_indices = [p[0] for p in pairs]
        close_indices = [p[1] for p in pairs]

        # Store for syscalls() to consume
        self._pair_tids = pair_tids
        self._num_pairs = len(pairs)
        self._paired_open_pos = set(oi + 1 for oi in open_indices)   # 1-based
        self._paired_close_pos = set(ci + 1 for ci in close_indices)  # 1-based
        # Map: open line_id (1-based) -> pair_idx (position in FIFO pair list)
        # open_indices is already in FIFO order, so enumerate gives the correct pair_idx
        self._pair_idx_from_open_line = {oi + 1: pi for pi, oi in enumerate(open_indices)}
        return pair_tids

    def _load_lines(self):
        """Read raw lines from ZIP into _cached_lines (idempotent)."""
        if self._cached_lines is None:
            try:
                with zipfile.ZipFile(self.path, 'r') as zipped:
                    with zipped.open(self.name + '.sc') as unzipped:
                        self._cached_lines = [line.decode('utf-8').rstrip() for line in unzipped]
            except Exception:
                raise Exception(f'Error while working with file: {self.name} at {self.path}')

    def prefetch(self):
        """Pre-decompress syscall data from ZIP into line cache.
        Call from a background thread to overlap I/O with CPU processing.
        """
        self._cache_lines = True
        self._load_lines()

    def syscalls(self):
        if self._cache_lines:
            self._load_lines()

            permuted_tids = None
            if self._permute_seed is not None:
                if self._permuted_tids is None:
                    self._permuted_tids = self._build_permuted_tids(self._cached_lines)
                permuted_tids = self._permuted_tids

            pair_idx_from_open = getattr(self, '_pair_idx_from_open_line', {})
            paired_open_pos = getattr(self, '_paired_open_pos', set())
            paired_close_pos = getattr(self, '_paired_close_pos', set())
            prev_pair_tid = None
            pair_tid_idx = 0

            for line_id, line in enumerate(self._cached_lines, start=1):
                syscall_object = Syscall2021(self.path, line, line_id=line_id)
                if self._direction == Direction.BOTH or syscall_object.direction() == self._direction:
                    if permuted_tids is not None and self._direction == Direction.BOTH:
                        if syscall_object.direction() == Direction.OPEN:
                            if line_id in paired_open_pos:
                                pair_idx = pair_idx_from_open[line_id]
                                prev_pair_tid = permuted_tids[pair_idx]
                                syscall_object._thread_id = prev_pair_tid
                                yield syscall_object
                            # else: unpaired OPEN — don't yield
                        else:
                            if line_id in paired_close_pos:
                                syscall_object._thread_id = prev_pair_tid
                                yield syscall_object
                            # else: unpaired CLOSE — don't yield
                    elif permuted_tids is not None:
                        syscall_object._thread_id = permuted_tids[pair_tid_idx]
                        pair_tid_idx += 1
                        yield syscall_object
                    else:
                        yield syscall_object
            if permuted_tids is not None and self._direction != Direction.BOTH:
                assert pair_tid_idx == len(permuted_tids), \
                    f"Filter mismatch: consumed {pair_tid_idx}, expected {len(permuted_tids)}"
        else:
            if self._permute_seed is not None:
                # Pass 1: collect thread IDs from ZIP stream; for BOTH also builds pair maps
                if self._permuted_tids is None:
                    try:
                        with zipfile.ZipFile(self.path, 'r') as zipped:
                            with zipped.open(self.name + '.sc') as unzipped:
                                line_gen = (line.decode('utf-8').rstrip() for line in unzipped)
                                self._permuted_tids = self._build_permuted_tids(line_gen)
                    except Exception:
                        raise Exception(f'Error while working with file: {self.name} at {self.path}')
                permuted_tids = self._permuted_tids

                # Pass 2: yield syscalls with permuted thread IDs
                pair_idx_from_open = getattr(self, '_pair_idx_from_open_line', {})
                paired_open_pos = getattr(self, '_paired_open_pos', set())
                paired_close_pos = getattr(self, '_paired_close_pos', set())
                prev_pair_tid = None
                pair_tid_idx = 0
                try:
                    with zipfile.ZipFile(self.path, 'r') as zipped:
                        with zipped.open(self.name + '.sc') as unzipped:
                            for line_id, raw in enumerate(unzipped, start=1):
                                syscall_object = Syscall2021(self.path, raw.decode('utf-8').rstrip(), line_id=line_id)
                                if self._direction == Direction.BOTH or syscall_object.direction() == self._direction:
                                    if permuted_tids is not None and self._direction == Direction.BOTH:
                                        if syscall_object.direction() == Direction.OPEN:
                                            if line_id in paired_open_pos:
                                                pair_idx = pair_idx_from_open[line_id]
                                                prev_pair_tid = permuted_tids[pair_idx]
                                                syscall_object._thread_id = prev_pair_tid
                                                yield syscall_object
                                            # else: unpaired OPEN — don't yield
                                        else:
                                            if line_id in paired_close_pos:
                                                syscall_object._thread_id = prev_pair_tid
                                                yield syscall_object
                                            # else: unpaired CLOSE — don't yield
                                    elif permuted_tids is not None:
                                        syscall_object._thread_id = permuted_tids[pair_tid_idx]
                                        pair_tid_idx += 1
                                        yield syscall_object
                                    else:
                                        yield syscall_object
                except Exception:
                    raise Exception(f'Error while working with file: {self.name} at {self.path}')
                if permuted_tids is not None and self._direction != Direction.BOTH:
                    assert pair_tid_idx == len(permuted_tids), \
                        f"Filter mismatch: consumed {pair_tid_idx}, expected {len(permuted_tids)}"
            else:
                try:
                    with zipfile.ZipFile(self.path, 'r') as zipped:
                        with zipped.open(self.name + '.sc') as unzipped:
                            for line_id, syscall in enumerate(unzipped, start=1):
                                syscall_object = Syscall2021(self.path, syscall.decode('utf-8').rstrip(), line_id=line_id)
                                if self._direction == Direction.BOTH or syscall_object.direction() == self._direction:
                                    yield syscall_object
                except Exception:
                    raise Exception(f'Error while working with file: {self.name} at {self.path}')

    def clear_cache(self):
        self._cached_lines = None
        self._permuted_tids = None
        self._pair_tids = None
        self._num_pairs = None
        self._paired_open_pos = None
        self._paired_close_pos = None
        self._pair_idx_from_open_line = None

    def packets(self):
        """

            Unzip and extract pcap objects,

            Returns:
            pcap obj: return pypcap Extractor object
            src:
                https://pypcapkit.jarryshaw.me/en/latest/foundation/extraction.html#pcapkit.foundation.extraction.Extractor

        """
        try:
            with zipfile.ZipFile(self.path, 'r') as zipped:
                file_list = zipped.namelist()
                for file in file_list:
                    if file.endswith('.pcap'):
                        zipped.extract(file, 'tmp')
            #obj = pcapkit.extract(fin=f'tmp/{self.name}.pcap',
            #                      engine='pyshark',
            #                      store=True,
            #                      nofile=True)
        except Exception:
            print(f'Error extracting pcap file {self.name}')
            return None
        finally:
            os.remove(f'tmp/{self.name}.pcap')

        #return obj
        return None

    def resource_stats(self) -> list:
        """

            Read .res file of recording.
            Includes usage of following resources for a point in time:
                timestamp,
                cpu_usage,
                memory_usage,
                network_received,
                network_send,
                storage_read,
                storage_written

            Returns:
            List of used resources

        """
        statistics = []
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.res') as unzipped:
                string = unzipped.read().decode('utf-8')
                reader = csv.reader(string.split('\n'), delimiter=',')
                # remove header
                next(reader)
                for row in reader:
                    if len(row) > 0:
                        statistics.append(ResourceStatistic(row))
        return statistics

    def metadata(self) -> dict:
        """

            Read json file and extract metadata as dict
            with following format:
            {"container": [
                    "ip": str,
                    "name": str,
                    "role": str
             "exploit": bool,
             "exploit_name": str,
             "image": str,
             "recording_time": int,
             "time":{
                    "container_ready": {
                        "absolute": float,
                        "source": str
                    },
                    "exploit": [
                        {
                            "absolute": float,
                            "name": str,
                            "source": str
                        }
                    ]
                    "warmup_end": {
                        "absolute": float,
                        "source": str
                    }
                }
            }

            Returns:
            dict: metadata dictionary

        """
        if self._metadata_cache is None:
            with zipfile.ZipFile(self.path, 'r') as zipped:
                with zipped.open(self.name + '.json') as unzipped:
                    unzipped_byte_json = unzipped.read()
                    self._metadata_cache = json.loads(
                        unzipped_byte_json.decode('utf-8').replace("'", '"'))
        return self._metadata_cache

    def check_recording(self) -> bool:
        """

            check if zip file exists and if all necessary files are included

            Returns:
            bool: if check was succesfull

        """
        try:
            if not os.path.isfile(self.path):
                raise Exception(f'Missing .zip file for recording: {self.path}')
            with zipfile.ZipFile(self.path, 'r') as zipped:
                file_list = zipped.namelist()
                err_str = 'Recording Error: '
                if len(file_list) != 4:
                    if self.name + '.res' not in file_list:
                        res_err = 'Missing .res file '
                        err_str += res_err
                    if self.name + '.sc' not in file_list:
                        sc_err = 'Missing .sc file '
                        err_str += sc_err
                    if self.name + '.pcap' not in file_list:
                        pcap_err = 'Missing .pcap file '
                        err_str += pcap_err
                    if self.name + '.json' not in file_list:
                        json_err = 'Missing .json file '
                        err_str += json_err
                    if not os.path.isfile('missing_files.txt'):
                        with open('missing_files.txt', 'w+') as file:
                            file.write(err_str + f'in recording: {self.path}. \n')
                    else:
                        with open('missing_files.txt', 'a') as file:
                            file.write(err_str + f'in recording: {self.path}. \n')
                    print(f'{err_str}')
                    print('Have a look in missing_files.txt file')
        except Exception:
            print(f'Error with file {self.name} at {self.path}')
            if not os.path.isfile('missing_files.txt'):
                with open('missing_files.txt', 'w+') as file:
                    file.write(err_str + f'in recording: {self.path}. \n')
            else:
                with open('missing_files.txt', 'a') as file:
                    file.write(err_str + f'in recording: {self.path}. \n')
