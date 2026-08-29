import os
import time
import hashlib
import random
import datetime

from enum import IntEnum
from typing import Generator

#from distutils.util import strtobool
from ast import literal_eval
from dataloader.direction import Direction
from dataloader.base_recording import BaseRecording
from dataloader.syscall_2019 import Syscall, Syscall2019


class RecordingDataParts(IntEnum):
    IMAGE_NAME = 0
    RECORDING_NAME = 1
    IS_EXECUTING_EXPLOIT = 2
    WARMUP_TIME = 3
    RECORDING_TIME = 4
    EXPLOIT_START_TIME = 5


class Recording2019(BaseRecording):
    """

    Single Recording built out of one line from runs.csv of LID-DS 2019

    Args:
        recording_data_list (list): runs.csv line as list
        base_path (str): the base path of the LID-DS 2019 scenario

    """
    def __init__(self, recording_data_list: list, base_path: str, direction: Direction,
                 cache_lines: bool = False, permute_seed: int = None):
        super().__init__()
        self.name = recording_data_list[RecordingDataParts.RECORDING_NAME]
        self.path = os.path.join(base_path, f'{self.name}.txt')
        self.recording_data_list = recording_data_list
        self._direction = direction
        self._cache_lines = cache_lines
        self._cached_lines = None
        self._permuted_tids = None
        self._pair_tids = None  # pairwise shuffled TIDs (one per entry-exit pair, direction=BOTH)
        # Set permute_seed AFTER _collect_metadata so that
        # _calc_absolute_exploit_time() -> self.syscalls() runs without permutation
        self._permute_seed = None
        self._metadata = self._collect_metadata()
        self.name = self._metadata['name']
        self._permute_seed = permute_seed

    def _build_permuted_tids(self, line_source):
        """Collect thread IDs in entry-exit pairs for Direction.BOTH mode.

        When direction=BOTH, each syscall appears as entry (>) followed by exit (<)
        in the stream. Both must receive the SAME permuted TID because they
        represent the same syscall in the same thread.

        Algorithm (FIFO queue per (tid, name)):
        1. For each OPEN: append its line number to the queue for (tid, name)
        2. For each CLOSE: if queue is non-empty, pop from front (FIFO) and pair
        3. Collect one TID per pair, shuffle them

        For direction=OPEN or direction=CLOSE: original single-syscall behavior.

        line_source: iterable of line strings (cached list or generator).
        """
        if self._direction != Direction.BOTH:
            # Original single-syscall shuffle logic (OPEN or CLOSE only — no pairs)
            tids = []
            for line in line_source:
                sc = Syscall2019(recording_path=self.path, syscall_line=line, line_id=-1)
                if sc.name() != 'switch':
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
            sc = Syscall2019(recording_path=self.path, syscall_line=line, line_id=-1)
            if sc.name() != 'switch':
                syscalls.append(sc)

        # Forward pass: match entries to exits using a per-(tid, name) FIFO queue.
        # Entry (>) appends to queue; matching Exit (<) consumes from queue front (FIFO).
        # This correctly handles interleaved threads: a CLOSE can only pair with
        # the OLDEST unpaired OPEN for that (tid, name), not a newer one.
        # CLOSEs that arrive before their OPEN (started before recording) are unpaired.
        pending_opens = {}  # (tid, name) -> deque of line numbers waiting for CLOSE
        pairs = []  # List of (open_line, close_line, tid, name)
        for line_num, line in enumerate(lines, start=1):
            sc = Syscall2019(recording_path=self.path, syscall_line=line, line_id=line_num)
            if sc.name() == 'switch':
                continue
            key = (sc.thread_id(), sc.name())
            if sc.direction() == Direction.OPEN:
                if key not in pending_opens:
                    pending_opens[key] = []
                pending_opens[key].append(line_num)
            else:  # Direction.CLOSE
                if key in pending_opens and pending_opens[key]:
                    # FIFO: consume the OLDEST unmatched OPEN (queue front)
                    open_line = pending_opens[key].pop(0)
                    pairs.append((open_line, line_num, sc.thread_id(), sc.name()))
                # else: unpaired CLOSE — no OPEN in flight for this (tid, name)

        # Collect the shuffled TIDs (one per paired syscall entry)
        open_tids = [p[2] for p in pairs]  # original tid per pair
        seed_str = f"{self._permute_seed}_{self.path}::{self.name}"
        derived_seed = int(hashlib.md5(seed_str.encode('utf-8')).hexdigest(), 16) % (2**32)
        rng = random.Random(derived_seed)
        rng.shuffle(open_tids)

        # Build pair_tids: shuffled TID for each pair, and store close_line -> shuffled_tid
        pair_tids = list(open_tids)
        open_lines = [p[0] for p in pairs]
        close_lines = [p[1] for p in pairs]

        # Store for syscalls() to consume
        self._pair_tids = pair_tids
        self._num_pairs = len(pairs)
        self._paired_open_pos = set(open_lines)
        self._paired_close_pos = set(close_lines)
        # Map: open_line (1-based) -> pair_idx in range(num_pairs)
        # Needed so syscalls() can do O(1) lookup: pair_tid = permuted_tids[pair_idx_from_open[line_id]]
        self._pair_idx_from_open_line = {p[0]: pi for pi, p in enumerate(pairs)}
        return pair_tids

    def syscalls(self) -> Generator[Syscall, None, None]:
        """
        Prepare stream of syscalls, yield single lines.
        Returns: Generator[Syscall, None, None]
        """
        if self._cache_lines:
            if self._cached_lines is None:
                with open(self.path, 'r') as recording_file:
                    self._cached_lines = recording_file.readlines()

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
            for line_id, syscall_line in enumerate(self._cached_lines, start=1):
                syscall_object = Syscall2019(recording_path=self.path, syscall_line=syscall_line, line_id=line_id)
                if syscall_object.name() != 'switch':
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
                # Pass 1: collect thread IDs from file stream
                if self._permuted_tids is None:
                    with open(self.path, 'r') as recording_file:
                        self._permuted_tids = self._build_permuted_tids(recording_file)
                permuted_tids = self._permuted_tids

                # Pass 2: yield syscalls with permuted thread IDs
                pair_idx_from_open = getattr(self, '_pair_idx_from_open_line', {})
                paired_open_pos = getattr(self, '_paired_open_pos', set())
                paired_close_pos = getattr(self, '_paired_close_pos', set())
                prev_pair_tid = None
                pair_tid_idx = 0
                with open(self.path, 'r') as recording_file:
                    for line_id, syscall_line in enumerate(recording_file, start=1):
                        syscall_object = Syscall2019(recording_path=self.path, syscall_line=syscall_line, line_id=line_id)
                        if syscall_object.name() != 'switch':
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
                with open(self.path, 'r') as recording_file:
                    for line_id, syscall_line in enumerate(recording_file, start=1):
                        syscall_object = Syscall2019(recording_path=self.path, syscall_line=syscall_line, line_id=line_id)
                        if syscall_object.name() != 'switch':
                            if self._direction == Direction.BOTH or syscall_object.direction() == self._direction:
                                yield syscall_object

    def prefetch(self):
        """Pre-read file data into line cache."""
        self._cache_lines = True
        if self._cached_lines is None:
            with open(self.path, 'r') as recording_file:
                self._cached_lines = recording_file.readlines()

    def clear_cache(self):
        """Frees the line cache (e.g. after all configs for this scenario are done)."""
        self._cached_lines = None
        self._permuted_tids = None
        self._pair_tids = None
        self._paired_open_pos = None
        self._paired_close_pos = None
        self._pair_idx_from_open_line = None

    def _collect_metadata(self):
        """

            transfers metadata from csv line to same same dict format as from LID-DS 2021

        """
        is_exploit_str = self.recording_data_list[RecordingDataParts.IS_EXECUTING_EXPLOIT].lower()
        is_exploit = is_exploit_str == "true" or is_exploit_str == "1" or is_exploit_str == "yes"
        return {
            'image': self.recording_data_list[RecordingDataParts.IMAGE_NAME],
            'name': self.name,
            'exploit': is_exploit,
            'recording_time': int(self.recording_data_list[RecordingDataParts.RECORDING_TIME]),
            'time': {
                'exploit': [{
                    'absolute': self._calc_absolute_exploit_time() if is_exploit is True else None,
                    'relative': int(self.recording_data_list[RecordingDataParts.EXPLOIT_START_TIME]) if is_exploit is True else None
                }],
                'warmup_end': {
                    'relative': {
                        'relative': int(self.recording_data_list[RecordingDataParts.WARMUP_TIME])
                    }
                }
            }
        }

    def metadata(self) -> dict:
        return self._metadata

    def _calc_absolute_exploit_time(self):
        """

            creates missing absolute timestamp from LID-DS 2019 metadata

        """
        syscall_generator = self.syscalls()
        first_syscall_timestamp = next(syscall_generator).timestamp_datetime()

        # subtracting 2 seconds because of bad precision of relative timestamp in LID-DS 2019
        relative_time = int(self.recording_data_list[RecordingDataParts.WARMUP_TIME]) - 2

        # multiplying with 10⁹ to get nanoseconds from seconds
        absolute_time = first_syscall_timestamp + datetime.timedelta(seconds=relative_time)

        # casting to unix timestamp
        absolute_timestamp = time.mktime(absolute_time.timetuple())

        return absolute_timestamp
