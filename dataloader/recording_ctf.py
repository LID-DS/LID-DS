import json

import bt2

from typing import Generator

from dataloader.base_recording import BaseRecording
from dataloader.direction import Direction
from dataloader.syscall import Syscall
from dataloader.syscall_ctf import SyscallCTF


class RecordingCTF(BaseRecording):
    """
        represents one recording of an LID-DS file in CTF Format

        Parameters:
            name: the name of the recording
            path: the recording path
            direction: filter on direction
    """
    def __init__(self, name, path, direction=Direction.BOTH):
        super().__init__()
        self.path = path
        self.name = name
        self._direction = direction
        self.message_iterator = bt2.TraceCollectionMessageIterator(path)

    def syscalls(self) -> Generator[Syscall, None, None]:
        """
            Generator that yields one syscall object at a time
        """
        line_id = 1
        for msg in self.message_iterator:
            if type(msg) is bt2._EventMessageConst:
                full_event_name = msg.event.name

                splitted_name = full_event_name.split('_', 2)
                name = splitted_name[2]
                if splitted_name[1] == 'entry':
                    direction = Direction.OPEN
                else:
                    direction = Direction.CLOSE

                thread_id = msg.event['tid']
                process_id = msg.event['pid']
                process_name = msg.event['procname']
                unix_timestamp = msg.default_clock_snapshot.ns_from_origin

                syscall = SyscallCTF(
                    name=name,
                    thread_id=thread_id,
                    process_name=process_name,
                    process_id=process_id,
                    timestamp=unix_timestamp,
                    direction=direction,
                    recording_path=self.path,
                    line_id=line_id
                )
                line_id += 1

                if self._direction != Direction.BOTH:
                    if syscall.direction() == self._direction:
                        yield syscall
                else:
                    yield syscall

    def metadata(self) -> dict:
        """
            parses the metadata json file to dictionary
        """
        with open(f'{self.path}.json') as json_file:
            metadata = json.load(json_file)
        return metadata
