import bt2

from typing import Generator

from dataloader.base_recording import BaseRecording
from dataloader.syscall import Syscall


class RecordingCTF(BaseRecording):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.message_iterator = bt2.TraceCollectionMessageIterator(path)

    def syscalls(self) -> Generator[Syscall, None, None]:
        for msg in self.message_iterator:
            if type(msg) is bt2._EventMessageConst:
                name = msg.event.name
                thread_id = msg.event['tid']
                process_id = msg.event['pid']
                process_name = msg.event['procname']
                # timestamp = msg.event['timestamp']
                yield msg.event.__dict__

    def _collect_metadata(self):
        pass


if __name__ == '__main__':
    recording = RecordingCTF("/home/felix/datasets/CVE-2017-7529_LTTng_CTF_sample/test/normal_and_attack/defeated_chandrasekhar_3584")

    for syscall in recording.syscalls():
        print(syscall)


