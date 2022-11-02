# from util.bt2.trace_collection_message_iterator import TraceCollectionMessageIterator
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
                print(msg.event.name)

    def _collect_metadata(self):
        pass


if __name__ == '__main__':
    recording = RecordingCTF("/home/felix/repos/uni/work/LID-DS/scenarios/CVE-2017-7529/CVE-2017-7529_LTTng_CTF_sample/normal_and_attack/defeated_chandrasekhar_3584")

    for syscall in recording.syscalls():
        print(syscall)


