import base64
import subprocess
from difflib import SequenceMatcher
from lid_ds.data_models.sysdig_event import SysdigEvent


class PostprocessingSysdig:
    def __init__(self, file):
        self.MATCH_THRESHOLD = 0.8
        self.file = file

    def _start_subprocess(self):
        return subprocess.Popen(f"sysdig -ta -br {self.file}",
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

    def _is_packet_data_similar(self, packet_data, syscall_data):
        longest_match = SequenceMatcher(None, packet_data, syscall_data).find_longest_match(
            0, len(packet_data), 0, len(syscall_data)).size

        return longest_match / len(syscall_data) >= self.MATCH_THRESHOLD

    def _extract_data(self, args):
        for arg in args:
            if "data=" in arg:
                data = arg.replace("data=", "").encode()
                return base64.b64decode(data)
        return b""

    def find_first_matching_syscalls(self, packet, start=0):
        ip_arg = f"{packet.id.src[0].compressed}:{packet.id.src[1]}->{packet.id.dst[0].compressed}:{packet.id.dst[1]}"

        matching_enter_event = None

        p = self._start_subprocess()

        while p.poll() is None:
            line = p.stdout.readline()

            try:
                event = SysdigEvent(line)

                if event.sysdig_recording_index <= start:
                    continue

                if event.enter_event:
                    if ip_arg in event.args[0]:
                        matching_enter_event = event
                    else:
                        matching_enter_event = None

                elif matching_enter_event is not None:
                    data = self._extract_data(event.args)
                    if len(data) > 0 and self._is_packet_data_similar(packet.payload, data):
                        return matching_enter_event
            except:
                pass
