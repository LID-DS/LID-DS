from .tcpdump import PostprocessingTCP, TCPPacketMatcher
from .sysdig import PostprocessingSysdig


class PostprocessingMatcher:
    def __init__(self, pcap, scap, ip):
        self.tcpdump = PostprocessingTCP(pcap, ip)
        self.sysdig = PostprocessingSysdig(scap)
        self.last_index = -1

    def _get_optimized_time(self, event, packet):
        if event is not None:
            return event.event_time, "SYSDIG"
        elif packet is not None:
            return self.tcpdump.get_time_for_packet(packet), "TCPDUMP"

    def get_exact_attack_time(self, matcher: TCPPacketMatcher = None):
        if matcher is None:
            packet = self.tcpdump.find_first(self.last_index)
        else:
            packet = self.tcpdump.find_first_after_matcher(matcher)

        self.last_index = packet.index[-1]
        event = self.sysdig.find_first_matching_syscalls(packet)

        return self._get_optimized_time(event=event, packet=packet)
