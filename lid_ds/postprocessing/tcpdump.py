from typing import List

import pcapkit
from abc import ABC, abstractmethod


class TCPPacketMatcher(ABC):
    @abstractmethod
    def matches_packet(self, packet):
        pass


class TCPPacketPartsMatcher(TCPPacketMatcher):
    def __init__(self, required_parts: List[str] = None, forbidden_parts: List[str] = None):
        self.required = required_parts if required_parts is not None else []
        self.forbidden = forbidden_parts if forbidden_parts is not None else []

    def _contains_required(self, payload):
        for part in self.required:
            if part.encode() not in payload:
                return False
        return True

    def _not_contains_forbidden(self, payload):
        for part in self.forbidden:
            if part.encode() in payload:
                return False
        return True

    def matches_packet(self, packet):
        return self._contains_required(packet.payload) and self._not_contains_forbidden(packet.payload)


class PostprocessingTCP:
    def __init__(self, file, ip):
        self.extraction = pcapkit.extract(
            fin=file, verbose=False, engine="scapy", store=True, nofile=True, tcp=True, strict=True)
        self.ip = ip

    def find_first(self, after=0):
        for packet in self.extraction.reassembly['tcp']:
            if packet.id.src[0].compressed != self.ip:
                continue
            if packet.index[0] <= after:
                continue
            return packet

    def find_first_after_matcher(self, matcher: TCPPacketMatcher):
        matching_packet = self._find_by_matcher(matcher)
        last_index = matching_packet.index[-1]

        return self.find_first(last_index)

    def get_time_for_packet(self, packet):
        index = packet.index[1]
        return self.extraction.frame[index].time

    def _find_by_matcher(self, matcher: TCPPacketMatcher):
        for packet in self.extraction.reassembly['tcp']:
            if packet.id.src[0].compressed != self.ip:
                continue
            if matcher.matches_packet(packet):
                return packet
