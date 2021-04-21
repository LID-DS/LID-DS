from dataclasses import dataclass
from typing import Union, List

from lid_ds.postprocessing.tcpdump import TCPPacketMatcher


@dataclass
class Command:
    command: str
    name: str = "attack"
    after_packet: TCPPacketMatcher = None


@dataclass
class StdinCommand(Command):
    stdin = True


@dataclass
class ExecCommand(Command):
    stdin = False


@dataclass
class ChainImage:
    name: str
    commands: List[Union[ExecCommand, StdinCommand]] = None
    init_args: str = ""


class Image(ChainImage):
    def __init__(self, name: str, command: Union[ExecCommand, StdinCommand] = None, init_args=""):
        super(Image, self).__init__(name, [command] if command else [], init_args)
