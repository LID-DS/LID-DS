from dataclasses import dataclass
from typing import Union, List


@dataclass
class StdinCommand:
    stdin = True
    command: str
    name: str = "attack"


@dataclass
class ExecCommand:
    stdin = False
    command: str
    name: str = "attack"


@dataclass
class ChainImage:
    name: str
    commands: List[Union[ExecCommand, StdinCommand]] = None
    init_args: str = None


class Image(ChainImage):
    def __init__(self, name: str, command: Union[ExecCommand, StdinCommand] = None, init_args=None):
        super(Image, self).__init__(name, [command] if command else [], init_args)
