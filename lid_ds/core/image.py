from dataclasses import dataclass
from typing import Union


@dataclass
class StdinCommand:
    command: str


@dataclass
class Image:
    name: str
    command: Union[str, StdinCommand] = None
    init_args: str = None