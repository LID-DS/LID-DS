from enum import IntEnum


class Direction(IntEnum):
    OPEN = 0
    CLOSE = 1
    BOTH = 2

    @staticmethod
    def argparse(s):
        try:
            return Direction[s.upper()]
        except KeyError:
            return s
