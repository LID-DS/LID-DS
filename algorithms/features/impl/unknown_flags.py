from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock

class UnknownFlags(BuildingBlock):
    def __init__(self):
        super().__init__()
        self._flag_dict = {}

    def depends_on(self) -> list:
        return []

    def train_on(self, syscall: Syscall):
        """
            builds dictionary with all known flags seen in training for each syscall
        """
        if 'flags' in syscall.params().keys():
            if syscall.name() in self._flag_dict:
                self._flag_dict[syscall.name()].append(syscall.param('flags'))
            else:
                self._flag_dict[syscall.name()] = []
                self._flag_dict[syscall.name()].append(syscall.param('flags'))

    def _calculate(self, syscall: Syscall):
        """
            lookup of syscall flag in know flags
            if unknown -> returns 1 else 0
        """
        if 'flags' in syscall.params().keys():
            try:
                if syscall.param('flags') in self._flag_dict[syscall.name()]:
                    return 0
                else:
                    return 1
            except KeyError:
                # if syscall has not been in training data
                return 1
        else:
            return 0
