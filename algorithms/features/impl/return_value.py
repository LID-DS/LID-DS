from algorithms.building_block import BuildingBlock
from algorithms.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ReturnValue(BuildingBlock, metaclass=Singleton):
    """
    calculate system call return value for all syscalls.
    Training phase:
        save highest value.
    calculation phase:
        normalize with highest value of training phase
        return value is not integer -> -1 
    """

    def __init__(self):
        super().__init__()
        self._max = {
        }

    def train_on(self, syscall: Syscall):
        """
        save max value of each syscall
        """
        return_value_string = syscall.param('res')
        if return_value_string is not None:
            try:
                current_bytes = int(return_value_string)
                if syscall.name() in self._max:
                    if current_bytes >= self._max[syscall.name()]:
                        self._max[syscall.name()] = current_bytes
                else:
                    self._max[syscall.name()] = current_bytes
            except ValueError as e:
                pass

    def _calculate(self, syscall: Syscall):
        """
        calculate return value type and normalize with max value of training phase
        return -1 if 
            * syscall never had return value in training
            * return value was not an integer value
        """
        return_type = None
        normalized_bytes = 0
        return_value_string = syscall.param('res')
        if return_value_string is not None:
            try:
                current_bytes = int(return_value_string)
            except ValueError as e:
                return_type = 'not_int'
                normalized_bytes = -1
            try:
                if return_type != 'not_int':
                    #print(return_type)
                    #print(self._max[return_type])
                    if syscall.name() in self._max:
                        if self._max[syscall.name()] != 0:
                            normalized_bytes = current_bytes/self._max[syscall.name()]
                        else:
                            normalized_bytes = 0
                    else:
                        print('that')
                        normalized_bytes = -1
                else:
                    normalized_bytes = -1
            except ZeroDivisionError:
                normalized_bytes = 0
        return normalized_bytes

    def depends_on(self):
        return []
