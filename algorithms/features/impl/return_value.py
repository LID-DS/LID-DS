from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class ReturnValue(BuildingBlock):
    """
    calculate system call return value for all syscalls.
    Training phase:
        save highest value.
    calculation phase:
        normalize with highest value of training phase
        return value is not integer -> -1 
    """

    def __init__(self, min_max_scaling=True):
        super().__init__()
        self._max = {}
        self._min_max_scaling = min_max_scaling

    def train_on(self, syscall: Syscall):
        """
        save max value of each syscall
        """
        return_value_string = syscall.param('res')
        if self._min_max_scaling:
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
        return_value = 0
        return_value_string = syscall.param('res')
        if return_value_string is not None:
            try:
                current_bytes = int(return_value_string)
            except ValueError as e:
                return_type = 'not_int'
                return_value = -1
            try:
                if return_type != 'not_int':
                    if self._min_max_scaling:
                        if syscall.name() in self._max:
                            if self._max[syscall.name()] != 0:
                                return_value = current_bytes / self._max[syscall.name()]
                            else:
                                return_value = 0
                        else:
                            return_value = -1
                    else:
                        return_value = current_bytes
                else:
                    return_value = -1
            except ZeroDivisionError:
                return_value = 0
        return return_value

    def depends_on(self):
        return []


class ReturnValueWithError(BuildingBlock):
    """
    calculate system call return value for all syscalls.
    Returns:
        - return value as is if it is an integer
        - Error code if it is an error
        - 0 if it is not an integer and not an error
    """

    def __init__(self):
        super().__init__()

    def _calculate(self, syscall: Syscall):
        return_value_string = syscall.param('res')
        if return_value_string is not None:
            try:
                return_value = int(return_value_string)
            except ValueError:
                if '(E' in return_value_string:
                    return_value = return_value_string
                else:
                    return_value = 0
            return return_value

    def depends_on(self):
        return []
