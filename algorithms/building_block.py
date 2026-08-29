from collections.abc import Iterable

from algorithms.building_block_id_manager import BuildingBlockIDManager
from dataloader.syscall import Syscall


class BuildingBlock:
    """
    base class for features and other algorithms
    """
    _online_trainable = None  # None = auto-detect

    @property
    def online_trainable(self):
        """Whether _calculate() works correctly without fit() having been called.
        Auto-detected: True if fit() is not overridden, False otherwise.
        Subclasses with informational-only fit() can set _online_trainable = True.
        """
        if self._online_trainable is not None:
            return self._online_trainable
        return type(self).fit is BuildingBlock.fit

    def __init__(self):
        self._config = BuildingBlock._arguments()
        self.name = self.__class__.__name__
        self._instance_id = None
        self._last_result = None
        self._last_syscall = None

    def train_on(self, syscall: Syscall):
        """
        takes one system call to train this bb
        """

    def val_on(self, syscall: Syscall):
        """
        takes one system call to validate this bb on
        """

    def fit(self):
        """
        finalizes training
        """

    def get_result(self, syscall: Syscall):
        """        
        This function calculates this building block on the given syscall.
        It buffers its result until another system call is given.
        Returns its value (whatever it is) or None if it cant be calculated at the moment.
        """
        if self._last_syscall is not syscall:
            self._last_result = self._calculate(syscall)
            self._last_syscall = syscall
        return self._last_result

    def _calculate(self, syscall: Syscall):
        """
        calculates building block on the given syscall        
        """
        raise NotImplementedError("each building block has to implement _calculate")

    def new_recording(self):
        """
        empties buffer and prepares for next recording
        """

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this building block
        """
        raise NotImplementedError("each building block has to implement depends_on to indicate its dependencies")

    def __str__(self) -> str:
        """
        gives a more or less human-readable str representation of this object containing the name and configurations
        """
        return str(self.to_dict_repr())

    def to_dict_repr(self):
        """
        distilled dictionary representation containing the configurations.
        """
        if len(self._config) > 0:
            result = {
                'name': self.__class__.__name__,
                'id': hex(id(self)),
                'config': self._config,
            }
        else:
            result = {
                'name': self.__class__.__name__,
                'id': hex(id(self)),
            }
        return result

    def __repr__(self):
        """
        same for __repr__
        """
        return self.__str__()

    def get_id(self):
        """
        returns the id of this feature instance - used to differ between different building blocks
        """
        if self._instance_id is None:
            self._instance_id = BuildingBlockIDManager().get_id(self)
        return self._instance_id

    @staticmethod
    def _arguments():
        """Returns tuple containing dictionary of calling function's
        named arguments and a list of calling function's unnamed
        positional arguments.
        from: http://kbyanc.blogspot.com/2007/07/python-aggregating-function-arguments.html
        """
        from inspect import getargvalues, stack
        try:
            _, kwname, args = getargvalues(stack()[2][0])[-3:]  # modified the first index to get the correct arguments
            args.update(args.pop(kwname, []))
            del args['self']
            del args['__class__']
            final_args = {}
            for k, v in args.items():
                # print(f"at {k}")
                if not isinstance(v, BuildingBlock) and (isinstance(v, str) or not isinstance(v, Iterable)):
                    final_args[k] = v
                if isinstance(v, Iterable) and not isinstance(v, str):
                    final_iter = []
                    for item in v:
                        if not isinstance(item, BuildingBlock):
                            final_iter.append(item)
                    if len(final_iter) > 0:
                        final_args[k] = final_iter
            return final_args
        except KeyError:
            return {}

    def is_decider(self):
        """
            If BuildingBlock is a decider (e.g. max score threshold) return True
        """
        return False
