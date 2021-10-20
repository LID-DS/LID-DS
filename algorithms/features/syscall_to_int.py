import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class SyscallToInt(BaseSyscallFeatureExtractor):
    """
<<<<<<< HEAD
        convert system call name to unique integer
=======

        convert system call name to unique integer

>>>>>>> 213bd540697e5b334b7d61290fc0d793f3e97d7e
    """

    def __init__(self):
        self._syscall_dict = {}

    def train_on(self, syscall: Syscall):
        """
<<<<<<< HEAD
            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls
=======

            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls

>>>>>>> 213bd540697e5b334b7d61290fc0d793f3e97d7e
        """
        if syscall.name() not in self._syscall_dict:
            self._syscall_dict[syscall.name()] = len(self._syscall_dict) + 1

    def extract(self, syscall: Syscall) -> typing.Tuple[str, list]:
        """
<<<<<<< HEAD
            transforms given syscall name to integer
=======

            transforms given syscall name to integer

>>>>>>> 213bd540697e5b334b7d61290fc0d793f3e97d7e
        """
        try:
            sys_to_int = self._syscall_dict[syscall.name()]
        except KeyError:
            sys_to_int = 0
        return SyscallToInt.get_id(), [sys_to_int]
