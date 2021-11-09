import typing

from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor


class CurrentSyscallAsInt(BaseStreamFeatureExtractor):
    """

    add integer of current syscall to NgramMinusOne

    """

    def extract(self, syscall_feature: dict, stream_feature: dict) -> typing.Tuple[int, list]:
        """

        takes syscall feature (sys_to_int) and NgramMinusOne and combines them
        set sys_to_int at beginning

        Returns:
          key: id of feature and
          value: list [sys_to_int, ngramMinusOne]

        """
        sys_to_int = syscall_feature[SyscallToInt.get_id()]
        ngram = stream_feature[NgramMinusOne.get_id()]
        value = []
        value.append(sys_to_int)
        value += ngram
        print(value)
        return CurrentSyscallAsInt.get_id(), value
