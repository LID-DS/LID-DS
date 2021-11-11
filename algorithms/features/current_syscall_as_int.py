import typing

from algorithms.features.syscall_to_int import SyscallToInt
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor


class CurrentSyscallAsInt(BaseStreamFeatureExtractor):
    """

    add integer of current syscall to NgramMinusOne

    """

    def extract(self, syscall_features: dict, stream_features: dict) -> typing.Tuple[int, list]:
        """

        takes syscall feature (sys_to_int) and NgramMinusOne and combines them
        set sys_to_int at beginning

        Returns:
          key: id of feature and
          value: list [sys_to_int, ngramMinusOne]

        """
        if len(stream_features) == 0:
            return CurrentSyscallAsInt.get_id(), None
        sys_to_int = syscall_features[SyscallToInt.get_id()]
        ngram = stream_features[NgramMinusOne.get_id()]
        value = []
        value.append(sys_to_int[0])
        value += ngram
        return CurrentSyscallAsInt.get_id(), value
