import typing

from algorithms.features.feature_id_manager import FeatureIDManager
from dataloader.syscall import Syscall


class BaseSyscallFeatureExtractor:
    """

    base class for feature extraction of exactly one system call

    """
    # this is the id of this class determined at runtime
    class_id = None

    def __init__(self):
        pass

    def train_on(self, syscall: Syscall):
        """

        takes one system call instance to train this extraction

        """
        pass

    def fit(self):
        """

        finalizes training

        """
        pass

    def extract(self, syscall: Syscall) -> typing.Tuple[int, object]:
        """

        extracts feature from syscall

        Returns:
        string: key: id of the feature
                value: value of feature

        """
        pass

    @classmethod
    def get_id(cls):
        if cls.class_id is None:
            cls.class_id = FeatureIDManager().get_id(cls)
        return cls.class_id
