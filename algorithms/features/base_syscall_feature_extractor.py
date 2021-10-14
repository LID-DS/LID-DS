import typing

from dataloader.syscall import Syscall


class BaseSyscallFeatureExtractor:
    """

    base class for feature extraction of exactly one system call

    """

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

    def extract(self, syscall: Syscall) -> typing.Tuple[str, object]:
        """

        extracts feature from syscall

        Returns:
        string: key: name of feature
                value: value of feature

        """
        pass
