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

    def extract(self, syscall: Syscall) -> dict:
        """

        extracts feature from syscall

        Returns:
        dict: key: name of feature and
              value: value of feature

        """
        pass
