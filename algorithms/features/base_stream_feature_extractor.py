import typing

from algorithms.features.feature_id_manager import FeatureIDManager


class BaseStreamFeatureExtractor:
    """

    base class for feature extraction from a stream of system call features

    """
    # this is the id of this class determined at runtime
    class_id = None

    def __init__(self):
        pass

    def train_on(self, syscall_feature: dict):
        """

        takes features of one system call to train this extraction

        """
        pass

    def fit(self):
        """

        finalizes training

        """
        pass

    def extract(self, syscall_features: dict) -> typing.Tuple[int, object]:
        """

        extracts a feature from a stream of syscall features

        Returns:
          key: id of feature and
          value: value of feature

        """
        pass

    def new_recording(self):
        """

        empty buffers and prepare for next recording

        """
        pass

    @classmethod
    def get_id(cls):
        if cls.class_id is None:
            cls.class_id = FeatureIDManager().get_id(cls)
        return cls.class_id
