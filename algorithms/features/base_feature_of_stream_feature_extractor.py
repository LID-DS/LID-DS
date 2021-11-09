import typing

from algorithms.features.feature_id_manager import FeatureIDManager


class BaseFeatureOfStreamFeatureExtractor:
    """

    base class for feature extraction from stream features and syscall features

    """
    # this is the id of this class determined at runtime
    class_id = None

    def __init__(self, syscall_feature_list: list, stream_feature_list: list):
        pass

    def extract(self,
                stream_features: dict,
                syscall_features: dict = []) -> typing.Tuple[str, list]:
        """

        extracts a feature from a stream of syscall features
        also able to combine syscall and stream features

        Returns:
          key: id of feature and
          value: value of feature

        """

    @classmethod
    def get_id(cls):
        if cls.class_id is None:
            cls.class_id = FeatureIDManager().get_id(cls)
        return cls.class_id
