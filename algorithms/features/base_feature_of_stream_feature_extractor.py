import typing


class BaseFeatureOfStreamFeatureExtractor:
    """

    base class for feature extraction from stream features and syscall features

    """

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
