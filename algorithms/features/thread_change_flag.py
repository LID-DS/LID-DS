import typing
from collections.abc import Iterable

from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.base_feature_of_stream_feature_extractor import BaseFeatureOfStreamFeatureExtractor


class ThreadChangeFlag(BaseFeatureOfStreamFeatureExtractor):
    """
    receives ngram stream feature and threadID feature
    set thread change flag to 1 if ngram predecessor is from different thread
    othrewise 0
    initially also set to 0
    return received features plus appended thread change flag
    """

    def __init__(self, syscall_feature_list: list, stream_feature_list: list):
        """
        """
        super().__init__()
        self._list_of_feature_ids = []
        for feature_class in stream_feature_list:
            self._list_of_feature_ids.append(feature_class.get_id())
        self._last_thread_id = None
        self._syscall_feature_list = syscall_feature_list
        if ThreadIDExtractor not in syscall_feature_list:
            raise KeyError('No thread id in features')

    def extract(self, syscall_features: dict, stream_features: dict) -> typing.Tuple[str, list]:
        """
        check if stream features have been provided otherwise return None
        get current threadID of syscall
        compare with last thread id and determine thread change flag accordingly
        collect stream features with passed features and append thread change flag
        """
        if len(stream_features) == 0:
            return ThreadChangeFlag.get_id(), None
        try:
            thread_id = syscall_features[ThreadIDExtractor.get_id()]
        except KeyError:
            raise KeyError('No thread id in features')
        if self._last_thread_id is None:
            self._last_thread_id = thread_id
            thread_change_flag = 0
        elif thread_id == self._last_thread_id:
            thread_change_flag = 0
        else:
            thread_change_flag = 1
            self._last_thread_id = thread_id
        features = self._collect_features(stream_features)
        features.append(thread_change_flag)
        return ThreadChangeFlag.get_id(), features

    def _collect_features(self, stream_feature_dict: dict) -> list:
        """
        creates list of features included in stream_feature_list

        Returns:
            list: concatenated values of stream_feature_dict
        """
        array = []
        for feature_id in self._list_of_feature_ids:
            if feature_id in stream_feature_dict:
                if isinstance(stream_feature_dict[feature_id], Iterable):
                    array += stream_feature_dict[feature_id]
                else:
                    array.append(stream_feature_dict[feature_id])
        return array
