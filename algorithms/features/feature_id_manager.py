from typing import Type

from algorithms.features.util.Singleton import Singleton


class FeatureIDManager(metaclass=Singleton):
    def __init__(self):
        self._feature_to_int_dict = {}

    def get_id(self, feature: Type[object]) -> int:
        """
        given a class (or subclass) of either a BaseSyscallFeatureExtractor or a BaseStreamFeatureExtractor
        this method map the class to an integer - this will be used to differ between different features
        """
        if feature.__name__ not in self._feature_to_int_dict:
            self._feature_to_int_dict[feature.__name__] = len(self._feature_to_int_dict) + 1
        return self._feature_to_int_dict[feature.__name__]
