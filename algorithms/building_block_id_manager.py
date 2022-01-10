from algorithms.util.Singleton import Singleton


class BuildingBlockIDManager(metaclass=Singleton):
    def __init__(self):
        self._feature_to_int_dict = {}

    def get_id(self, feature: object) -> int:
        """
        given a object of either a BaseFeature or its subclasses
        this method map the object to an integer - this will be used to differ between different instances of features
        """
        if id(feature) not in self._feature_to_int_dict:
            self._feature_to_int_dict[id(feature)] = len(self._feature_to_int_dict) + 1
        return self._feature_to_int_dict[id(feature)]
