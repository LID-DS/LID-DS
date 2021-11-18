import typing

from algorithms.features.feature_id_manager import FeatureIDManager
from dataloader.syscall import Syscall


class BaseFeature:
    """
    base class for a feature
    """
    # this is the id of this class determined at runtime
    class_id = None

    def __init__(self):
        raise NotImplementedError('No feature should call this init method.')

    def train_on(self, syscall: Syscall, features: dict):
        """
        takes one system call instance and the given features to train this extraction
        """
        pass

    def fit(self):
        """
        finalizes training
        """
        pass

    def extract(self, syscall: Syscall, features: dict):
        """
        calculates features on the given syscall and other already calculated features given in features
        writes its result into the given feature dict with key = get_id()
        """
        pass

    def new_recording(self):
        """
        empties buffer and prepares for next recording
        """
        pass

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        pass

    @classmethod
    def get_id(cls):
        if cls.class_id is None:
            cls.class_id = FeatureIDManager().get_id(cls)
        return cls.class_id
