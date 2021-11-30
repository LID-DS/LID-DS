from algorithms.features.feature_id_manager import FeatureIDManager
from dataloader.syscall import Syscall


class BaseFeature:
    """
    base class for a feature
    """

    def __init__(self):
        self._instance_id = None

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
        raise NotImplementedError

    def new_recording(self):
        """
        empties buffer and prepares for next recording
        """
        pass

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        raise NotImplementedError

    def __str__(self) -> str:
        """
        gives a more or less human readable str representation of this object
        returns: "Name_of_class(memory_address)"
        """
        return f"{self.__class__.__name__}({hex(id(self))})"

    def __repr__(self):
        """
        same for __repr__
        """
        return self.__str__()

    def get_id(self):
        """
        returns the id of this feature instance - used to differ between different features
        """
        if self._instance_id is None:
            self._instance_id = FeatureIDManager().get_id(self)
        return self._instance_id
