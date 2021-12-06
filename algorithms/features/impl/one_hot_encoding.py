from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class OneHotEncoding(BaseFeature, metaclass=Singleton):
    """
        convert system call name to One Hot Encoding array
    """

    def __init__(self):
        super().__init__()
        self._syscall_dict = {}
        self._ohe_dict = {}

    def depends_on(self):
        return []

    def train_on(self, syscall: Syscall, features: dict):
        """
            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls
        """
        if syscall.name() not in self._syscall_dict:
            self._syscall_dict[syscall.name()] = len(self._syscall_dict) + 1

    def fit(self):
        length = len(self._syscall_dict)
        ohe_array = [0] * length
        self._ohe_dict[0] = ohe_array
        for i in range(1,length+1):
            ohe_array = [0] * length
            ohe_array[i-1] = 1
            self._ohe_dict[i] = ohe_array
        # print(self._ohe_dict)

    def extract(self, syscall: Syscall, features: dict):
        """
            transforms given syscall name an OHE array
        """
        try:
            sys_to_int = self._syscall_dict[syscall.name()]
        except KeyError:
            sys_to_int = 0
        features[self.get_id()] = self._ohe_dict[sys_to_int]
    
    def get_embedding_size(self):
        return len(self._syscall_dict)
