import typing

from dataloader.syscall import Syscall
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor


class ReturnValue(BaseSyscallFeatureExtractor):

    def __init__(self):
        super().__init__()
        self._max_time_delta = 0
        self._last_time = {}
        self.type_dict = {}
        self._max_returned_bytes_read = 0
        self._max_returned_bytes_write = 0

    def train_on(self, syscall: Syscall):
        """

        calc max time delta

        """
        return_value_string = syscall.param('res')
        if return_value_string is not None:
            try:
                current_bytes = int(return_value_string)
                if current_bytes > 1 and current_bytes < 1000000000:
                    if "write" in return_value_string:
                        if current_bytes >= self._max_returned_bytes_write:
                            self._max_returned_bytes_write = current_bytes
                    elif "sendfile" in return_value_string:
                        if current_bytes >= self._max_returned_bytes_write:
                            self._max_returned_bytes_write = current_bytes
                    elif "read" in return_value_string:
                        if current_bytes >= self._max_returned_bytes_read:
                            self._max_returned_bytes_read = current_bytes
                    elif "recv" in return_value_string:
                        # recv msg from socket
                        pass
                    else:
                        # print("else")
                        print(self._max_returned_bytes_read)
                        print(self._max_returned_bytes_write)
                        print(syscall.name(), return_value_string)
                        b = 'write' in return_value_string
                        # print(b)
            except Exception:
                pass
                #print(syscall.name(), return_value_string)
        # delta = self._calc_delta(current_time, syscall)
        # if delta > self._max_time_delta:
        # self._max_time_delta = delta

    def fit(self):
        print(self._max_returned_bytes_read)
        print(self._max_returned_bytes_write)

    def extract(self, syscall: Syscall) -> typing.Tuple[int, float]:
        """
        """
        return_value_string = syscall.param('res')
        return_type = 'read'
        if return_value_string is not None:
            try:
                current_bytes = int(return_value_string)
                if current_bytes > 1 and current_bytes < 1000000000:
                    if "write" in return_value_string:
                        return_type = 'write'
                    elif "sendfile" in return_value_string:
                        return_type = 'write'
                    else:
                        # print("else")
                        print(max_returned_bytes_read)
                        print(max_returned_bytes_write)
                        print(syscall.name(), return_value_string)
                        b = 'write' in return_value_string
                        # print(b)
            except Exception:
                pass
            if return_type == 'read':
                normalized_bytes = current_bytes/self._max_retruned_bytes_read
            else:
                normalized_bytes = current_bytes/self._max_retruned_bytes_write
            return normalized_bytes

