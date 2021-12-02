import typing

from algorithms.features.base_feature import BaseFeature
from algorithms.features.util.Singleton import Singleton
from dataloader.syscall import Syscall


class ReturnValue(BaseFeature, metaclass=Singleton):
    """
    Extract system call return value for specific syscalls.
    Include:
        write and writev are summarized as           write
        read, readv and are summarized as            read
        sendfile as                                  send_socket
        recv as                                      recv_socket
        getdents as                                  get_dents
    Training phase:
        save highest value.
    Extraction phase:
        normalize with highest value of training phase
    """

    def __init__(self):
        super().__init__()
        self._max = {
            'read': 0,
            'write': 0,
            'recv_socket': 0,
            'get_dents': 0,
            'send_socket': 0
        }
        self.write = ['write', 'writev']
        self.read = ['read', 'readv']
        self.send_socket = ['sendfile', 'sendmsg']
        self.recv_socket =  ['recvfrom', 'recv', 'recvmsg']
        self.get_dents =  ['getdents']
        self.not_interesting = ['clone', 'getcwd', 'lseek', 'fcntl', 'futex', 'epoll_wait']
        self.interesting = self.read \
                           + self.write \
                           + self.send_socket \
                           + self.recv_socket \
                           + self.get_dents

    def train_on(self, syscall: Syscall, features: dict):
        """
        save max value of each specified syscall
        """
        if syscall.name() in self.interesting:
            return_value_string = syscall.param('res')
            if return_value_string is not None:
                try:
                    current_bytes = int(return_value_string)
                    if syscall.name() in self.write:
                        if current_bytes >= self._max['write']:
                            self._max['write'] = current_bytes
                    elif syscall.name() in self.send_socket:
                        if current_bytes >= self._max['send_socket']:
                            self._max['send_socket'] = current_bytes
                    elif syscall.name() in self.read:
                        if current_bytes >= self._max['read']:
                            self._max['read'] = current_bytes
                    elif syscall.name() in self.get_dents:
                        if current_bytes >= self._max['get_dents']:
                            self._max['get_dents'] = current_bytes
                    elif syscall.name() in self.recv_socket:
                        # recv msg from socket
                        # bytes received
                        if current_bytes >= self._max['recv_socket']:
                            self._max['recv_socket'] = current_bytes
                    elif syscall.name() in self.not_interesting:
                        pass
                    else:
                        print("not handled")
                        print(syscall.name(), return_value_string)
                except Exception as e:
                    print(e)
                    print('Return Value: Could not cast return value to int')
                    print(f' Return string: {return_value_string}')

    def extract(self, syscall: Syscall, features: dict):
        """
        extract return value type and normalize with max value of training phase
        """
        return_type = None
        normalized_bytes = 0
        if syscall.name() in self.interesting:
            return_value_string = syscall.param('res')
            if return_value_string is not None:
                try:
                    current_bytes = int(return_value_string)
                    if syscall.name() in self.write:
                        return_type = 'write'
                    elif syscall.name() in self.send_socket:
                        return_type = 'send_socket'
                    elif syscall.name() in self.read:
                        return_type = 'read'
                    elif syscall.name() in self.recv_socket:
                        return_type = 'recv_socket'
                    elif syscall.name() in self.get_dents:
                        return_type = 'get_dents'
                    else:
                        pass
                except Exception as e:
                    print(e)
                    print('Return Value: Could not cast return value to int')
                    print(f' Return string: {return_value_string}')
                try:
                    if return_type:
                        normalized_bytes = current_bytes/self._max[return_type]
                    else:
                        normalized_bytes = 0
                except ZeroDivisionError:
                    normalized_bytes = 0
        features[self.get_id()] = normalized_bytes

    def depends_on(self):
        return []
