from syscall import Syscall


class Syscall_ADFA_LD(Syscall):
    def __init__(self, syscall_id):
        super().__init__()
        self.syscall_id = syscall_id

    def name(self) -> str:
        """
        gets syscall name from recorded line
        Returns:
            string: syscall name
        """
        if self._name is None:
            self._name = self.syscall_id
        return self._name

