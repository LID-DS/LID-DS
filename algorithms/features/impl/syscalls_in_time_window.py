from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class SyscallsInTimeWindow(BuildingBlock):

    def __init__(self, window_length_in_s: int):
        """
            Featurecalculateor that calculates number of syscalls in time window
            before current syscall, acts thread aware

            args:
                window_length_in_s = window length in seconds
        """
        super().__init__()
        self.window_length = window_length_in_s
        self._count_in_window = 0
        self._syscall_buffer = {}
        self._training_max = 0

        self._dependency_list = []

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall, features: dict):
        """
            trains the calculateor by finding the biggest count of syscalls
            in time window needed for normalization of feature
        """
        current_timestamp = syscall.timestamp_datetime()
        thread_id = syscall.thread_id()
        if thread_id not in self._syscall_buffer.keys():
            self._syscall_buffer[thread_id] = []
        self._syscall_buffer[thread_id].append(syscall)

        last_index = 0
        i = 0
        while i < len(self._syscall_buffer[thread_id]):
            buffered_syscall = self._syscall_buffer[thread_id][i]
            i += 1
            difference = (current_timestamp - buffered_syscall.timestamp_datetime()).total_seconds()

            # saving the index of the first element that is in time window
            if difference <= self.window_length:
                last_index = i
                break

        # clear first n elements from buffer where time difference > time window
        self._syscall_buffer[thread_id] = self._syscall_buffer[thread_id][last_index - 1:]

        # window count is the length of the left buffer
        syscalls_in_window = len(self._syscall_buffer[thread_id])
        if syscalls_in_window > self._training_max:
            self._training_max = syscalls_in_window

    def fit(self):
        """
            clears the syscall buffer
        """
        self._syscall_buffer = {}

    def calculate(self, syscall: Syscall, features: dict):
        """
            calculates count of syscalls in time window before current syscall
            returns normalized value based on training data
        """
        current_timestamp = syscall.timestamp_datetime()
        thread_id = syscall.thread_id()

        if thread_id not in self._syscall_buffer.keys():
            self._syscall_buffer[thread_id] = []

        self._syscall_buffer[thread_id].append(syscall)
        last_index = 0

        if (current_timestamp - self._syscall_buffer[thread_id][0].timestamp_datetime()).total_seconds() \
                >= self.window_length:
            i = 0
            while i < len(self._syscall_buffer[thread_id]):
                buffered_syscall = self._syscall_buffer[thread_id][i]
                i += 1
                difference = (current_timestamp - buffered_syscall.timestamp_datetime()).total_seconds()

                # saving the index of the first element that is in time window
                if difference <= self.window_length:
                    last_index = i
                    break

            # clear first n elements from buffer where time difference > time window
            self._syscall_buffer[thread_id] = self._syscall_buffer[thread_id][last_index - 1:]

            # window count is the length of the left buffer
            syscalls_in_window = len(self._syscall_buffer[thread_id])

            # normalizing the return value with maximum count from training data
            normalized_count = syscalls_in_window / self._training_max
            features[self.get_id()] = normalized_count

        else:
            features[self.get_id()] = 0

    def new_recording(self):
        """
            clears syscall buffer
        """
        self._syscall_buffer = {}
