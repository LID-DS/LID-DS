import os.path
import typing

from gensim.models import KeyedVectors, Word2Vec

from algorithms.features.syscall_name import SyscallName
from algorithms.features.threadID_extractor import ThreadIDExtractor

from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class SyscallsInTimeWindow(BaseSyscallFeatureExtractor):
    """
        implementation of the w2v embedding approach based on BaseSyscallFeatureExtractor

        Special for this one:
            uses n_gram feature stream to create sentences for word corpus
            -> thread and file awareness given
    """

    def __init__(self, window_length_in_s):
        super().__init__()
        self.window_length = window_length_in_s
        self._count_in_window = 0
        self._syscall_buffer = []
        self._training_max = 0

    def train_on(self, syscall: Syscall):
        """

        """
        current_timestamp = syscall.timestamp_datetime()
        self._syscall_buffer.append(syscall)
        for buffered_syscall in self._syscall_buffer:
            difference = (current_timestamp - buffered_syscall.timestamp_datetime()).total_seconds()
            if difference > self.window_length:
                self._syscall_buffer.remove(buffered_syscall)
            else:
                break

        syscalls_in_window = len(self._syscall_buffer)
        if syscalls_in_window > self._training_max:
            self._training_max = syscalls_in_window

    def fit(self):
        """
            trains the w2v model on training sentences
        """
        self._syscall_buffer = []

    def extract(self, syscall: Syscall) -> typing.Tuple[int, float]:
        """
            embeds one system call in w2v model

            if word is not in corpus a zero-vector with correct size is returned

            Returns:
                syscall vector
        """
        current_timestamp = syscall.timestamp_datetime()
        self._syscall_buffer.append(syscall)

        if not (current_timestamp - self._syscall_buffer[0].timestamp_datetime()).total_seconds() > self.window_length:
            for buffered_syscall in self._syscall_buffer:
                difference = (current_timestamp - buffered_syscall.timestamp_datetime()).total_seconds()
                if difference > self.window_length:
                    self._syscall_buffer.remove(buffered_syscall)
                else:
                    break

            syscalls_in_window = len(self._syscall_buffer)
            normalized_count = syscalls_in_window / self._training_max
            return SyscallsInTimeWindow.get_id(), normalized_count

        else:
            return SyscallsInTimeWindow.get_id(), 0



    def new_recording(self):
        """
            tells n_gram streamer to clear buffer after beginning of new recording
        """
        self._syscall_buffer = []
