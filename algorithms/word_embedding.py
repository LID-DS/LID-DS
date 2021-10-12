import timeit
import typing

from collections import deque
from gensim.models import Word2Vec, KeyedVectors

from algorithms.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class WordEmbedding(BaseSyscallFeatureExtractor):
    """

        base class for feature transformation e.g. embedding process

    """

    def __init__(self, window, vector_size,
                 thread_aware, epochs=50,
                 path='Models/', force_train=False):
        self._window = window
        self._vector_size = vector_size
        self._epochs = epochs
        self._path = path + f'{self._window}{self._vector_size}embedding.model'
        self._word_list = []
        self._thread_aware = thread_aware
        self._system_call_buffer = {}
        self.w2v = None
        if not force_train:
            self.load()

    def train_on(self, syscall: Syscall):
        """

            takes one feature instance to train transformation approach

        """
        if not self.w2v:
            ngram = self.create_ngram(syscall.name(), syscall.thread_id())
            if ngram:
                self._word_list.append(ngram)
        else:
            pass

    def fit(self):
        """

            finalizes training section

        """
        if not self.w2v:
            print('Start to fit word2vec.')
            word2vec = Word2Vec(window=self._window,
                                vector_size=self._vector_size)
            t = timeit.default_timer()
            word2vec.build_vocab(self._word_list, progress_per=10000)
            print(f'Took {timeit.default_timer() - t} to create vocab.')
            t = timeit.default_timer()
            word2vec.train(self._word_list,
                           total_examples=word2vec.corpus_count,
                           epochs=self._epochs,
                           report_delay=1)
            word2vec = word2vec.wv
            word2vec.save(fname_or_handle=self._path)
            print(f'Took {timeit.default_timer() - t} for training.')
            self.w2v = word2vec

    def extract(self, syscall: Syscall) -> typing.Tuple[str, list]:
        """

            transforms given syscall name to word embedding

        """
        return 'w2v', self.w2v[syscall.name()]

    def load(self):
        """

            check if word embedding has been created for this scenario

        """
        try:
            self.w2v = KeyedVectors.load(self._path, mmap='r')
            print(f'Loaded embedding: {self._path}')
        except Exception:
            print(f'No embedding found for: {self._path}')

    def create_ngram(self, syscall_name: str, thread_id: int) -> list:
        """

            receives input_vector and creates ngram

        """
        thread_id = 0
        if self._thread_aware:
            thread_id = thread_id
        if thread_id not in self._system_call_buffer:
            self._system_call_buffer[thread_id] = \
                deque(maxlen=self._window)
        self._system_call_buffer[thread_id].append(syscall_name)
        ngram = None
        if len(self._system_call_buffer[thread_id]) == self._window:
            ngram = list(self._system_call_buffer[thread_id])
        return ngram
