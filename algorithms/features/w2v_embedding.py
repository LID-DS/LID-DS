import os.path
import typing

from gensim.models import KeyedVectors, Word2Vec

from algorithms.features.syscall_name import SyscallName
from algorithms.features.threadID_extractor import ThreadIDExtractor

from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall


class W2VEmbedding(BaseSyscallFeatureExtractor):
    """
        implementation of the w2v embedding approach based on BaseSyscallFeatureExtractor

        Special for this one:
            uses n_gram feature stream to create sentences for word corpus
            -> thread and file awareness given
    """

    def __init__(self,
                 vector_size: int,
                 window_size: int,
                 epochs: int,
                 scenario_path: str,
                 path: str = 'Models',
                 force_train: bool = False,
                 distinct: bool = True,
                 thread_aware=True):
        super().__init__()
        scenario_name = os.path.basename(os.path.normpath(scenario_path))
        path = path + f'/{scenario_name}'
        if not os.path.exists(path):
            os.makedirs(path)
        self._vector_size = vector_size
        self._epochs = epochs
        self._path = os.path.join(path, f'{vector_size}-{window_size}-{scenario_name}-{thread_aware}-{distinct}-w2v.model')
        self._force_train = force_train
        self._distinct = distinct
        self.w2vmodel = None
        self._sentences = []
        self._feature_list = [SyscallName(), ThreadIDExtractor()]
        self._window_size = window_size
        self._n_gram_streamer = StreamNgramExtractor(feature_list=[SyscallName()],
                                                     thread_aware=thread_aware,
                                                     ngram_length=window_size)
        if not force_train:
            self.load()

    def train_on(self, syscall: Syscall):
        """
            gives syscall features to n_gram feature stream, casts it as sentence and saves it to training corpus
        """
        if self.w2vmodel is None:
            syscall_feature_dict = {}
            for feature in self._feature_list:
                k, v = feature.extract(syscall)
                syscall_feature_dict[k] = v

            _, sentence = self._n_gram_streamer.extract(syscall_feature_dict)

            if sentence is not None:
                if self._distinct:
                    if sentence not in self._sentences:
                        self._sentences.append(sentence)
                else:
                    self._sentences.append(sentence)

    def fit(self):
        """
            trains the w2v model on training sentences
        """
        if not self.w2vmodel:
            model = Word2Vec(sentences=self._sentences, vector_size=self._vector_size, epochs=self._epochs,
                             window=self._window_size, min_count=1)

            model.save(fname_or_handle=self._path)
            self.w2vmodel = model

    def extract(self, syscall: Syscall) -> typing.Tuple[int, list]:
        """
            embeds one system call in w2v model

            if word is not in corpus a zero-vector with correct size is returned

            Returns:
                syscall vector
        """
        try:
            return W2VEmbedding.get_id(), self.w2vmodel.wv[syscall.name()].tolist()
        except KeyError:
            return W2VEmbedding.get_id(), [0] * self._vector_size

    def load(self):
        """
            check if word embedding has been created for this scenario
        """
        try:
            self.w2vmodel = KeyedVectors.load(self._path, mmap='r')
            print(f'Loaded embedding: {self._path}')
        except Exception:
            print(f'No embedding found for: {self._path}')

    def new_recording(self):
        """
            tells n_gram streamer to clear buffer after beginning of new recording
        """
        self._n_gram_streamer.new_recording()
