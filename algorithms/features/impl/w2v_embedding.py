import os.path

from gensim.models import KeyedVectors, Word2Vec

from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall import Syscall


class W2VEmbedding(BuildingBlock):
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
        self._path = os.path.join(path,
                                  f'{vector_size}-{window_size}-{scenario_name}-{thread_aware}-{distinct}-{epochs}-w2v.model')
        self._force_train = force_train
        self._distinct = distinct
        self.w2vmodel = None
        self._sentences = []
        self._syscall_name_feature = SyscallName()
        self._window_size = window_size
        self._n_gram_streamer = Ngram(feature_list=[SyscallName()],
                                      thread_aware=thread_aware,
                                      ngram_length=window_size)
        if not force_train:
            self.load()

        self._dependency_list = []

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall, features: dict):
        """
            gives syscall features to n_gram feature stream, casts it as sentence and saves it to training corpus
        """
        if self.w2vmodel is None:
            local_features = {}
            self._syscall_name_feature.calculate(syscall, local_features)
            self._n_gram_streamer.calculate(syscall, local_features)
            if self._n_gram_streamer.get_id() in local_features:
                sentence = local_features[self._n_gram_streamer.get_id()]
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

    def calculate(self, syscall: Syscall, features: dict):
        """
            embeds one system call in w2v model

            if word is not in corpus a zero-vector with correct size is returned

            Returns:
                syscall vector
        """
        try:
            features[self.get_id()] = self.w2vmodel.wv[syscall.name()].tolist()
        except KeyError:
            features[self.get_id()] = [0] * self._vector_size

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
