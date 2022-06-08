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

        Args:
            vector_size: the w2v output vector size
            window_size: size of w2v context window
            epochs: number of epochs for 2v training
            scenario_path: path of the LID-DS scenario (used for model persist)
            path: path for Models directory
            force_train: bool that decides if w2v model shall be loaded or forced to retrain
            distinct: true if training dataset shall be distinct, gives tremendous increase in training speed
            thread_aware: true if training sentences shall be created thread aware
            unknown_input_value: value that gets set for every dimension if unknown input word is given to w2v model
    """

    def __init__(self,
                 vector_size: int,
                 window_size: int,
                 epochs: int,
                 scenario_path: str,
                 path: str = 'Models',
                 force_train: bool = False,
                 distinct: bool = True,
                 thread_aware=True,
                 unknown_input_value: float = 0.0):
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
        self._window_size = window_size
        self._n_gram_streamer = Ngram(feature_list=[SyscallName()],
                                      thread_aware=thread_aware,
                                      ngram_length=window_size)
        if not force_train:
            self.load()

        self._unknown_input_value = unknown_input_value
        self._dependency_list = []

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
            gives syscall features to n_gram feature stream, casts it as sentence and saves it to training corpus
        """
        if self.w2vmodel is None:            
            #self._syscall_name_feature.get_result(syscall)
            ngram = self._n_gram_streamer.get_result(syscall)
            if ngram is not None:                
                if self._distinct:
                    if ngram not in self._sentences:
                        self._sentences.append(ngram)
                else:
                    self._sentences.append(ngram)

    def fit(self):
        """
            trains the w2v model on training sentences
        """
        if not self.w2vmodel:
            model = Word2Vec(sentences=self._sentences, vector_size=self._vector_size, epochs=self._epochs,
                             window=self._window_size, min_count=1)

            model.save(fname_or_handle=self._path)
            self.w2vmodel = model

    def _calculate(self, syscall: Syscall):
        """
            embeds one system call in w2v model

            if word is not in corpus a zero-vector with correct size is returned

            Returns:
                syscall vector
        """
        try:
            return tuple(self.w2vmodel.wv[syscall.name()].tolist())
        except KeyError:
            return tuple([self._unknown_input_value] * self._vector_size)

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
