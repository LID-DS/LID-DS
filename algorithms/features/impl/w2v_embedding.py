from gensim.models import KeyedVectors, Word2Vec
from algorithms.building_block import BuildingBlock
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall import Syscall


class W2VEmbedding(BuildingBlock):
    """
        Args:
            word: BuildingBlock used as word in the sentences Word2Vec learns from.
            vector_size: the w2v output vector size
            window_size: size of w2v context window (the senctence size)
            epochs: number of epochs for 2v training                                    
            distinct: true if training dataset shall be distinct, gives tremendous increase in training speed
            thread_aware: true if training sentences shall be created thread aware
            unknown_input_value: value that gets set for every dimension if unknown input word is given to w2v model
    """

    def __init__(self,
                 word: BuildingBlock,
                 vector_size: int,
                 window_size: int,
                 epochs: int,
                 distinct: bool = True,
                 thread_aware=True,
                 unknown_input_value: float = 0.0):
        super().__init__()
        self._vector_size = vector_size
        self._epochs = epochs
        self._distinct = distinct
        self.w2vmodel = None
        self._sentences = []        
        self._window_size = window_size
        
        self._input_bb = word

        self._ngram_bb = Ngram(feature_list=[word],
                               thread_aware=thread_aware,
                               ngram_length=window_size)

        self._unknown_input_value = unknown_input_value
        self._dependency_list = [self._ngram_bb, self._input_bb]

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
            gets training systemcalls one after another
            builds sentences(ngrams) from them 
            saves them to training corpus
        """
        if self.w2vmodel is None:
            ngram = self._ngram_bb.get_result(syscall)
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
            print(f"w2v.train_set: {len(self._sentences)}".rjust(27))
            model = Word2Vec(sentences=self._sentences,
                             vector_size=self._vector_size,
                             epochs=self._epochs,
                             window=self._window_size,
                             min_count=1)
            self.w2vmodel = model

    def _calculate(self, syscall: Syscall):
        """
            returns the w2v embedding to a given input            
            if the input is not in the training corpus a pre-defined vector (see: unknown_input_value) is returned

            Returns:
                tuple representing the w2v embedding or None if no embedding can be calculated for the input
        """
        try:
            input = self._input_bb.get_result(syscall)
            if input is not None:
                return tuple(self.w2vmodel.wv[input].tolist())
            else: 
                return None
        except KeyError:
            return tuple([self._unknown_input_value] * self._vector_size)
