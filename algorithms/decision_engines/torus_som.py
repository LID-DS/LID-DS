import numpy
from numpy import eye

from algorithms.util.toroidalsom import ToroidalSOM, torusDistanceFunction
from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class TorusSom(BuildingBlock):
    def __init__(self, input_vector, size, tscale, tfac):
        super().__init__()

        self._result_dict = {}
        self._input_vector = input_vector
        self._size = size
        self._dependency_list = [input_vector]
        self._tscale = tscale
        self._tfac = tfac
        self._buffer = set()

        self._som = None


    def depends_on(self) -> list:
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
            creates distinct input data buffer used for training
        """
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            if input_vector not in self._buffer:
                self._buffer.add(input_vector)

    def fit(self):

        x = numpy.array(list(self._buffer))
        vector_size = x.shape[1]
        alpha0 = 100.0 / float(x.shape[0])
        self._som = ToroidalSOM(self._size, vector_size)
        self._som.random_initialisation()

        self._som.fit(x=x, tfac=self._tfac, tscale=self._tscale, alpha0=alpha0)

    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            if input_vector in self._result_dict:
                return self._result_dict[input_vector]
            else:
                numpy_vector = numpy.array(input_vector)
                distances = self._som.distfun(numpy_vector, self._som.xmap.T, eye(numpy_vector.shape[0]))
                score = distances.min()
                self._result_dict[input_vector] = score
                return score
        else:
            return None