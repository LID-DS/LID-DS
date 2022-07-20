import numpy

from numpy import eye
from functools import lru_cache

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock
from algorithms.util.toroidalsom import ToroidalSOM


class TorusSom(BuildingBlock):
    def __init__(self, input_vector: BuildingBlock, size: int, tscale, tfac):
        """
            Anomaly Detection Building Block using a toroidal SOM
            Uses adjusted toroidal SOM Implementation from https://github.com/swilshin/toroidalsom/

            Parameters:

                input_vector: a Building Block
                size: Number of Neurons to be initialized
                tfac: number of epochs over which significant decay occurs
                tscale: is multiplied with tfac to set total number of epochs

        """
        super().__init__()

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
        """
            initializes and trains the toroidal SOM on the training Data
            initial learning rate is derived from number of input datapoints
        """
        x = numpy.array(list(self._buffer))
        vector_size = x.shape[1]
        alpha0 = 100.0 / float(x.shape[0])
        self._som = ToroidalSOM(self._size, vector_size)
        self._som.random_initialisation()

        self._som.fit(x=x, tfac=self._tfac, tscale=self._tscale, alpha0=alpha0)

    @lru_cache(maxsize=1000)
    def _cached_results(self, input_vector: tuple):
        """
            calculates and caches anomaly score

            the anomaly score is the distance on the torus between the test datapoint
            and the weight vector of the  winning neuron

            Parameters:
                input_vector: tuple containing the test vector
        """
        if input_vector is not None:
            numpy_vector = numpy.array(input_vector)
            distances = self._som.distfun(numpy_vector, self._som.xmap.T, eye(numpy_vector.shape[0]))
            score = distances.min()
            return score
        else:
            return None

    def _calculate(self, syscall: Syscall):
        """
            extracts test vector from current syscall and returns cached result
        """
        input_vector = self._input_vector.get_result(syscall)
        return self._cached_results(input_vector)
