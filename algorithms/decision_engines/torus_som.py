import numpy

from algorithms.util.toroidalsom import toroidalSOM
from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class TorusSom(BuildingBlock):
    def __init__(self, input_vector, size, epochs):
        super().__init__()

        self._input_vector = input_vector
        self._size = size
        self._dependency_list = []
        self._epochs = epochs
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
        vector_size = len(next(iter(self._buffer)))
        self._som = toroidalSOM(Nmap=self._size, D=vector_size)

        alpha0 = 0.01

        x = numpy.array(self._buffer)

        self._som.fit(x=x, tfac=100, tscale=self._epochs, alpha0=alpha0)

    def _calculate(self, syscall: Syscall):
        input_vector = numpy.array(self._input_vector.get_result(syscall))
        distances = self._som.distfun(input_vector, self._som.xmap.T)
        return min(distances)
