import math

from matplotlib import pyplot as plt

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall
from minisom import MiniSom
from tqdm import tqdm
import numpy as np
from numpy.linalg import norm


class Som(BuildingBlock):
    def __init__(self, input_vector: BuildingBlock, epochs: int = 50, sigma: float = 1.0, learning_rate: float = 0.5 ,  max_size: int = None):
        """
            Anomaly Detection Engine based on Teuvo Kohonen's Self-Organizing-Map (SOM)

            Uses the MiniSOM Implementation from https://github.com/JustGlowing/minisom

            Vector size is derived from input data size

            Parameters:

                epochs: Number of Epochs for training (Iterations over complete training data)
                sigma: Spread of the neighborhood function, needs to be adequate to the dimensions of the map
                    (at iteration t: have sigma(t) = sigma / (1 + t/T) where T is #num_iteration/2)
                learning_rate: Initial learning rate
                    (at iteration t: learning_rate(t) = learning_rate / (1 + t/T) where T is #num_iteration/2)
        """
        super().__init__()
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._sigma = sigma
        self._learning_rate = learning_rate
        self._buffer = set()
        self._epochs = epochs
        self._som = None
        self._cache = {}
        self._max_size = max_size
        self.custom_fields = {}

    def depends_on(self):
        return self._dependency_list

    def _estimate_som_size(self):
        """
            Estimates the SOM size by adding 1 to the root of number of vectors in training data.
            As training data is distinct this leads to a slightly higher number of Neurons than distinct input vectors

            Idea: Have at least one Neuron for every single distinct input vector
        """
        som_size = round(math.sqrt(
            len(self._buffer)
        ), 0)

        som_size += 1
        if self._max_size is not None and som_size > self._max_size:
            return self._max_size
        else:
            return int(som_size)

    def train_on(self, syscall: Syscall, dependencies: dict):
        """
            creates distinct input data buffer used for training
        """
        if self._input_vector.get_id() in dependencies:
            input_vector = dependencies[self._input_vector.get_id()]
            if not input_vector in self._buffer:
                self._buffer.add(input_vector)

    def fit(self):
        """
            finalizes the training step for the som
        """
        print(f"som.train_set: {len(self._buffer)} ".rjust(27))
        # print(self._buffer)
        som_size = self._estimate_som_size()
        # vector_size = len(self._buffer[0])
        vector_size = len(next(iter(self._buffer)))

        self._som = MiniSom(som_size, som_size, vector_size,
                            random_seed=1,
                            sigma=self._sigma,
                            learning_rate=self._learning_rate)

        for epoch in tqdm(range(self._epochs), desc='Training SOM'.rjust(27)):
            for vector in self._buffer:
                self._som.update(vector, self._som.winner(vector), epoch, self._epochs)

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
            calculates euclidean distance between input and codebook vector which is used as anomaly score

            Returns:
                distance (float): euclidian distance/anomaly score
        """
        if self._input_vector.get_id() in dependencies:
            input_vector = dependencies[self._input_vector.get_id()]
            if input_vector not in self._cache:
                codebook_vector = np.array(self._som.quantization([input_vector])[0])
                vector = np.array(input_vector)
                distance = norm(vector - codebook_vector)
                self._cache[input_vector] = distance
            else:
                distance = self._cache[input_vector]
            dependencies[self.get_id()] = distance
            

    def show_distance_plot(self):
        """
            Creates distance plot for trained SOM, ach cell is the normalised sum of the distances
            between a neuron and its neighbours.
        """
        plt.figure()
        plt.pcolor(self._som.distance_map(), cmap='gnuplot')
        plt.colorbar()

        plt.show()

    def calculate_errors(self):
        """
            Calculates Errors and adds them to public custom field dict.

            Errors are only calculated for training data.

            Quantization Error:
                average distance between each input sample and its best matching neuron

            Topographic Error:
                Is computed by finding the best-matching and second-best-matching neuron
                in the map for each input and then evaluating the positions.

                A sample for which these two nodes are not adjacent counts as
                an error. The topographic error is given by the
                the total number of errors divided by the total of samples.

                If the topographic error is 0, no error occurred.
                If 1, the topology was not preserved for any of the samples.
        """
        self.custom_fields['training_quantization_error'] = self._som.quantization_error(self._buffer)
        self.custom_fields['training_quantization_error'] = self._som.topographic_error(self._buffer)
