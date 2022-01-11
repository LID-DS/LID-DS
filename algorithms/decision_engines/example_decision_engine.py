import random

from algorithms.building_block import BuildingBlock


class ExampleDecisionEngine(BuildingBlock):
    """

    Base class for decision engine

        input: feature array from feature transformator
        output: anomaly score

    """

    def __init__(self):
        super().__init__()
        self._buffer = []
        self._final_list = []

    def train_on(self, input_array):
        """

        takes one feature instance to train decision approach

        """
        self._buffer = input_array
        pass

    def fit(self):
        """

        finalizes training section

        """
        self._final_list = self._buffer
        pass

    def predict(self, input_array) -> float:
        """

        predicts anomaly score for feature input

        """
        return random.random()
