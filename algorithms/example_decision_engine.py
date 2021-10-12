class ExampleDecisionEngine:
    """

    Base class for decision engine

        input: feature array from feature transformator
        output: anomaly score

    """
    def __init__(self):
        self._buffer = []
        self._final_list = []
        pass

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
        return self._final_list[0]
