class BaseDecisionEngine:
    """

    Base class for decision engine

        input: feature array from feature transformator
        output: anomaly score

    """
    def __init__(self):
        pass

    def train_on(self, input_array):
        """

        takes one feature instance to train decision approach

        """
        pass

    def fit(self):
        """

        finalizes training section

        """
        pass

    def predict(self, input_array) -> float:
        """

        predicts anomaly score for feature input

        """
        pass
