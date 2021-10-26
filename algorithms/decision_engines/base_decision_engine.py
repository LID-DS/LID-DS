class BaseDecisionEngine:
    """

    Base class for decision engine

        input: feature array from feature transformator
        output: anomaly score

    """
    def __init__(self):
        self.custom_fields = {}
        pass

    def train_on(self, input_array: list):
        """

        takes one feature instance to train decision approach

        """
        pass

    def fit(self):
        """

        finalizes training section

        some DEs need validation data to check if training improved

        """
        pass

    def predict(self, input_array: list) -> float:
        """

        predicts anomaly score for feature input

        """
        pass

    def new_recording(self):
        """

        after every recording
         e.g. clears window after score calculation

        """
        pass
