class BaseFeatureTransformer:
    """

    base class for feature transformation e.g. embedding process

    """

    def __init__(self):
        pass

    def train_on(self, feature):
        """

        takes one feature instance to train transformation approach

        """
        pass

    def fit(self):
        """

        finalizes training section

        """
        pass

    def transform(self, feature):
        """

        transforms given feature to input data for decision engine

        """
        pass
