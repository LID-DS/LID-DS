import numpy as np
from sklearn.svm import OneClassSVM as SklearnOCSVM

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class OCSVM(BuildingBlock):
    def __init__(self, input_vector: BuildingBlock,
                 kernel='rbf', nu=0.5, gamma='scale'):
        """
            Anomaly Detection Engine based on sklearn's One-Class SVM.

            Trains on distinct normal vectors, scores via negated decision_function
            (higher = more anomalous, consistent with other engines).

            Parameters:
                input_vector: Input BuildingBlock providing feature vectors
                kernel: Kernel type ('rbf', 'linear', 'poly', 'sigmoid')
                nu: Upper bound on training error fraction / lower bound on support vectors. Range (0, 1]
                gamma: Kernel coefficient for rbf/poly/sigmoid
        """
        super().__init__()
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._kernel = kernel
        self._nu = nu
        self._gamma = gamma
        self._buffer = set()
        self._model = None
        self._cache = {}

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            self._buffer.add(input_vector)

    def fit(self):
        print(f"ocsvm.train_set: {len(self._buffer)}".rjust(27))
        training_data = np.array(list(self._buffer))
        self._model = SklearnOCSVM(
            kernel=self._kernel, nu=self._nu, gamma=self._gamma)
        self._model.fit(training_data)
        self._buffer = set()

    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            if input_vector not in self._cache:
                score = -self._model.decision_function(
                    np.array([input_vector]))[0]
                self._cache[input_vector] = score
            return self._cache[input_vector]
        return None
