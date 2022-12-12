import math

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class KCenter(BuildingBlock):
    def __init__(self,
                 feature: BuildingBlock, k: int):
        super().__init__()
        self._feature = feature
        self._dependency_list = []
        self._dependency_list.append(self._feature)
        self._k = k

        self._datapoints = []
        self.distance_matrix = []

        self.centers = []

    def is_decider(self):
        return True

    def val_on(self, syscall: Syscall):
        feature_input = self._feature.get_result(syscall)
        self._datapoints.append(list(feature_input))

    def fit(self):
        for point_a in self._datapoints:
            distances = []
            for point_b in self._datapoints:
                # calculate euclidian distance
                distance = math.dist(point_a, point_b)
                distances.append(distance)
            self.distance_matrix.append(distances)
        self._find_k_centers()

    def _find_k_centers(self):
        n = len(self.distance_matrix)
        dist = [0] * n
        for i in range(n):
            dist[i] = 10 ** 9

        maximum = 0
        for i in range(self._k):
            self.centers.append(maximum)
            for j in range(n):
                # updating the distance
                # of the center to their
                # closest centers
                dist[j] = min(dist[j], self.distance_matrix[maximum][j])

            # updating the index of the
            # center with the maximum
            # distance to it's closest center
            maximum = self._calc_max_index(dist, n)

    @staticmethod
    def _calc_max_index(dist, n):
        max_index = 0
        for i in range(n):
            if dist[i] > dist[max_index]:
                max_index = i
        return max_index


