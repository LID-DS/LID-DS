import math

from tqdm import tqdm

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class NearestNeighbour(BuildingBlock):
    def __init__(self,
                 feature: BuildingBlock):
        """
        Building Block that implements the nearest neighbour anomaly decider approach

        Idea:   - find nearest neighbour from validation data for new test data point by euclidian distance
                - find nearest neighbour of the nearest neighbour
                - compare their distances and decide if datapoint is anomal

        @param feature: the input feature building block
        """
        super().__init__()
        self._feature = feature
        self._dependency_list = []
        self._dependency_list.append(self._feature)

        self._datapoints = []
        self._distance_matrix = []

        self._nearest_neighbour_distances = []

        self._cache = {}

    def is_decider(self):
        return True

    def depends_on(self):
        return self._dependency_list

    def val_on(self, syscall: Syscall):
        """
        adds validation datapoints to distinct datapoint list
        @param syscall: the current validation system call
        """
        feature_input = self._feature.get_result(syscall)

        # cast int to list
        if type(feature_input) == int:
            feature_input = [feature_input]

        if feature_input is not None:
            if list(feature_input) not in self._datapoints:
                self._datapoints.append(list(feature_input))

    def fit(self):
        """
        calculates the distance matrix for all datapoints in validation data
        saves the nearest neighbours for all datapoints
        """

        # calculate distance matrix
        for point_a in tqdm(self._datapoints, desc="Calc distance matrix".rjust(27)):
            distances = []
            for point_b in self._datapoints:
                # calculate euclidian distance
                distance = math.dist(point_a, point_b)
                distances.append(distance)
            self._distance_matrix.append(distances)

        # find distance of nearest neighbour for every datapoint and save it in list
        for distances in tqdm(self._distance_matrix, desc="Calc all nearest neighbours".rjust(27)):
            min_distance = 10 ** 9
            for distance in distances:
                # the point has distance 0.0 to itself but is not its own neighbour -> filtering it
                if 0.0 < distance < min_distance:
                    min_distance = distance

            self._nearest_neighbour_distances.append(min_distance)

    def _calculate(self, syscall: Syscall) -> bool:
        """
        finds the nearest neighbour and its distance for new datapoint

        checks if the distance to the nearest neighbour of the nearest neighbour
        is higher or lower than the calculated distance

        @param syscall: System Call to be evaluated by this building block
        @return: boolean decision if point is an anomaly or not
        """
        feature_input = self._feature.get_result(syscall)

        # cast int to list
        if type(feature_input) == int:
            feature_input = [feature_input]

        if feature_input is not None:
            feature_input = list(feature_input)
            # caching the result
            if tuple(feature_input) in self._cache.keys():
                return self._cache[tuple(feature_input)]
            else:
                # find the nearest neighbour of input datapoint
                min_distance = 10 ** 9
                min_index = 0
                for point_index, datapoint in enumerate(self._datapoints):
                    current_distance = math.dist(feature_input, datapoint)
                    if current_distance < min_distance:
                        min_distance = current_distance
                        min_index = point_index

                # retrieve the distance of nearest neighbour to its nearest neighbour by looking up its index
                nearest_neighbour_nn_distance = self._nearest_neighbour_distances[min_index]

                # check if distance of datapoint to nearest neighbour is higher than
                # the distance of the nearest neighbour to its nearest neighbour
                if min_distance > nearest_neighbour_nn_distance:
                    self._cache[tuple(feature_input)] = True
                    return True
                else:
                    self._cache[tuple(feature_input)] = False
                    return False
