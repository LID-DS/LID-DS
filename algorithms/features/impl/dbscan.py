import math
import typing

import numpy as np
from sklearn.cluster import DBSCAN
from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class DBScan(BuildingBlock):
    """
    clustering BB 
    -> clusters the input
    -> gives a representative as result
    uses scikit learns implementation of dbscan
    """
    def __init__(self, bb_to_cluster: BuildingBlock, eps=0.01):
        """
        """
        super().__init__()
        self._bb_to_cluster = bb_to_cluster
        self._bb_id = self._bb_to_cluster.get_id()        
        self._training_data = set()
        self._dbscan = DBSCAN(eps=eps, min_samples=10)
        self._result_buffer = {}

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        return [self._bb_to_cluster]

    def train_on(self, syscall: Syscall, features: dict):        
        if self._bb_id in features:
            current_value = features[self._bb_id]
            self._training_data.add(current_value)

    def fit(self):
        """
        calculates all clusters
        """
        print(f"dbscan.#points: {len(self._training_data)}".rjust(27))
        tdata = np.array(list(self._training_data))
        tdata = np.reshape(tdata, (-1,1))                
        self._dbscan.fit(tdata)
        num_clusters = len(set(self._dbscan.labels_)) - (1 if -1 in self._dbscan.labels_ else 0)
        print(f"dbscan.clusters: {num_clusters}".rjust(27))

    def calculate(self, syscall: Syscall, features: dict):
        """
        calculates the cluster ID of the given input
        """
        if self._bb_id in features:
            input = features[self._bb_id]
            if input in self._result_buffer:
                features[self.get_id()] = self._result_buffer[input]
            else:
                result = None
                result = self._predict(self._dbscan, features[self._bb_id])
                features[self.get_id()] = result
                self._result_buffer[input] = result

    def _predict(self, db, x):
        dists = np.sqrt(np.sum((db.components_ - x)**2, axis=1))
        if len(dists) == 0:
            return -1
        i = np.argmin(dists)
        return db.labels_[db.core_sample_indices_[i]] if dists[i] < db.eps else -1