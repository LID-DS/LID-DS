import math
import sys
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

    def train_on(self, syscall: Syscall):
        current_value = self._bb_to_cluster.get_result(syscall)
        if current_value is not None:
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

    def _calculate(self, syscall: Syscall):
        """
        calculates the cluster ID of the given input
        """
        current_value = self._bb_to_cluster.get_result(syscall)
        if current_value is not None:
            if current_value in self._result_buffer:
                return self._result_buffer[current_value]
            else:
                result = self._predict(self._dbscan, current_value)
                self._result_buffer[current_value] = result
                return result
        else:
            return None
                

    def _predict(self, db, x):
        dists = np.sqrt(np.sum((db.components_ - x)**2, axis=1))
        if len(dists) == 0:
            return -1
        i = np.argmin(dists)
        return db.labels_[db.core_sample_indices_[i]] if dists[i] < db.eps else -1