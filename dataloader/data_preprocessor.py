from typing import Union

from tqdm import tqdm

from algorithms.features.feature_manager import FeatureManager
from dataloader.data_loader import DataLoader
from dataloader.data_loader_2019 import DataLoader as DataLoader_2019
from dataloader.syscall import Syscall


class DataPreprocessor:
    """

        Receives DataLoader object, SyscallFeatureExtractor and StreamFeatureExtractor.
        Training data, validation data and test data can than be returned as feature lists.

    """

    def __init__(self,
                 data_loader: Union[DataLoader, DataLoader_2019],
                 feature_list: list
                 ):
        self._data_loader = data_loader
        self._feature_manager = FeatureManager(feature_list)
        print("feature dependency graph: ")
        print(self._feature_manager.to_dot())
        self._prepare_and_build_features()

    def _prepare_and_build_features(self):
        """
        preprocessing for features
        - calls train on and fit for each feature on the training data in the order given by the feature_manager
        """

        num_generations = len(self._feature_manager.feature_generations)
        for current_generation in range(0, num_generations):
            print(f"at generation: {current_generation + 1} of {num_generations}")
            print(f"   features: {self._feature_manager.feature_generations[current_generation]}")
            for previous_generation in range(0, current_generation):
                print(f"     depending on: {self._feature_manager.feature_generations[previous_generation]}")
            for recording in tqdm(self._data_loader.training_data(),
                                  f"preparing features {current_generation + 1}/{num_generations}".rjust(27),
                                  unit=" recording"):
                for syscall in recording.syscalls():
                    feature_dict = {}
                    # calculate already fitted features
                    for previous_generation in range(0, current_generation - 1):
                        for previous_feature in self._feature_manager.feature_generations[previous_generation]:
                            previous_feature.extract(syscall, feature_dict)
                    # call train_on for current iteration features
                    for current_feature in self._feature_manager.feature_generations[current_generation]:
                        current_feature.train_on(syscall, feature_dict)
                self.new_recording()

            # fit current generation features
            for current_feature in tqdm(self._feature_manager.feature_generations[current_generation],
                                        f"fitting features {current_generation + 1}/{num_generations}".rjust(27),
                                        unit=" features"):
                current_feature.fit()

    def syscall_to_feature(self, syscall: Syscall):
        """
        Convert syscall to feature.
        feature may be None.
        Returns:
        list: feature_vector or None
        """
        # first calculate all features in the correct order
        feature_dict = {}
        for current_generation in range(0, len(self._feature_manager.feature_generations)):
            for current_feature in self._feature_manager.feature_generations[current_generation]:
                current_feature.extract(syscall, feature_dict)
        # now build the final feature vector
        # here we must take care when appending / extending the feature vector, differt between:
        # strings (append), iterable (extend) and the rest (append)
        feature_vector = []
        for feature in self._feature_manager.get_features():
            if feature.get_id() in feature_dict and feature_dict[feature.get_id()] is not None:
                fv = feature_dict[feature.get_id()]
                if isinstance(fv, str):
                    feature_vector.append(fv)
                else:
                    try:
                        feature_vector.extend(fv)
                    except TypeError:
                        feature_vector.append(fv)
            else:
                return None
        return feature_vector

    def new_recording(self):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all features and calls new_recording on them
        """
        for generation in self._feature_manager.feature_generations:
            for feature in generation:
                feature.new_recording()
