from typing import Union

from tqdm import tqdm

from algorithms.features.feature_dependency_manager import FeatureDependencyManager
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
                 feature_manager: FeatureDependencyManager
                 ):
        self._data_loader = data_loader
        self._feature_manager = feature_manager
        self._prepare_and_build_features()

    def _prepare_and_build_features(self):
        """
        preprocessing for features
        - calls train on and fit for each feature on the training data in the order given by the feature_extractor
        """

        num_generations = len(self._feature_manager.feature_generations)
        for current_generation in range(0, num_generations):
            for recording in tqdm(self._data_loader.training_data(),
                                  f"preparing features {current_generation + 1}/{num_generations}".rjust(25),
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
                                f"fitting features {current_generation + 1}/{num_generations}".rjust(25),
                                unit=" features"):
                current_feature.fit()

    def _extract_features_from_syscall(self,
                                       syscall: Syscall) -> dict:
        """
        This method applies the passed feature extractors to the passed system call
        and creates a dictionary containing one entry for each of the features.
        """
        syscall_feature_dict = {}
        for feature in self._syscall_feature_list:
            k, v = feature.extract(syscall)
            syscall_feature_dict[k] = v
        return syscall_feature_dict

    def _extract_features_from_stream(self,
                                      syscall_features: dict) -> list:
        """
        This method applies the passed feature extractors to the passed dict of system call features
        and creates the final array (list) of feature values.
        """
        stream_feature_dict = {}
        for stream_feature in self._stream_feature_list:
            k, v = stream_feature.extract(syscall_features)
            if v is not None:
                stream_feature_dict[k] = v
        extracted_feature_list = []
        for key in stream_feature_dict.keys():
            extracted_feature_list += stream_feature_dict[key]
        return extracted_feature_list

    def syscall_to_feature(self, syscall: Syscall):
        """

        Convert syscall to feature.
        feature may be None.

        Returns:
        list: feature_vector

        """
        feature_dict = self._extract_features_from_syscall(syscall)
        feature_vector = self._extract_features_from_stream(feature_dict)
        if len(feature_vector) > 0:
            return feature_vector
        else:
            return None

    def new_recording(self):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all features and calls new_recording on them
        """
        syscall_feature: BaseSyscallFeatureExtractor  # type hint
        stream_feature: BaseStreamFeatureExtractor  # type hint
        for syscall_feature in self._syscall_feature_list:
            syscall_feature.new_recording()
        for stream_feature in self._stream_feature_list:
            stream_feature.new_recording()
