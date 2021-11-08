from tqdm import tqdm
from typing import Union

from dataloader.data_loader import DataLoader
from dataloader.syscall import Syscall
from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor
from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.data_loader_2019 import DataLoader as DataLoader_2019


class DataPreprocessor:
    """

        Receives DataLoader object, SyscallFeatureExtractor and StreamFeatureExtractor.
        Training data, validation data and test data can than be returned as feature lists.

    """
    def __init__(self,
                 data_loader: Union[DataLoader, DataLoader_2019],
                 syscall_feature_list: list,
                 stream_feature_list: list,
                 feature_of_stream_feature_list: list):
        self._data_loader = data_loader
        self._syscall_feature_list = syscall_feature_list
        self._stream_feature_list = stream_feature_list
        self._feature_of_stream_feature_list = feature_of_stream_feature_list
        self._prepare_and_build_features()

    def _prepare_and_build_features(self):
        """
        preprocessing for features
        - calls train on and fit for each syscall and stream feature on the training data
        """
        # train syscall features

        for recording in tqdm(self._data_loader.training_data(), "preparing features 1/2".rjust(25), unit=" recording"):
            for syscall in recording.syscalls():
                for syscall_feature in self._syscall_feature_list:
                    syscall_feature.train_on(syscall)
            self.new_recording()

        # fit syscall features
        for syscall_feature in tqdm(self._syscall_feature_list, "fitting features 1/2".rjust(25), unit=" features"):
            syscall_feature.fit()

        # train streaming features
        for recording in tqdm(self._data_loader.training_data(), "preparing features 2/2".rjust(25), unit=" recording"):
            for syscall in recording.syscalls():
                features_of_syscall = self._extract_features_from_syscall(syscall)
                for stream_feature in self._stream_feature_list:
                    stream_feature.train_on(features_of_syscall)
            self.new_recording()

        # fit streaming features
        for stream_feature in tqdm(self._stream_feature_list, "fitting features 2/2".rjust(25), unit=" features"):
            stream_feature.fit()

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
        """
        stream_feature_dict = {}
        for stream_feature in self._stream_feature_list:
            k, v = stream_feature.extract(syscall_features)
            if v is not None:
                stream_feature_dict[k] = v
        return stream_feature_dict

    def _extract_features_from_stream_features(self,
                                               syscall_features: dict,
                                               stream_features: dict) -> list:
        """
        This method applies the passed feature extractors to the passed dict of system call features
        """
        stream_feature_dict = {}
        for stream_feature in self._feature_of_stream_feature_list:
            k, v = stream_feature.extract(syscall_features, stream_features)
            if v is not None:
                stream_feature_dict[k] = v
        return stream_feature_dict

    def _convert_feature_dict_to_list(self,
                                      stream_feature_dict: dict) -> list:
        """
        This method creates the final array (list) of feature values.
        """
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
        syscall_feature_dict = self._extract_features_from_syscall(syscall)
        # print(syscall_feature_dict)
        stream_feature_dict = self._extract_features_from_stream(syscall_feature_dict)
        feature_dict = self._extract_features_from_stream_features(syscall_feature_dict,
                                                                   stream_feature_dict)
        feature_vector = self._convert_feature_dict_to_list(feature_dict)
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
