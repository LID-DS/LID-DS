from typing import Union, Type, Generator

from tqdm import tqdm

from algorithms.base_decision_engine import BaseDecisionEngine
from dataloader.data_loader import DataLoader
from dataloader.syscall import Syscall


class IDS:
    def __init__(self,
                 syscall_feature_list: list,
                 stream_feature_list: list,
                 data_loader: Union[DataLoader, DataLoader],
                 decision_engine: Type[BaseDecisionEngine]):
        self._data_loader = data_loader
        self._decision_engine = decision_engine
        self._syscall_feature_list = syscall_feature_list
        self._stream_feature_list = stream_feature_list
        self._prepare_and_build_features()
        self._threshold = 0.0

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

    def _generate_feature_vectors(self,
                                  data: list,
                                  description: str = "") -> Generator[list, None, None]:
        """
        generator: given a list of recordings (like dataloader.trainint()) generates all feature vectors
        """
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_dict = self._extract_features_from_syscall(syscall)
                feature_vector = self._extract_features_from_stream(feature_dict)
                if len(feature_vector) > 0:
                    yield feature_vector

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
        # fit syscall features
        for syscall_feature in tqdm(self._syscall_feature_list, "fitting features 1/2".rjust(25), unit=" features"):
            syscall_feature.fit()

        # train streaming features
        for recording in tqdm(self._data_loader.training_data(), "preparing features 2/2".rjust(25), unit=" recording"):
            for syscall in recording.syscalls():
                features_of_syscall = self._extract_features_from_syscall(syscall)
                for stream_feature in self._stream_feature_list:
                    stream_feature.train_on(features_of_syscall)

        # fit streaming features
        for stream_feature in tqdm(self._stream_feature_list, "fitting features 2/2".rjust(25), unit=" features"):
            stream_feature.fit()

    def train_decision_engine(self):
        # train of DE
        for feature_vector in self._generate_feature_vectors(self._data_loader.training_data(), "train DE".rjust(25)):
            self._decision_engine.train_on(feature_vector)
        self._decision_engine.fit()

    def determine_threshold(self):
        max_score = 0.0
        for feature_vector in self._generate_feature_vectors(self._data_loader.validation_data(),
                                                             "determine threshold".rjust(25)):
            anomaly_score = self._decision_engine.predict(feature_vector)
            if anomaly_score > max_score:
                max_score = anomaly_score
        self._threshold = max_score

    def do_detection(self):
        for feature_vector in self._generate_feature_vectors(self._data_loader.test_data(),
                                                             "anomaly detection".rjust(25)):
            anomaly_score = self._decision_engine.predict(feature_vector)
            if anomaly_score > self._threshold:
                pass
                # TODO count statistics, maybe here we cant use the _generate_feature_vectors method...

