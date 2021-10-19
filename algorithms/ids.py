from typing import Union

from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from dataloader.data_preprocessor import DataPreprocessor
from dataloader.data_loader import DataLoader


class IDS:
    def __init__(self,
                 data_loader: Union[DataLoader, DataLoader],
                 data_preprocessor: DataPreprocessor,
                 decision_engine: BaseDecisionEngine):
        self._data_loader = data_loader
        self._data_preprocessor = data_preprocessor
        self._decision_engine = decision_engine
        self._threshold = 0.0

    def train_decision_engine(self):
        # train of DE
        data = self._data_loader.training_data()
        description = 'Training: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    self._decision_engine.train_on(feature_vector)
            self._data_preprocessor.reset_recording()
            self._decision_engine.new_recording()
        self._decision_engine.fit()

    def determine_threshold(self):
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    anomaly_score = self._decision_engine.predict(feature_vector)
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.reset_recording()
            self._decision_engine.new_recording()
        self._threshold = max_score

    def do_detection(self):
        data = self._data_loader.test_data()
        description = 'anomaly detection: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    anomaly_score = self._decision_engine.predict(feature_vector)
                    if anomaly_score > self._threshold:
                        pass
            self._data_preprocessor.reset_recording()
            self._decision_engine.new_recording()
