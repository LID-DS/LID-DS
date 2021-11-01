from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_preprocessor import DataPreprocessor
from algorithms.performance_measurement import PerformanceMeasurement


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 data_preprocessor: DataPreprocessor,
                 decision_engine: BaseDecisionEngine):
        self._data_loader = data_loader
        self._data_preprocessor = data_preprocessor
        self._decision_engine = decision_engine
        self.threshold = 0.0
        self._performance_values = {}
        self._alarm = False
        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._first_syscall_after_exploit_list = []
        self._last_syscall_of_recording_list = []

    def train_decision_engine(self):
        # train of DE
        data = self._data_loader.training_data()
        description = 'Training: '
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    self._decision_engine.train_on(feature_vector)
            self._data_preprocessor.new_recording()
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
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()
        self.threshold = max_score

    def get_scores(self):

        perform = PerformanceMeasurement(self.threshold)

        data = self._data_loader.test_data()
        description = 'anomaly detection: '

        for recording in tqdm(data, description, unit=" recording"):
            perform.scan_recording(recording)

            for syscall in recording.syscalls():
                perform.scan_syscall(syscall)
                perform.get_plotting_data(syscall)

        self._data_preprocessor.new_recording()
        self._decision_engine.new_recording()

    def get_performance(self):

        """
        returns dict with performance values
        """

        return self._performance_values

    def get_plotting_data(self):

        """
           returns relevant information for plot
        """

        return self.threshold, self._first_syscall_after_exploit_list, self._last_syscall_of_recording_list, self._anomaly_scores_exploits, self._anomaly_scores_no_exploits