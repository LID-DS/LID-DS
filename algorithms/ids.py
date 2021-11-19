from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from algorithms.performance_measurement import PerformanceMeasurement
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_preprocessor import DataPreprocessor


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 feature_list: list,
                 decision_engine: BaseDecisionEngine,
                 plot_switch: bool):
        self._data_loader = data_loader
        self._data_preprocessor = DataPreprocessor(self._data_loader, feature_list)
        self._decision_engine = decision_engine
        self.threshold = 0.0
        self._alarm = False
        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._first_syscall_after_exploit_list = []
        self._last_syscall_of_recording_list = []
        self.performance = PerformanceMeasurement()
        if plot_switch is True:
            self.plot = ScorePlot(data_loader.scenario_path)
        else:
            self.plot = None

    def train_decision_engine(self):
        """
        trains decision engine with training data

        """
        # train of DE
        data = self._data_loader.training_data()
        description = 'Training'.rjust(27)
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    self._decision_engine.train_on(feature_vector)
            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()
        self._decision_engine.fit()

    def determine_threshold(self):
        """
        decision engine calculates anomaly scores using validation data,
        saves biggest score as threshold for detection phase

        """
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation'.rjust(27)
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
        self.performance.set_threshold(max_score)
        if self.plot is not None:
            self.plot.threshold = max_score

    def do_detection(self):
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True

        """

        data = self._data_loader.test_data()
        description = 'anomaly detection'.rjust(27)

        for recording in tqdm(data, description, unit=" recording"):
            self.performance.new_recording(recording)
            if self.plot is not None:
                self.plot.new_recording(recording)

            for syscall in recording.syscalls():
                feature_vector = self._data_preprocessor.syscall_to_feature(syscall)
                if feature_vector is not None:
                    anomaly_score = self._decision_engine.predict(feature_vector)

                    self.performance.analyze_syscall(syscall, anomaly_score)
                    if self.plot is not None:
                        self.plot.add_to_plot_data(anomaly_score, syscall, self.performance.get_cfp_indices())

            self._data_preprocessor.new_recording()
            self._decision_engine.new_recording()

    def draw_plot(self):
        # plot data if wanted
        if self.plot is not None:
            self.plot.feed_figure()
            self.plot.show_plot()
