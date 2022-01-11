from tqdm import tqdm
from algorithms.building_block import BuildingBlock

from algorithms.performance_measurement import PerformanceMeasurement
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from algorithms.data_preprocessor import DataPreprocessor


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block: BuildingBlock,                 
                 plot_switch: bool,
                 create_alarms: bool = False):
        self._data_loader = data_loader
        self._final_bb = resulting_building_block
        self._data_preprocessor = DataPreprocessor(self._data_loader, resulting_building_block)
        self.threshold = 0.0
        self._alarm = False
        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._first_syscall_after_exploit_list = []
        self._last_syscall_of_recording_list = []
        self.performance = PerformanceMeasurement(create_alarms)
        if plot_switch is True:
            self.plot = ScorePlot(data_loader.scenario_path)
        else:
            self.plot = None

    def get_config(self) -> str:
        return self._data_preprocessor.get_graph_dot()

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
                results = self._data_preprocessor.calculate_building_blocks_for_syscall(syscall)
                if self._final_bb.get_id() in results:
                    anomaly_score = results[self._final_bb.get_id()]
                    #print(anomaly_score)
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording()
            # self._decision_engine.new_recording()
        self.threshold = max_score
        self.performance.set_threshold(max_score)
        if self.plot is not None:
            self.plot.threshold = max_score
        print(f"threshold={max_score:.3f}".rjust(27))

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
                results = self._data_preprocessor.calculate_building_blocks_for_syscall(syscall)
                if self._final_bb.get_id() in results:
                    anomaly_score = results[self._final_bb.get_id()]
                    self.performance.analyze_syscall(syscall, anomaly_score)
                    if self.plot is not None:
                        self.plot.add_to_plot_data(anomaly_score, syscall, self.performance.get_cfp_indices())

            self._data_preprocessor.new_recording()
            #self._decision_engine.new_recording()

            # run end alarm once to ensure that last alarm gets saved
            if self.performance.alarms is not None:
                self.performance.alarms.end_alarm()

            # run end alarm once to ensure that last alarm gets saved
            if self.performance.alarms is not None:
                self.performance.alarms.end_alarm()

    def draw_plot(self):
        # plot data if wanted
        if self.plot is not None:
            self.plot.feed_figure()
            self.plot.show_plot()
