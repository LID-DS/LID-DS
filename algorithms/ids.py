from os import get_exec_path
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map

from algorithms.building_block import BuildingBlock
from pprint import pprint

from algorithms.alarms import Alarms
from algorithms.performance_measurement import Performance, PerformanceMeasurement
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from algorithms.data_preprocessor import DataPreprocessor
from dataloader.base_recording import BaseRecording



class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block: BuildingBlock,                 
                 plot_switch: bool,
                 create_alarms: bool = False,
                 recording: BaseRecording = None):
        self._data_loader = data_loader
        self._final_bb = resulting_building_block
        self._data_preprocessor = DataPreprocessor(self._data_loader, resulting_building_block)
        self.threshold = 0.0
        self._alarm = False
        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._first_syscall_after_exploit_list = []
        self._last_syscall_of_recording_list = []
        self._create_alarms = create_alarms
        self.performance = PerformanceMeasurement(create_alarms)
        if plot_switch is True:
            self.plot = ScorePlot(data_loader.scenario_path)
        else:
            self.plot = None
        self._recording = recording

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
                anomaly_score = self._final_bb.get_result(syscall)
                if anomaly_score != None:                
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording()            
        self.threshold = max_score
        self.performance.set_threshold(max_score)
        if self.plot is not None:
            self.plot.threshold = max_score
        print(f"threshold={max_score:.3f}".rjust(27))

    def detect_on_recording(self, recording: BaseRecording) -> Performance:
        performance = Performance()
        performance.set_threshold(self.threshold)
            # Wenn das eine Exploit-Aufnahme ist, dann schreibe den Zeit-Stempel auf
        if recording.metadata()["exploit"]:
            performance.set_exploit_time(recording.metadata()["time"]["exploit"][0]["absolute"])

        for syscall in recording.syscalls():
            anomaly_score = self._final_bb.get_result(syscall)
            if anomaly_score != None:
                performance.analyze_syscall(syscall, anomaly_score)

            # run end alarm once to ensure that last alarm gets saved
        if performance.alarms is not None:
            performance.alarms.end_alarm()
            
        return performance


    def do_detection(self):
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True
        """
        data = self._data_loader.test_data()
        description = 'anomaly detection'.rjust(27)

        # Paralleler shit hier

        results = process_map(self.verarbeiteRecording, data)
        pprint(results) # Ich gehe davon aus, dass ich eine Liste an Performance-Objekten erhalte.



        # TODO: Consectuvie Sachen im Nachhinein bestimmen
        # Dann reduce 
        
        #exit(1)
        

        # Hier das Alte aber funktionierende
        for recording in tqdm(data, description, unit=" recording"):
            #pprint(f"Current recording: {recording.name}")
            self.performance.new_recording(recording)
            if self.plot is not None:
                self.plot.new_recording(recording)
            for syscall in recording.syscalls():
                anomaly_score = self._final_bb.get_result(syscall)
                if anomaly_score != None:
                    self.performance.analyze_syscall(syscall, anomaly_score)
                    if self.plot is not None:
                        self.plot.add_to_plot_data(anomaly_score, syscall, self.performance.get_cfp_indices())

            self._data_preprocessor.new_recording()

            # run end alarm once to ensure that last alarm gets saved
            if self.performance.alarms is not None:
                self.performance.alarms.end_alarm()

    def draw_plot(self, filename=None):
        # plot data if wanted
        if self.plot is not None:
            self.plot.feed_figure()
            self.plot.show_plot(filename)
            
    def __repr__(self) -> str:
        return f"IDS-Object with Algorithm: {self._final_bb} and threshold: {self.threshold} and dataloader: {self._data_loader}"
           