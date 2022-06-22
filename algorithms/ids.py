from os import get_exec_path
from tqdm import tqdm
from algorithms.building_block import BuildingBlock
from pprint import pprint

from algorithms.alarms import Alarms
from algorithms.performance_measurement import Performance, PerformanceMeasurement
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from algorithms.data_preprocessor import DataPreprocessor
from dataloader.base_recording import BaseRecording

class SingleRecordingPerformance:
    
    def __init__(self, threshold: float, create_alarms: bool = False):
        self._treshold = threshold
        self._fp = 0
        self._tp = 0
        self._fn = 0
        self._tn = 0
        self._alarm_count = 0
        self._create_alarms = create_alarms
        
        self._current_exploit_time = None
        self._exploit_count = 0
        self._alarm = False
        
        # CFP things
        self._cfp_count_exploits = 0
        self._current_cfp_stream = 0
        self._current_cfp_stream_exploits = 0
        self._exploit_anomaly_score_count = 0
        self._first_syscall_of_cfp_list_exploits = []
        self._last_syscall_of_cfp_list_exploits = []
        self._cfp_counter_wait_exploits = False

        self._cfp_count_normal = 0
        self._current_cfp_stream_normal = 0
        self._normal_score_count = 0
        self._first_syscall_of_cfp_list_normal = []
        self._last_syscall_of_cfp_list_normal = []
        self._cfp_counter_wait_normal = False
        if self.create_alarms:
            self.alarms = Alarms()
        else:
            self.alarms = None
    
    
    def analyze_syscall(self, syscall, anomaly_score):
        pass
    
    
    def get_cfp_indices(self):
        pass
    





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
        self._create_alarms = create_alarms
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

    def do_detection(self):
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True
        """
        data = self._data_loader.test_data()
        description = 'anomaly detection'.rjust(27)

        # Paralleler shit hier
        for recording in tqdm(data, description, uni=" recording"): # Hier muss ganz sicher noch was anderes hin
            performance = Performance()
            performance.set_threshold(self.threshold)

            # Wenn das eine Exploit-Aufnahme ist, dann schreibe den Zeit-Stempel auf
            if recording.metadata()["exploit"]:
                performance.set_exploit_time(recording.metadata()["time"]["exploit"][0]["absolute"])


            # Jetzt nach Exploit-Time unterscheiden
            if performance.get_exploit_time() is not None:
                pass

            elif performance.get_exploit_time() is None:
                pass


        
        # Dann reduce 
        
        
        

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
            
   
    def process_recording(self, recording: BaseRecording) -> SingleRecordingPerformance:
        # New Recording - calls reinnehmen nachdem ich sie verstehe
        results = SingleRecordingPerformance(threshold=self.threshold, create_alarms=self._create_alarms)
        
        for syscall in recording:
            anomaly_score = self._final_bb.get_result(syscall)
            if anomaly_score != None:
                results.analyze_syscall(syscall, anomaly_score) 
                if self.plot is not None: 
                    self.plot.add_to_plot_data(anomaly_score, syscall, results.get_cfp_indices())
    
            
            self._data_preprocessor.new_recording() ############# Muss noch übersetzt werden TODO

            # run end alarm once to ensure that last alarm gets saved
            if results.alarms is not None:
                results.alarms.end_alarm()
    
    
        return results
    
    
    
    
