from typing import Union, Type, Generator

from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
from algorithms.features.base_stream_feature_extractor import BaseStreamFeatureExtractor
from dataloader.data_loader import DataLoader
from dataloader.syscall import Syscall
import datetime


class IDS:
    def __init__(self,
                 syscall_feature_list: list,
                 stream_feature_list: list,
                 data_loader: Union[DataLoader, DataLoader],
                 decision_engine: BaseDecisionEngine):
        self._data_loader = data_loader
        self._decision_engine = decision_engine
        self._syscall_feature_list = syscall_feature_list
        self._stream_feature_list = stream_feature_list
        self._prepare_and_build_features()
        self._threshold = 0.0
        self._performance_values = {}
        self._alarm = False

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
                                  description: str = "") -> Generator[tuple, None, None]:
        """
        generator: given a list of recordings (like dataloader.training()) generates all feature vectors

        yields feature vector, boolean for exploit, absolute time of exploit

        """

        first_syscall_time = None

        for recording in tqdm(data, description, unit=" recording"):

            if self._alarm is not False:
                self._alarm = False
            if recording.metadata()["exploit"] is True:
                if first_syscall_time is None:
                    print("hier")
                    exploit_time = datetime.timedelta(seconds=recording.metadata()["time"]["exploit"][0]["relative"])

                elif first_syscall_time:
                    exploit_time = first_syscall_time + datetime.timedelta(seconds=recording.metadata()["time"]["exploit"][0]["relative"])
            else:
                exploit_time = None

            for syscall in recording.syscalls():
                if first_syscall_time is None:
                    first_syscall_time = Syscall.timestamp_datetime(syscall)
                syscall_time = Syscall.timestamp_datetime(syscall)
                #print(f"sct = {syscall_time},"
                #      f"ext = {exploit_time}")
                feature_dict = self._extract_features_from_syscall(syscall)
                feature_vector = self._extract_features_from_stream(feature_dict)
                if len(feature_vector) > 0:
                    yield feature_vector, exploit_time, syscall_time
            stream_feature: BaseStreamFeatureExtractor  # type hint
            for stream_feature in self._stream_feature_list:
                stream_feature.new_recording()
            self._decision_engine.new_recording()

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
            for stream_feature in self._stream_feature_list:
                stream_feature.new_recording()

        # fit streaming features
        for stream_feature in tqdm(self._stream_feature_list, "fitting features 2/2".rjust(25), unit=" features"):
            stream_feature.fit()

    def train_decision_engine(self):
        # train of DE
        for feature_vector, _, _ in self._generate_feature_vectors(self._data_loader.training_data(), "train DE".rjust(25)):
            self._decision_engine.train_on(feature_vector)
        self._decision_engine.fit()

    def determine_threshold(self):
        max_score = 0.0
        for feature_vector, _, _ in self._generate_feature_vectors(self._data_loader.validation_data(),
                                                             "determine threshold".rjust(25)):
            anomaly_score = self._decision_engine.predict(feature_vector)
            if anomaly_score > max_score:
                max_score = anomaly_score
        self._threshold = max_score

    def do_detection(self):
        """
        detects: false positives, true positives, true negatives, false, negatives, consecutive false alarms
                 from feature_vectors and metadata

        returns: counts of fp, tp, tn, fn, cfa as int, alarm

        """
        fp = 0
        tp = 0
        tn = 0
        fn = 0
        cfa_stream = 0
        alarm_count = 0
        cfa_count = 0

        for feature_vector, exploit_time, syscall_time in self._generate_feature_vectors(self._data_loader.test_data(),
                                                             "anomaly detection".rjust(25)):
            anomaly_score = self._decision_engine.predict(feature_vector)

            if anomaly_score > self._threshold:
                if exploit_time is not None:
                    if exploit_time > syscall_time:
                        fp += 1
                        cfa_stream += 1
                    elif exploit_time < syscall_time and self._alarm is False:
                        tp += 1
                        alarm_count += 1
                        self._alarm = True
                    elif exploit_time < syscall_time and self._alarm is True:
                        tp += 1
                else:
                    fp += 1

            if anomaly_score < self._threshold:
                if exploit_time is not None:
                    if cfa_stream > 0:
                        cfa_stream = 0
                        cfa_count += 1

                    if exploit_time > syscall_time:
                        tn += 1
                    elif exploit_time < syscall_time:
                        fn += 1
                    else:
                         tn += 1

        re = tp/(tp+fn)
        pr = tp/(tp+fp)

        self._performance_values = {"false positives": fp,
                                    "true positives": tp,
                                    "true negatives": tn,
                                    "false negatives": fn,
                                    "Alarm?": alarm_count,
                                    "consecutive false alarms": cfa_count,
                                    "Recall": re,
                                    "Precision": pr,
                                    "F1": 2*((pr*re)/(pr+re))}


    def get_performance(self):

        """
        returns dict with performance values
        """

        return self._performance_values
