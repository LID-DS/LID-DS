class AnomalyScores:
    def __init__(self,
                 epoch,
                 anomaly_scores_train,
                 anomaly_scores_val,
                 anomaly_scores_before_exploit,
                 anomaly_scores_after_exploit,
                 anomaly_scores_normal,
                 anomaly_scores_val_exc_train,
                 anomaly_scores_before_exploit_exc_train,
                 anomaly_scores_after_exploit_exc_train,
                 anomaly_scores_normal_exc_train,
                 anomaly_scores_after_exploit_per_recording,
                 anomaly_scores_before_exploit_per_recording,
                 anomaly_scores_normal_per_recording
                 ):
        self.epoch = epoch
        self.train = anomaly_scores_train
        self.val = anomaly_scores_val
        self.before_exploit = anomaly_scores_before_exploit
        self.after_exploit = anomaly_scores_after_exploit
        self.normal = anomaly_scores_normal
        self.val_exc_train = anomaly_scores_val_exc_train
        self.before_exploit_exc_train = anomaly_scores_before_exploit_exc_train
        self.after_exploit_exc_train = anomaly_scores_after_exploit_exc_train
        self.normal_exc_train = anomaly_scores_normal_exc_train
        self.after_exploit_per_recording = anomaly_scores_after_exploit_per_recording
        self.before_exploit_per_recording = anomaly_scores_before_exploit_per_recording
        self.normal_per_recording = anomaly_scores_normal_per_recording
        self.threshold = max(anomaly_scores_val)
        self.threshold_train = max(anomaly_scores_train)
        self.threshold_before_exploit = max(anomaly_scores_before_exploit, default=0)
        self.threshold_after_exploit = max(anomaly_scores_after_exploit)
        self.threshold_normal = max(anomaly_scores_normal)
        self.threshold_val_exc_train = max(anomaly_scores_val_exc_train)
        self.has_detected = self.threshold < self.threshold_after_exploit
        self.true_anomal_ngs_count = 0
        self.detected = [score > self.threshold for score in anomaly_scores_after_exploit]
        self.has_false_positive = self.threshold_before_exploit > self.threshold or self.threshold_normal > self.threshold
        self.false_positives = [score > self.threshold for score in anomaly_scores_before_exploit] + \
                               [score > self.threshold for score in anomaly_scores_normal]

    def __str__(self):
        return f'AnomalyScores: epoch={self.epoch}, detected={self.has_detected}, false_positive={self.has_false_positive}, ' \
               f'threshold={self.threshold}, threshold_train={self.threshold_train}, dc={sum(self.detected)}, fpc={sum(self.false_positives)}'

    def __repr__(self):
        return str(self)
