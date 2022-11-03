"""
Example execution of LIDS Framework
"""
from dataloader.recording_2019 import Recording2019
from dataloader.direction import Direction

from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.ngram import Ngram

import timeit


if __name__ == '__main__':

    THREAD_AWARE = True
    WINDOW_LENGTH = 500
    NGRAM_LENGTH = 5

    start = timeit.default_timer()

    train_recording = Recording2019(["","train", "False", "0", "0","-1"], "../../../bitAggregat/minimal-stide-examples/Data/", Direction.BOTH)
    val_recording = Recording2019(["","val", "False", "0", "0","-1"], "../../../bitAggregat/minimal-stide-examples/Data/", Direction.BOTH)
    test_recording = Recording2019(["","test", "False", "0", "0","-1"], "../../../bitAggregat/minimal-stide-examples/Data/", Direction.BOTH)

    recording = timeit.default_timer()

    int_embedding = IntEmbedding()
    print("Start training\n")
    ngram = Ngram([int_embedding], THREAD_AWARE, NGRAM_LENGTH)
    stide = Stide(ngram)
    stream_sum = StreamSum(stide, False, WINDOW_LENGTH, False)
    max_score = MaxScoreThreshold(stream_sum)

    train_data = train_recording.syscalls()
    for syscall in train_data:
        int_embedding.train_on(syscall)
        ngram.train_on(syscall)
        stide.train_on(syscall)
    stide.fit()

    training = timeit.default_timer()
    ngram.new_recording()
    stide.new_recording()
    stream_sum.new_recording()
    for syscall in val_recording.syscalls():
        max_score.val_on(syscall)
    validation = timeit.default_timer()
    ngram.new_recording()
    stide.new_recording()
    stream_sum.new_recording()

    alarm_count = 0
    for syscall in test_recording.syscalls():
        alarm = max_score.get_result(syscall) 
        if alarm:
            alarm_count += 1
    detection = timeit.default_timer()
    print(f"Full: {detection - start}\nRec: {recording - start}\nTrain: {training - recording}\n"
            f"Val: {validation - training}\nTest: {detection - validation}")

    print(f"Threshold: {max_score._threshold}")
    print(f"Alarms: {alarm_count}")
