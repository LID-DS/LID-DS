import pytest

from algorithms.features.stream_ngram_extractor import StreamNgramExtractor
from algorithms.features.threadID_extractor import ThreadIDExtractor
from algorithms.features.thread_change_flag import ThreadChangeFlag
from algorithms.features.syscall_name import SyscallName
from dataloader.syscall import Syscall


def test_thread_change_flag():
    # legit
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686304 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686305 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686304 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_10 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 hello < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscalls = [syscall_1,
                syscall_2,
                syscall_3,
                syscall_4,
                syscall_5,
                syscall_6,
                syscall_7,
                syscall_8,
                syscall_9,
                syscall_10]

    feature_list = [ThreadIDExtractor(), SyscallName()]

    n_gram_streamer = StreamNgramExtractor(
        feature_list=[SyscallName],
        thread_aware=True,
        ngram_length=3
    )

    thread_change_flag = ThreadChangeFlag(
        syscall_feature_list=[ThreadIDExtractor],
        stream_feature_list=[StreamNgramExtractor]
    )

    # SYSCALL 1
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_1)[0]] = feature.extract(syscall_1)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), None)

    # SYSCALL 2
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_2)[0]] = feature.extract(syscall_2)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), None)

    # SYSCALL 3
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_3)[0]] = feature.extract(syscall_3)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), ['open', 'close', 'poll', 0])

    # SYSCALL 4
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_4)[0]] = feature.extract(syscall_4)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), None)

    # SYSCALL 5
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_5)[0]] = feature.extract(syscall_5)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), None)

    # SYSCALL 6
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_6)[0]] = feature.extract(syscall_6)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), None)

    # SYSCALL 7
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_7)[0]] = feature.extract(syscall_7)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), ['close', 'poll', 'mmap', 0])

    # SYSCALL 8
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_8)[0]] = feature.extract(syscall_8)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), ['mmap', 'open', 'open', 1])

    # SYSCALL 9
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_9)[0]] = feature.extract(syscall_9)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), ['poll', 'mmap', 'close', 1])

    # SYSCALL 10
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_10)[0]] = feature.extract(syscall_10)[1]
    ngram = n_gram_streamer.extract(syscall_dict)
    stream_dict = {}
    # check if value is not None
    if ngram[1] is not None:
        stream_dict[ngram[0]] = ngram[1]
    feature = thread_change_flag.extract(syscall_dict, stream_dict)
    assert feature == (ThreadChangeFlag.get_id(), ['mmap', 'close', 'hello', 0])
