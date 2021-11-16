import pytest

from algorithms.features.ngram_plus_next_syscall import NgramPlusNextSyscall
from algorithms.features.threadID import ThreadID
from algorithms.features.int_embedding import IntEmbedding
from algorithms.features.syscall_name import SyscallName
from dataloader.syscall import Syscall


def test_ngram_plus_next_syscall():
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
        "1631209047762064269 0 3686303 apache2 3686304 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall(
        "1631209047762064269 0 3686303 apache2 gibberish gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_11 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 hello < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_12 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 bye < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")


    syscalls = [syscall_1,
                syscall_2,
                syscall_3,
                syscall_4,
                syscall_5,
                syscall_6,
                syscall_7,
                syscall_8,
                syscall_9,
                syscall_10,
                syscall_11]

    feature_list = [ThreadID(), SyscallName(), IntEmbedding()]

    for syscall in syscalls:
        for feature in feature_list:
            feature.train_on(syscall)
    for feature in feature_list:
        feature.fit()

    n_gram_streamer = NgramPlusNextSyscall(
        feature_list=[SyscallName],
        thread_aware=True,
        ngram_length=3
    )

    # SYSCALL 1
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_1)[0]] = feature.extract(syscall_1)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 2
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_2)[0]] = feature.extract(syscall_2)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 3
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_3)[0]] = feature.extract(syscall_3)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 4
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_4)[0]] = feature.extract(syscall_4)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 5
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_5)[0]] = feature.extract(syscall_5)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 6
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_6)[0]] = feature.extract(syscall_6)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 7
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_7)[0]] = feature.extract(syscall_7)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), [4, 'open', 'close', 'poll'])

    # SYSCALL 8
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_8)[0]] = feature.extract(syscall_8)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), None)

    # SYSCALL 9
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_9)[0]] = feature.extract(syscall_9)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), [2, 'mmap', 'open', 'open'])

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        syscall_dict = {}
        for feature in feature_list:
            syscall_dict[feature.extract(syscall_10)[0]] = feature.extract(syscall_10)[1]
        n_gram_streamer.extract(syscall_dict)

    # SYSCALL 11
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_11)[0]] = feature.extract(syscall_11)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), [7, 'close', 'poll', 'mmap'])

    # SYSCALL 12 not in training data
    syscall_dict = {}
    for feature in feature_list:
        syscall_dict[feature.extract(syscall_12)[0]] = feature.extract(syscall_12)[1]
    n_gram = n_gram_streamer.extract(syscall_dict)
    assert n_gram == (NgramPlusNextSyscall.get_id(), [0, 'poll', 'mmap', 'hello'])
