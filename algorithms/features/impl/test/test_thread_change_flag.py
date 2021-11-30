import pytest

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall import Syscall


def helper(syscall, feature_list, ngram, tcf, cid):
    syscall_dict = {}
    for feature in feature_list:
        feature.extract(syscall, syscall_dict)
    ngram.extract(None, syscall_dict)
    tcf.extract(None, syscall_dict)
    return syscall_dict[cid]

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

    features = [ThreadID(), SyscallName()]

    ng = Ngram(
        feature_list=[SyscallName],
        thread_aware=True,
        ngram_length=3
    )

    tcf = ThreadChangeFlag()

    id = tcf.get_id()

    # SYSCALL 1
    assert helper(syscall[0], features, ng, tcf, id) == None

    # SYSCALL 2
    assert helper(syscall[1], features, ng, tcf, id) == None

    # SYSCALL 3
    assert helper(syscall[2], features, ng, tcf, id) == ['open', 'close', 'poll', 0]

    # SYSCALL 4
    assert helper(syscall[3], features, ng, tcf, id) == None

    # SYSCALL 5
    assert helper(syscall[4], features, ng, tcf, id) == None

    # SYSCALL 6
    assert helper(syscall[5], features, ng, tcf, id) == None

    # SYSCALL 7
    assert helper(syscall[6], features, ng, tcf, id) == ['close', 'poll', 'mmap', 0]

    # SYSCALL 8
    assert helper(syscall[7], features, ng, tcf, id) == ['mmap', 'open', 'open', 1]

    # SYSCALL 9
    assert helper(syscall[8], features, ng, tcf, id) == ['poll', 'mmap', 'close', 1]

    # SYSCALL 10
    assert helper(syscall[9], features, ng, tcf, id) == ['mmap', 'close', 'hello', 0]
