import pytest

from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.stream_minimum import StreamMinimum
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def eva(syscall, tid, avg):
    feature_dict = {}
    ThreadID().calculate(syscall, feature_dict)
    tid.calculate(syscall, feature_dict)
    avg._sum.calculate(syscall, feature_dict)
    avg.calculate(syscall, feature_dict)
    return feature_dict[avg.get_id()]


def test_avg():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 10 apache2 10 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 11 apache2 11 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 12 apache2 12 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 13 apache2 13 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 12 apache2 12 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 9 apache2 9 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 8 apache2 8 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 9 apache2 9 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 6 apache2 6 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 XXX apache2 XXX gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 11 apache2 10 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_12 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 12 apache2 10 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_13 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 13 apache2 10 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    pid = ProcessID()
    avg = StreamAverage(feature=pid, thread_aware=True, window_length=3)

    assert eva(syscall_1, pid, avg) == 10 / 3  # 10
    assert eva(syscall_2, pid, avg) == 11 / 3  # 11
    assert eva(syscall_3, pid, avg) == 12 / 3  # 12
    assert eva(syscall_4, pid, avg) == 13 / 3  # 13
    assert eva(syscall_5, pid, avg) == 24 / 3  # 12
    assert eva(syscall_6, pid, avg) == 9 / 3  # 9
    assert eva(syscall_7, pid, avg) == 8 / 3  # 8
    assert eva(syscall_8, pid, avg) == 18 / 3  # 9
    assert eva(syscall_9, pid, avg) == 6 / 3  # 6
    assert eva(syscall_1, pid, avg) == 20 / 3  # 10
    assert eva(syscall_1, pid, avg) == 30 / 3  # 10
    assert eva(syscall_1, pid, avg) == 30 / 3  # 10

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        assert eva(syscall_10, pid, avg) == "XXX"

    avg = StreamAverage(feature=pid, thread_aware=False, window_length=3)
    assert eva(syscall_1, pid, avg) == 10 / 3  # 10
    assert eva(syscall_2, pid, avg) == 21 / 3  # 11
    assert eva(syscall_3, pid, avg) == 33 / 3  # 12
    assert eva(syscall_4, pid, avg) == 36 / 3  # 13
    assert eva(syscall_5, pid, avg) == 37 / 3  # 12
    assert eva(syscall_6, pid, avg) == 34 / 3  # 9
    assert eva(syscall_7, pid, avg) == 29 / 3  # 8
    assert eva(syscall_8, pid, avg) == 26 / 3  # 9
    assert eva(syscall_9, pid, avg) == 23 / 3  # 6

    assert eva(syscall_11, pid, avg) == 26 / 3  # 11
    assert eva(syscall_12, pid, avg) == 29 / 3  # 12
    assert eva(syscall_13, pid, avg) == 36 / 3  # 13
