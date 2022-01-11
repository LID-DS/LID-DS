import pytest

from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.stream_minimum import StreamMinimum
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def eva(syscall, tid, sum):
    syscall_dict = {}
    ThreadID().calculate(syscall,syscall_dict)
    tid.calculate(syscall, syscall_dict)
    sum.calculate(syscall, syscall_dict)
    return syscall_dict[sum.get_id()]


def test_sum():
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
    sum = StreamSum(feature=pid, thread_aware=True, window_length=3)

    assert eva(syscall_1, pid, sum) == 10  # 10
    assert eva(syscall_2, pid, sum) == 11  # 11
    assert eva(syscall_3, pid, sum) == 12  # 12
    assert eva(syscall_4, pid, sum) == 13  # 13
    assert eva(syscall_5, pid, sum) == 24  # 12
    assert eva(syscall_6, pid, sum) == 9  # 9
    assert eva(syscall_7, pid, sum) == 8  # 8
    assert eva(syscall_8, pid, sum) == 18  # 9
    assert eva(syscall_9, pid, sum) == 6  # 6
    assert eva(syscall_1, pid, sum) == 20  # 10
    assert eva(syscall_1, pid, sum) == 30  # 10
    assert eva(syscall_1, pid, sum) == 30  # 10

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        assert eva(syscall_10, pid, sum) == "XXX"

    sum = StreamSum(feature=pid, thread_aware=False, window_length=3)
    assert eva(syscall_1, pid, sum) == 10  # 10
    assert eva(syscall_2, pid, sum) == 21  # 11
    assert eva(syscall_3, pid, sum) == 33  # 12
    assert eva(syscall_4, pid, sum) == 36  # 13
    assert eva(syscall_5, pid, sum) == 37  # 12
    assert eva(syscall_6, pid, sum) == 34  # 9
    assert eva(syscall_7, pid, sum) == 29  # 8
    assert eva(syscall_8, pid, sum) == 26  # 9
    assert eva(syscall_9, pid, sum) == 23  # 6

    assert eva(syscall_11, pid, sum) == 26  # 11
    assert eva(syscall_12, pid, sum) == 29  # 12
    assert eva(syscall_13, pid, sum) == 36  # 13
