import pytest

from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.stream_minimum import StreamMinimum
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021

def test_avg():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 1 apache2 1 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 2 apache2 2 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 2 apache2 2 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 2 apache2 2 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 7 apache2 1 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 4 apache2 1 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 3 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 XXX apache2 XXX gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    pid = ProcessID()
    avg = StreamAverage(feature=pid, thread_aware=True, window_length=3)
    #                                           PID  TID
    assert avg._calculate(syscall_1) == None  #   1    1
    assert avg._calculate(syscall_2) == None  #   1    1
    assert avg._calculate(syscall_3) == None  #   2    2
    assert avg._calculate(syscall_4) == 1     #   1    1
    assert avg._calculate(syscall_5) == None  #   2    2
    assert avg._calculate(syscall_6) == 2     #   2    2 
    assert avg._calculate(syscall_7) == 3     #   7    1
    assert avg._calculate(syscall_8) == 4     #   4    1
    assert avg._calculate(syscall_9) == None  #   1    3

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        assert avg._calculate(syscall_10) == "XXX"

    avg = StreamAverage(feature=pid, thread_aware=False, window_length=3)
    #                                           PID  TID
    assert avg._calculate(syscall_1) == None  #   1    1
    assert avg._calculate(syscall_2) == None  #   1    1
    assert avg._calculate(syscall_3) == 4/3   #   2    2
    assert avg._calculate(syscall_4) == 4/3   #   1    1
    assert avg._calculate(syscall_5) == 5/3   #   2    2
    assert avg._calculate(syscall_6) == 5/3   #   2    2 
    assert avg._calculate(syscall_7) == 11/3  #   7    1
    assert avg._calculate(syscall_8) == 13/3  #   4    1
    assert avg._calculate(syscall_9) == 12/3  #   1    3

