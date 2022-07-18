import pytest

from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.threadID import ThreadID

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

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

    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_18 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_19 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

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

    tid = ThreadID()
    avg = StreamAverage(feature=tid, thread_aware=False, window_length=2)
    assert avg._calculate(syscall_11) == None  #   1
    assert avg._calculate(syscall_12) == 3/2   #   2
    assert avg._calculate(syscall_13) == 5/2   #   3
    assert avg._calculate(syscall_14) == 7/2   #   4
    assert avg._calculate(syscall_15) == 9/2   #   5
    assert avg._calculate(syscall_16) == 6/2   #   1
    assert avg._calculate(syscall_17) == 3/2   #   2
    assert avg._calculate(syscall_18) == 5/2   #   3
    assert avg._calculate(syscall_19) == 7/2   #   4
