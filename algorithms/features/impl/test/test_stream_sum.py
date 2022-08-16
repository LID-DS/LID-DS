import pytest

from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.stream_minimum import StreamMinimum
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.threadID import ThreadID

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

def test_stream_sum():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 1 apache2 0 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 0 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 0 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 2 apache2 0 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 2 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 2 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 XXX apache2 XXX gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 1 apache2 1 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_12 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 2 apache2 4 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_13 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_18 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_19 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_20 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_21 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_22 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

    sum = StreamSum(feature=ProcessID(), thread_aware=True, window_length=3)

    # we use _calculate insted of get_result here in order to re use the syscall_xx objects
    #                                         TID
    assert sum._calculate(syscall_1) == None  # 0
    assert sum._calculate(syscall_2) == None  # 0
    assert sum._calculate(syscall_3) == 3     # 0
    assert sum._calculate(syscall_4) == None  #   1
    assert sum._calculate(syscall_5) == None  #   1
    assert sum._calculate(syscall_6) == 4     # 0
    assert sum._calculate(syscall_7) == None  #     2
    assert sum._calculate(syscall_8) == 3     #   1
    assert sum._calculate(syscall_9) == None  #     2
    assert sum._calculate(syscall_1) == 4     # 0
    assert sum._calculate(syscall_1) == 4     # 0
    assert sum._calculate(syscall_1) == 3     # 0

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        assert sum.get_result(syscall_10) == "XXX"

    sum = StreamSum(feature=ProcessID(), thread_aware=False, window_length=3)
    #                                       TID 0 1 2 3 4
    assert sum._calculate(syscall_1) == None  # 0
    assert sum._calculate(syscall_2) == None  # 0
    assert sum._calculate(syscall_3) == 3     # 0
    assert sum._calculate(syscall_4) == 3     #   1
    assert sum._calculate(syscall_5) == 3     #   1
    assert sum._calculate(syscall_6) == 4     # 0
    assert sum._calculate(syscall_7) == 4     #     2
    assert sum._calculate(syscall_8) == 4     #   1
    assert sum._calculate(syscall_9) == 3     #     2
    assert sum._calculate(syscall_11) == 3    #   1
    assert sum._calculate(syscall_12) == 4    #         4
    assert sum._calculate(syscall_13) == 6    #       3

    tid = ThreadID()
    sum = StreamSum(feature=tid, thread_aware=False, window_length=4)

    assert sum._calculate(syscall_14) == None # 1
    assert sum._calculate(syscall_15) == None # 2
    assert sum._calculate(syscall_16) == None # 3
    assert sum._calculate(syscall_17) == 10   # 4
    assert sum._calculate(syscall_18) == 14   # 5
    assert sum._calculate(syscall_19) == 13   # 1
    assert sum._calculate(syscall_20) == 12   # 2
    assert sum._calculate(syscall_21) == 11   # 3
    assert sum._calculate(syscall_22) == 10   # 4
