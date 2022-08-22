import pytest

from algorithms.features.impl.stream_product import StreamProduct
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.threadID import ThreadID

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def test_multiply():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 10 apache2 10 write < res=10 fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=10 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 11 apache2 11 write < res=11 fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=11 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 write < res=1 fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=1 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 0.1 apache2 2 write < res=0.1fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0.1 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 0 apache2 0 write < res=0 fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_6 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_7 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_8 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt')
    syscall_9 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_10 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_13 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

    tid = ThreadID()
    product = StreamProduct(feature=tid, thread_aware=False, window_length=3)

    # use _calculate instead of get_result to re use syscalls here

    assert product._calculate(syscall_1) == None  # 10
    assert product._calculate(syscall_2) == None  # 11
    assert product._calculate(syscall_3) == 110 # 1
    assert product._calculate(syscall_4) == 22  # 2
    assert product._calculate(syscall_5) == 0  # 0
    assert product._calculate(syscall_1) == 0  # 10
    assert product._calculate(syscall_1) == 0  # 10
    assert product._calculate(syscall_1) == 1000  # 10
    assert product._calculate(syscall_2) == 1100  # 11

    # 2019 Syscall
    assert product._calculate(syscall_6) == 110 # 1
    assert product._calculate(syscall_7) == 22 # 2
    assert product._calculate(syscall_8) == 6    # 3
    assert product._calculate(syscall_9) == 24   # 4
    assert product._calculate(syscall_10) == 60  # 5
    assert product._calculate(syscall_11) == 20  # 1
    assert product._calculate(syscall_12) == 10  # 2
    assert product._calculate(syscall_13) == 6  # 3
    assert product._calculate(syscall_14) == 24  # 4
