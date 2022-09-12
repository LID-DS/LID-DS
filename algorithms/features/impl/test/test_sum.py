import pytest

from algorithms.features.impl.sum import Sum
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.one_hot_encoding import OneHotEncoding

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def test_sum():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 10 apache2 1 open < res=10 fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=10 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 11 apache2 2 read < res=11 fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=11 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 3 write < res=1 fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=1 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 0.1 apache2 1 write < res=0.1fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0.1 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 0 apache2 1 write < res=0 fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

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

    train = [syscall_1, syscall_2,
             syscall_3, syscall_4,
             syscall_5]
    val = [syscall_1, syscall_2,
           syscall_3, syscall_4,
           syscall_5]
    

    ohe = OneHotEncoding(SyscallName())
    tid = ThreadID()
    concat = Concat([tid,tid,tid,tid])
    sum = Sum([ohe,concat])

    for sc in train:
        ohe.train_on(sc)
    ohe.fit()

    for sc in val:
        sum.val_on(sc)
    #                                              OHE  CON
    assert sum._calculate(syscall_1) == (2,1,1,1)  # 1000  1111
    assert sum._calculate(syscall_2) == (2,3,2,2)  # 0100  2222
    assert sum._calculate(syscall_3) == (3,3,4,3)  # 0010  3333
    assert sum._calculate(syscall_4) == (1,1,2,1)  # 0010  1111
    assert sum._calculate(syscall_5) == (1,1,2,1)  # 0010  1111

    train = [syscall_6, syscall_7,
             syscall_8, syscall_9,
             syscall_10]
    val = [syscall_6, syscall_7,
           syscall_8, syscall_9,
           syscall_10]
    

    ohe = OneHotEncoding(SyscallName())
    tid = ThreadID()
    concat = Concat([tid,tid,tid,tid])
    sum = Sum([ohe,concat])

    for sc in train:
        ohe.train_on(sc)
    ohe.fit()

    for sc in val:
        sum.val_on(sc)

    #                                              OHE CON
    assert sum._calculate(syscall_7) == (3,2,2,2)  # 1000 2222
    assert sum._calculate(syscall_8) == (3,4,3,3)  # 0100 3333 
    assert sum._calculate(syscall_9) == (4,5,4,4)  # 0100 4444 
    assert sum._calculate(syscall_10) == (5,5,6,5) # 0010 5555 
