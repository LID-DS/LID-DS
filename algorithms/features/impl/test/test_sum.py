import pytest

from algorithms.features.impl.sum import Sum
from algorithms.features.impl.concat import Concat
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


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

    train = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5]
    val = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5]
    

    ohe = OneHotEncoding(SyscallName())
    tid = ThreadID()
    concat = Concat([tid,tid,tid])
    sum = Sum([ohe,concat])

    for sc in train:
        ohe.train_on(sc)
    ohe.fit()

    for sc in val:
        sum.val_on(sc)
    #                                              OHE  CON
    assert sum._calculate(syscall_1) == (2,1,1)  # 100  111
    assert sum._calculate(syscall_2) == (2,3,2)  # 010  222
    assert sum._calculate(syscall_3) == (3,3,4)  # 001  333
    assert sum._calculate(syscall_4) == (1,1,2)  # 001  111
    assert sum._calculate(syscall_5) == (1,1,2)  # 001  111
