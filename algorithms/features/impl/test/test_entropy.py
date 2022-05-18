import pytest

from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.entropy import Entropy

from dataloader.syscall_2021 import Syscall2021

def test_entropy():
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
                            "1631209047762064269 0 113 apache2 13 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 123 apache2 12 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 123123 apache2 9 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")


    pid = ProcessID()
    ent = Entropy(feature=pid)

    assert ent._calculate(syscall_1) == 1  # 10
    assert ent._calculate(syscall_2) == 0  # 11
    assert ent._calculate(syscall_3) == 1  # 12
    assert round(ent._calculate(syscall_4),1) == 0.9  # 113
    assert round(ent._calculate(syscall_5),1) == 1.6  # 123
    assert round(ent._calculate(syscall_6),1) == 1.6  # 123123

    name = SyscallName()
    ent = Entropy(feature=name)

    assert ent._calculate(syscall_1) == 2       # open
    assert round(ent._calculate(syscall_2),2) == 2.32    # close
    assert ent._calculate(syscall_3) == 1.5     # poll

