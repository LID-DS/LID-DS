import pytest

from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.stream_product import StreamProduct
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def eva(syscall, bb1, bb2):
    syscall_dict = {}    
    bb1.calculate(syscall, syscall_dict)
    bb2.calculate(syscall, syscall_dict)
    return syscall_dict[bb2.get_id()]


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


    tid = ThreadID()
    product = StreamProduct(feature=tid, thread_aware=False, window_length=3)

    assert eva(syscall_1, tid, product) == 10  # 10
    assert eva(syscall_2, tid, product) == 110  # 11
    assert eva(syscall_3, tid, product) == 110 # 1
    assert eva(syscall_4, tid, product) == 22  # 2
    assert eva(syscall_5, tid, product) == 0  # 0
    assert eva(syscall_1, tid, product) == 0  # 10
    assert eva(syscall_1, tid, product) == 0  # 10
    assert eva(syscall_1, tid, product) == 1000  # 10
    assert eva(syscall_2, tid, product) == 1100  # 11
