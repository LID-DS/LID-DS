import pytest

from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def test_thread_id():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 717 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # str instead of int
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 3686303 apache2 gibberish getuid < uid=33(www-data) ")

    tid = ThreadID()

    features = {}

    tid.calculate(syscall_1, features)
    assert features[tid.get_id()] == 3686302
    tid.calculate(syscall_2, features)
    assert features[tid.get_id()] == 717
    with pytest.raises(ValueError):
        tid.calculate(syscall_3, features)
