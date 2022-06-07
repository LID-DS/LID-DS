from dataloader.syscall_2021 import Syscall2021

from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.int_embedding import IntEmbedding


def test_int_embedding():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 4686302 apache2 3686302 unknown < uid=33(www-data) ")

    si = IntEmbedding()
    # trianing
    si.train_on(syscall_1)
    si.train_on(syscall_2)
    si.train_on(syscall_3)
    si.fit()

    # detection
    assert si._calculate(syscall_1) == 1
    assert si._calculate(syscall_2) == 1
    assert si._calculate(syscall_3) == 2
    assert si._calculate(syscall_4) == 0

    pid = ProcessID()
    si = IntEmbedding(building_block=pid)
    si._syscall_dict = {}
    si.train_on(syscall_1)
    si.train_on(syscall_2)
    si.train_on(syscall_3)

    assert si._calculate(syscall_1) == 1
    assert si._calculate(syscall_2) == 2
    assert si._calculate(syscall_3) == 1
    assert si._calculate(syscall_4) == 0
