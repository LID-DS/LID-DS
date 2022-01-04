from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall_2021 import Syscall2021


def test_syscall_name_extract():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")

    sn = SyscallName()
    feature_dict = {}
    sn.calculate(syscall_1, feature_dict)
    assert feature_dict[sn.get_id()] == 'open'
    sn.calculate(syscall_2, feature_dict)
    assert feature_dict[sn.get_id()] == 'open'
    sn.calculate(syscall_3, feature_dict)
    assert feature_dict[sn.get_id()] == 'getuid'
