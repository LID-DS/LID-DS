from algorithms.features.impl.syscall_name import SyscallName

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def test_syscall_name_extract():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")

    syscall_4 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_5 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    sn = SyscallName()    
    assert sn.get_result(syscall_1) == 'open'
    assert sn.get_result(syscall_2) == 'open'
    assert sn.get_result(syscall_3) == 'getuid'
    assert sn.get_result(syscall_4) == 'write'
    assert sn.get_result(syscall_5) == 'write'
