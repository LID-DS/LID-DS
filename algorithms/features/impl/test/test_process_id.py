import pytest

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

from algorithms.features.impl.processID import ProcessID


def test_process_id():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 10 apache2 10 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 11 apache2 11 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 12 apache2 12 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_4 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "2569 00:10:50.488781617 2 999 mysqld 22545 < write res=78 data=J....5.5.23....hJyAy_PR...................*yE-M}Q\Z0|E.mysql_native_password.")
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 123123 apache2 9 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    pid = ProcessID()

    assert pid.get_result(syscall_1) == 10       # 10
    assert pid.get_result(syscall_2) == 11       # 11
    assert pid.get_result(syscall_3) == 12       # 12
    assert pid.get_result(syscall_4) is None     # 2019 Syscall does not include pid
    assert pid.get_result(syscall_5) == 3686302  # 3686302
    assert pid.get_result(syscall_6) == 123123   # 123123
