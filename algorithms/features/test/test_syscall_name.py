from algorithms.features.syscall_name import SyscallName
from dataloader.syscall import Syscall


def test_syscall_name_extract():
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall("1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")

    sn = SyscallName()

    data = sn.extract(syscall_1)
    assert (data[1][0] == 'open')
    data = sn.extract(syscall_2)
    assert (data[1][0] == 'open')
    data = sn.extract(syscall_3)
    assert (data[1][0] == "getuid")
