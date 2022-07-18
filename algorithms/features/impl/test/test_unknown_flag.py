from algorithms.features.impl.unknown_flags import UnknownFlags

from dataloader.syscall_2019 import Syscall2019
from dataloader.syscall_2021 import Syscall2021


def test_unknown_flag():
    syscall_1 = Syscall2021("",
        "1631209047761484608 0 10 apache2 10 open < flags=test fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max mode=0 dev=200024")
    syscall_2 = Syscall2021("",
        "1631209047762064269 0 11 apache2 11 open < flags=test2 fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group mode=0 dev=200021 ")
    syscall_3 = Syscall2021("",
        "1631209047762064269 0 12 apache2 12 poll < flags=test3 fd=9(<f>/etc/group) name=/etc/group mode=0 dev=200021 ")
    syscall_4 = Syscall2021("",
        "1631209047762064269 0 13 apache2 13 open < flags=test in_fd=9(<f>/etc/test) name=/etc/group mode=0 dev=200021 ")
    syscall_5 = Syscall2021("",
        "1631209047762064269 0 12 apache2 12 open < flags=test4 out_fd=9(<f>/etc/password) name=/etc/group mode=0 dev=200021 ")

    syscall_6 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11 flags=test5')
    syscall_7 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:.... flags=test6')
    syscall_8 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt flags=test6')
    syscall_9 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16 flags=test7')
    syscall_10 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4 flags=test8')
    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data= flags=test8')
    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL) flags=test10')
    syscall_13 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null) flags=test11')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4 flags=test6')

    f = UnknownFlags()

    f.train_on(syscall_1)
    assert f._flag_dict == {'open': ['test']}

    f.train_on(syscall_2)
    assert f._flag_dict == {'open': ['test', 'test2']}

    f.train_on(syscall_3)
    assert f._flag_dict == {'open': ['test', 'test2'],
                            'poll': ['test3']}
    
    assert f._calculate(syscall_4) == 0
    assert f._calculate(syscall_5) == 1

    f = UnknownFlags()
    f.train_on(syscall_6)
    assert f._flag_dict == {'write': ['test5']}
    f.train_on(syscall_7)
    assert f._flag_dict == {'write': ['test5', 'test6']}
    f.train_on(syscall_8)
    assert f._flag_dict == {'setsockopt': ['test6'],
                            'write': ['test5', 'test6']}
    f.train_on(syscall_9)
    assert f._flag_dict == {'setsockopt': ['test6', 'test7'], 
                            'write': ['test5', 'test6']}
    f.train_on(syscall_10)
    assert f._flag_dict == {'setsockopt': ['test6', 'test7'],
                            'write': ['test5', 'test6'],
                            'read': ['test8']}
    assert f._calculate(syscall_11) == 0
    assert f._calculate(syscall_12) == 1
    assert f._calculate(syscall_13) == 1
    assert f._calculate(syscall_14) == 0
