from algorithms.features.impl.syscalls_in_time_window import SyscallsInTimeWindow

from dataloader.syscall_2021 import Syscall2021 as Syscall
from dataloader.syscall_2019 import Syscall2019


def test_syscalls_in_time_window():
    syscall_1 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    syscall_2 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209048762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_3 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209049762064269 0 3686303 apache2 3686304 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_4 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209050762064269 0 3686303 apache2 3686304 open < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_5 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209051762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_6 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209052762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_7 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1000000001000000000 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_8 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1000000002000000000 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_9 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1000000003000000000 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_10 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         "1000000004000000000 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_11 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         "1000000005000000000 0 3686303 apache2 3686303 open < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_12 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         "1000000009000000000 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 1 > setsockopt')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:57.976999081 6 999 mysqld 1 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:58.977001060 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:59.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:16:00.977003699 6 999 mysqld 1 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_18 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:16:01.977004485 6 999 mysqld 1 < fcntl res=0(<f>/dev/null)')
    syscall_19 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:16:02.977105435 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_20 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:16:03.977105435 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_21 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:16:05.077105435 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_22 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:16:07.577105435 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    training_syscalls = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5, syscall_6]
    scitw = SyscallsInTimeWindow(window_length_in_s=3)

    for syscall in training_syscalls:
        scitw.train_on(syscall)
    scitw.fit()

    #SYSCALL 2021
    assert scitw._training_max == 2

    # first three return None because time difference < time window
    
    assert scitw.get_result(syscall_7) == None
    assert scitw.get_result(syscall_8) == None
    assert scitw.get_result(syscall_9) == None

    # 4 syscalls in window, 2 max in training: 4/2 = 2
    assert scitw.get_result(syscall_10) == 2
    assert scitw.get_result(syscall_11) == 2

    # syscall time difference to last one is 4s, only syscall in window is this one, leads to 1/2 = 0.5    
    assert scitw.get_result(syscall_12) == 0.5

    #SYSCALL 2019
    training_syscalls = [syscall_13, syscall_14,
                         syscall_15, syscall_16,
                         syscall_17, syscall_18]
    scitw = SyscallsInTimeWindow(window_length_in_s=2)
    for syscall in training_syscalls:
        scitw.train_on(syscall)
    scitw.fit()
    print('training done')
    print(scitw._training_max)

    assert scitw.get_result(syscall_17) == None
    assert scitw.get_result(syscall_18) == None
    assert scitw.get_result(syscall_19) == 2/2
    assert scitw.get_result(syscall_20) == 2/2
    assert scitw.get_result(syscall_21) == 2/2
    assert scitw.get_result(syscall_22) == 1/2
