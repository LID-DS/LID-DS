from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag

from dataloader.syscall_2021 import Syscall2021 as Syscall
from dataloader.syscall_2019 import Syscall2019


def test_thread_change_flag():
    # legit
    syscall_1 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686304 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686305 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686304 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_10 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         "1631209047762064269 0 3686303 apache2 3686303 hello < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 1 < write res=11 data=......:....')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 2 > setsockopt')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 2 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 2 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 1 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_18 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 1 < fcntl res=0(<f>/dev/null)')
    syscall_19 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

    ng = Ngram(
        feature_list=[SyscallName()],
        thread_aware=True,
        ngram_length=3
    )

    tcf = ThreadChangeFlag(ng)

    # SYSCALL 2021
    assert tcf.get_result(syscall_1) == None
    assert tcf.get_result(syscall_2) == None
    assert tcf.get_result(syscall_3) == 1
    assert tcf.get_result(syscall_4) == None
    assert tcf.get_result(syscall_5) == None
    assert tcf.get_result(syscall_6) == None
    assert tcf.get_result(syscall_7) == 0
    assert tcf.get_result(syscall_8) == 1
    assert tcf.get_result(syscall_9) == 1
    assert tcf.get_result(syscall_10) == 0

    # SYSCALL 2019
    assert tcf.get_result(syscall_11) == None
    assert tcf.get_result(syscall_12) == None
    assert tcf.get_result(syscall_13) == None
    assert tcf.get_result(syscall_14) == None
    assert tcf.get_result(syscall_15) == 1
    assert tcf.get_result(syscall_16) == 1
    assert tcf.get_result(syscall_17) == 0
    assert tcf.get_result(syscall_18) == 0
    assert tcf.get_result(syscall_19) == 0
