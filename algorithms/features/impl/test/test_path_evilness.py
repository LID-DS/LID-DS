from algorithms.features.impl.path_evilness import PathEvilness

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def helper(syscall, path_evil):
    tmp_dict = {}
    path_evil._calculate(syscall, tmp_dict)
    return tmp_dict[path_evil.get_id()]


def test_path_evilness():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit with in_fd
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit with out_fd
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no fd
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # invalid fd
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # invalid fd
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # valid fd but ip instead of file
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # valid fd but ip instead of file
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 3686303 open < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=9(<f>/proc/sys/kernel/normal) size=11')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt fd=9(<f>/proc/sys/kernel/normal)')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=9(<f>/proc/sys/kernel/normal)')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_18 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=9(<f>/proc/sys/kernel/unnormal)')
    syscall_19 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_20 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<f>/etc/passwd) size=4')

    # only valid training data
    training_syscalls_round_1 = [syscall_1, syscall_2, syscall_3, syscall_4]
    pe1 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models', force_retrain=True)
    """
    
    scenario path is a mock that is only used to name the tree model
    
    path is overwritten to algorithms/Models because we assume pytest runs from the main LID-DS folder
    
    """

    for syscall in training_syscalls_round_1:
        pe1.train_on(syscall)
    pe1.fit()

    # deviation at depth 2
    assert pe1.get_result(syscall_5) == 0.5

    # deviation at depth 4
    assert pe1.get_result(syscall_6)== 0.25

    # invalid fd
    assert pe1.get_result(syscall_9) == 0

    # fd is ip
    assert pe1.get_result(syscall_11) == 0

    # filepath is known
    assert pe1.get_result(syscall_1) == 0

    # also invalid training data
    training_syscalls_round_2 = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_7, syscall_8, syscall_10]
    pe2 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')

    for syscall in training_syscalls_round_2:
        pe2.train_on(syscall)
    pe2.fit()

    # deviation at depth 2
    assert pe2.get_result(syscall_5) == 0.5

    # deviation at depth 4
    assert pe2.get_result(syscall_6) == 0.25

    # invalid fd
    assert pe2.get_result(syscall_9) == 0

    # fd is ip
    assert pe2.get_result(syscall_11) == 0

    # filepath is known
    assert pe2.get_result(syscall_1) == 0

    # 2019 Syscall

    train_syscalls_2019 = [syscall_12, syscall_13,
                           syscall_14, syscall_15]

    pe3 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models', force_retrain=True)

    print(pe3._file_tree)
    for syscall in train_syscalls_2019:
        pe3.train_on(syscall)
    pe3.fit()

    print(pe3._file_tree)
    # filepath is known
    assert pe3.get_result(syscall_16) == 0

    # no filepath 
    assert pe3.get_result(syscall_17) == 0

    # deviation in depth 4 
    assert pe3.get_result(syscall_18) == 0.25

    # no filepath
    assert pe3.get_result(syscall_19) == 0

    # deviation in depth 1 
    assert pe3.get_result(syscall_20) == 1
