from algorithms.features.impl.path_evilness import PathEvilness
from dataloader.syscall_2021 import Syscall2021


def helper(syscall, path_evil):
    tmp_dict = {}
    path_evil.calculate(syscall, tmp_dict)
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

    # only valid training data
    training_syscalls_round_1 = [syscall_1, syscall_2, syscall_3, syscall_4]
    pe1 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')
    """
    
    scenario path is a mock that is only used to name the tree model
    
    path is overwritten to algorithms/Models because we assume pytest runs from the main LID-DS folder
    
    """

    feature_dict = {}
    for syscall in training_syscalls_round_1:
        pe1.train_on(syscall, feature_dict)
    pe1.fit()

    # deviation at depth 2
    assert helper(syscall_5, pe1) == 0.5

    # deviation at depth 4
    assert helper(syscall_6, pe1) == 0.25

    # invalid fd
    assert helper(syscall_9, pe1) == 0

    # fd is ip
    assert helper(syscall_11, pe1) == 0

    # filepath is known
    assert helper(syscall_1, pe1) == 0

    # also invalid training data
    training_syscalls_round_2 = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_7, syscall_8, syscall_10]
    pe2 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')

    feature_dict = {}
    for syscall in training_syscalls_round_2:
        pe2.train_on(syscall, feature_dict)

    # deviation at depth 2
    assert helper(syscall_5, pe2) == 0.5

    # deviation at depth 4
    assert helper(syscall_6, pe2) == 0.25

    # invalid fd
    assert helper(syscall_9, pe2) == 0

    # fd is ip
    assert helper(syscall_11, pe2) == 0

    # filepath is known
    assert helper(syscall_1, pe2) == 0
