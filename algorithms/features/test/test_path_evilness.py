from algorithms.features.path_evilness import PathEvilness
from dataloader.syscall import Syscall


def test_path_evilness():
    # legit
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit with in_fd
    syscall_4 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit with out_fd
    syscall_5 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no fd
    syscall_7 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # invalid fd
    syscall_8 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # invalid fd
    syscall_9 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # valid fd but ip instead of file
    syscall_10 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # valid fd but ip instead of file
    syscall_11 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")


    # only valid training data
    training_syscalls_round_1 = [syscall_1, syscall_2, syscall_3, syscall_4]
    extractor_round_1 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')
    """
    
    scenario path is a mock that is only used to name the tree model
    
    path is overwritten to algorithms/Models because we assume pytest runs from the main LID-DS folder
    
    """

    for syscall in training_syscalls_round_1:
        extractor_round_1.train_on(syscall)

    extractor_round_1.fit()

    # deviation at depth 2
    evilness = extractor_round_1.extract(syscall_5)
    assert evilness == (PathEvilness.get_id(), 0.5)

    # deviation at depth 4
    evilness = extractor_round_1.extract(syscall_6)
    assert evilness == (PathEvilness.get_id(), 0.25)

    # invalid fd
    evilness = extractor_round_1.extract(syscall_9)
    assert evilness == (PathEvilness.get_id(), 0)

    # fd is ip
    evilness = extractor_round_1.extract(syscall_11)
    assert evilness == (PathEvilness.get_id(), 0)

    # filepath is known
    evilness = extractor_round_1.extract(syscall_1)
    assert evilness == (PathEvilness.get_id(), 0)

    # also invalid training data
    training_syscalls_round_2 = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_7, syscall_8, syscall_10]
    extractor_round_2 = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')

    for syscall in training_syscalls_round_2:
        extractor_round_2.train_on(syscall)

    # deviation at depth 2
    evilness = extractor_round_2.extract(syscall_5)
    assert evilness == (PathEvilness.get_id(), 0.5)

    # deviation at depth 4
    evilness = extractor_round_2.extract(syscall_6)
    assert evilness == (PathEvilness.get_id(), 0.25)

    # invalid fd
    evilness = extractor_round_2.extract(syscall_9)
    assert evilness == (PathEvilness.get_id(), 0)

    # fd is ip
    evilness = extractor_round_2.extract(syscall_11)
    assert evilness == (PathEvilness.get_id(), 0)

    # filepath is known
    evilness = extractor_round_2.extract(syscall_1)
    assert evilness == (PathEvilness.get_id(), 0)



