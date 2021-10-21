from algorithms.features.path_evilness import PathEvilness
from dataloader.syscall import Syscall


def test_path_evilness():
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_3 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_4 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_5 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_6 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    training_syscalls = [syscall_1, syscall_2, syscall_3, syscall_4]
    extractor = PathEvilness(scenario_path='/Test/test', path='algorithms/Models')
    """
    
    scenario path is a mock that is only used to name the tree model
    
    path is overwritten to algorithms/Models because we assume pytest runs from the main LID-DS folder
    
    """

    for syscall in training_syscalls:
        extractor.train_on(syscall)

    extractor.fit()

    evilness = extractor.extract(syscall_5)
    assert evilness == (PathEvilness.get_id(), 0.5)

    evilness = extractor.extract(syscall_6)
    assert evilness == (PathEvilness.get_id(), 0.25)

