from algorithms.features.time_delta_syscalls import TimeDeltaSyscalls
from dataloader.syscall import Syscall


def test_time_delta_syscalls():
    # legit
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall(
        "1631209047762164269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall(
        "1631209047762264269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall(
        "1631209047762364269 0 3686303 apache2 3686304 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall(
        "1631209047762464269 0 3686303 apache2 3686305 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall(
        "1631209047762564269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall(
        "1631209047762664269 0 3686303 apache2 3686304 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall(
        "1631209047762764269 0 3686303 apache2 3686304 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscalls = [syscall_1,
                syscall_2,
                syscall_3,
                syscall_4,
                syscall_5,
                syscall_6,
                syscall_7,
                syscall_8,
                syscall_9]

    td = TimeDeltaSyscalls(thread_aware=False)
    for syscall in syscalls:
        td.train_on(syscall)
    td.fit()
    # biggest time delta 579 nanoseconds
    max_time_delta = td._max_time_delta
    # first syscall, no time delta
    data = td.extract(syscall_1)
    assert (data[1] == 0)
    # second syscall has biggest time_delta -> normalized = 1
    data = td.extract(syscall_2)
    assert (data[1] == 1.0)
    # timedelta of 100 nanoseconds: 100/579
    data = td.extract(syscall_3)
    assert (data[1] == 100/max_time_delta)
