from algorithms.features.impl.time_delta import TimeDelta
from dataloader.syscall_2021 import Syscall2021


def test_time_delta():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762164269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762264269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762374269 0 3686303 apache2 3686304 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762464269 0 3686303 apache2 3686305 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762564269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762664269 0 3686303 apache2 3686304 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762764269 0 3686303 apache2 3686305 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscalls = [syscall_1,
                syscall_2,
                syscall_3,
                syscall_4,
                syscall_5,
                syscall_6,
                syscall_7,
                syscall_8,
                syscall_9]

    td = TimeDelta(thread_aware=False)
    for syscall in syscalls:
        td.train_on(syscall)
    td.fit()
    print('done with training')
    # biggest time delta 579661 nanoseconds
    max_time_delta = td._max_time_delta

    # first syscall, no time delta
    assert td._calculate(syscall_1) == 0
    # second syscall has biggest time_delta -> normalized = 1
    assert td._calculate(syscall_2) == 1.0
    # timedelta of 100000 nanoseconds: 100000/579661
    assert td._calculate(syscall_3) == 100000 / max_time_delta

    td = TimeDelta(thread_aware=True)
    # id = td.get_id()
    for syscall in syscalls:
        td.train_on(syscall)
    td.fit()
    # biggest time delta 579 microseconds
    max_time_delta = td._max_time_delta
    # first syscall, no time delta
    assert td._calculate(syscall_1) == 0
    # second syscall has biggest time_delta -> normalized = 1
    assert td._calculate(syscall_2) == 1.0
    # timedelta of 100000 nanoseconds: 100000/579661
    assert td._calculate(syscall_3) == 100000 / max_time_delta
    # new thread_id so delta = 0
    assert td._calculate(syscall_4) == 0
    # timedelta of 110000 nanoseconds: 110000/579661
    assert td._calculate(syscall_5) == 110000 / max_time_delta
    # new thread_id so delta = 0
    assert td._calculate(syscall_6) == 0
    # timedelta of 400000 nanoseconds: 400000/579661
    assert td._calculate(syscall_7) == 400000 / max_time_delta
    # timedelta of 290000 nanoseconds: 290000/579
    assert td._calculate(syscall_8) == 290000 / max_time_delta
    # timedelta of 300000 nanoseconds: 300000/579
    assert td._calculate(syscall_9) == 300000 / max_time_delta
