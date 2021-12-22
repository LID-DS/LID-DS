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
        td.train_on(syscall, None)
    td.fit()
    # biggest time delta 579 nanoseconds
    max_time_delta = td._max_time_delta

    features = {}
    id = td.get_id()
    # first syscall, no time delta
    td.calculate(syscall_1, features)
    assert features[id] == 0
    # second syscall has biggest time_delta -> normalized = 1
    td.calculate(syscall_2, features)
    assert features[id] == 1.0
    # timedelta of 100 nanoseconds: 100/579
    td.calculate(syscall_3, features)
    assert features[id] == 100 / max_time_delta

    td = TimeDelta(thread_aware=True)
    id = td.get_id()
    for syscall in syscalls:
        td.train_on(syscall, None)
    td.fit()
    # biggest time delta 579 nanoseconds
    max_time_delta = td._max_time_delta
    # first syscall, no time delta
    td.calculate(syscall_1, features)
    assert features[id] == 0
    # second syscall has biggest time_delta -> normalized = 1
    td.calculate(syscall_2, features)
    assert features[id] == 1.0
    # timedelta of 100 nanoseconds: 100/579
    td.calculate(syscall_3, features)
    assert features[id] == 100 / max_time_delta
    # new thread_id so delta = 0
    td.calculate(syscall_4, features)
    assert features[id] == 0
    # timedelta of 110 nanoseconds: 110/579
    td.calculate(syscall_5, features)
    assert features[id] == 110 / max_time_delta
    # new thread_id so delta = 0
    td.calculate(syscall_6, features)
    assert features[id] == 0
    # timedelta of 110 nanoseconds: 110/579
    td.calculate(syscall_7, features)
    assert features[id] == 400 / max_time_delta
    # timedelta of 290 nanoseconds: 290/579
    td.calculate(syscall_8, features)
    assert features[id] == 290 / max_time_delta
    # timedelta of 300 nanoseconds: 300/579
    td.calculate(syscall_9, features)
    assert features[id] == 300 / max_time_delta
