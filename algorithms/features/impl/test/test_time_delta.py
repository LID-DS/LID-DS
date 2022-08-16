from algorithms.features.impl.time_delta import TimeDelta

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


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

    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 22:25:22.103544170 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 22:25:22.103552183 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 22:25:22.103560083 6 999 mysqld 3 > setsockopt')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 22:25:22.103562511 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 22:25:22.103564819 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 22:25:22.103565925 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 22:25:22.103567943 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_18 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 22:25:22.103569989 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_19 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36595 22:25:22.103572989 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')


    syscalls = [syscall_1, syscall_2, syscall_3,
                syscall_4, syscall_5, syscall_6,
                syscall_7, syscall_8, syscall_9]

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

    print('relevant')
    syscalls = [syscall_11, syscall_12, syscall_13,
                syscall_14, syscall_15, syscall_16]

    td = TimeDelta(thread_aware=False)
    for syscall in syscalls:
        td.train_on(syscall)
    td.fit()
    
    assert td._calculate(syscall_17) == 0
    assert td._calculate(syscall_18) == 2/td._max_time_delta
    assert td._calculate(syscall_19) == 3/td._max_time_delta
