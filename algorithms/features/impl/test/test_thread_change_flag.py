from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall_2021 import Syscall2021 as Syscall


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


    ng = Ngram(
        feature_list=[SyscallName()],
        thread_aware=True,
        ngram_length=3
    )

    tcf = ThreadChangeFlag(ng)

    # SYSCALL 1
    assert tcf.get_result(syscall_1) == None

    # SYSCALL 2
    assert tcf.get_result(syscall_2) == None

    # SYSCALL 3
    assert tcf.get_result(syscall_3) == 1

    # SYSCALL 4
    assert tcf.get_result(syscall_4) == None

    # SYSCALL 5
    assert tcf.get_result(syscall_5) == None

    # SYSCALL 6
    assert tcf.get_result(syscall_6) == None

    # SYSCALL 7
    assert tcf.get_result(syscall_7) == 0

    # SYSCALL 8
    assert tcf.get_result(syscall_8) == 1

    # SYSCALL 9
    assert tcf.get_result(syscall_9) == 1

    # SYSCALL 10
    assert tcf.get_result(syscall_10) == 0
