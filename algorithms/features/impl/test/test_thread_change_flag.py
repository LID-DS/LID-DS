from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.syscall_2021 import Syscall2021 as Syscall


def helper(syscall, feature_list, ngram, tcf, cid):
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall, syscall_dict)
    ngram.calculate(syscall, syscall_dict)
    tcf.calculate(syscall, syscall_dict)
    print(syscall_dict)
    print(ngram.get_id())
    return syscall_dict[cid]


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

    features = [ThreadID(), SyscallName()]

    ng = Ngram(
        feature_list=[SyscallName()],
        thread_aware=True,
        ngram_length=3
    )

    tcf = ThreadChangeFlag(ng)

    id = tcf.get_id()

    # SYSCALL 1
    assert helper(syscall_1, features, ng, tcf, id) == 0

    # SYSCALL 2
    assert helper(syscall_2, features, ng, tcf, id) == 0

    # SYSCALL 3
    assert helper(syscall_3, features, ng, tcf, id) == 1

    # SYSCALL 4
    assert helper(syscall_4, features, ng, tcf, id) == 0

    # SYSCALL 5
    assert helper(syscall_5, features, ng, tcf, id) == 0

    # SYSCALL 6
    assert helper(syscall_6, features, ng, tcf, id) == 0

    # SYSCALL 7
    assert helper(syscall_7, features, ng, tcf, id) == 0

    # SYSCALL 8
    assert helper(syscall_8, features, ng, tcf, id) == 1

    # SYSCALL 9
    assert helper(syscall_9, features, ng, tcf, id) == 1

    # SYSCALL 10
    assert helper(syscall_10, features, ng, tcf, id) == 0
