import pytest

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def helper(syscall, feature_list, ngram, ngram_mo, cid):
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall, syscall_dict)
    ngram.calculate(syscall, syscall_dict)
    ngram_mo.calculate(syscall, syscall_dict)
    return syscall_dict[cid]


def test_ngram_minus_one():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686304 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686305 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686304 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 gibberish gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 3686303 hello < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    features = [ThreadID(), SyscallName()]

    ng = Ngram(feature_list=[SyscallName()], thread_aware=True, ngram_length=3)
    ngm = NgramMinusOne(ngram=ng, element_size=1)

    id = ngm.get_id()

    # SYSCALL 1
    with pytest.raises(KeyError):
        helper(syscall_1, features, ng, ngm, id)

    # SYSCALL 2
    with pytest.raises(KeyError):
        helper(syscall_2, features, ng, ngm, id)

    # SYSCALL 3
    assert helper(syscall_3, features, ng, ngm, id) == ('open', 'close')

    # SYSCALL 4
    with pytest.raises(KeyError):
        helper(syscall_4, features, ng, ngm, id)

    # SYSCALL 5
    with pytest.raises(KeyError):
        helper(syscall_5, features, ng, ngm, id)

    # SYSCALL 6
    with pytest.raises(KeyError):
        helper(syscall_6, features, ng, ngm, id)

    # SYSCALL 7
    assert helper(syscall_7, features, ng, ngm, id) == ('close', 'poll')

    # SYSCALL 8
    assert helper(syscall_8, features, ng, ngm, id) == ('mmap', 'open')

    # SYSCALL 9
    assert helper(syscall_9, features, ng, ngm, id) == ('poll', 'mmap')

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        helper(syscall_10, features, ng, ngm, id)

    # SYSCALL 11
    assert helper(syscall_11, features, ng, ngm, id) == ('mmap', 'close')
