import pytest

from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.threadID import ThreadID
from dataloader.syscall_2021 import Syscall2021


def test_ngram():
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

    feature_list = [ThreadID(), SyscallName()]

    n_gram_streamer = Ngram(
        feature_list=[SyscallName()],
        thread_aware=True,
        ngram_length=3
    )

    # SYSCALL 1
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_1, syscall_dict)
    n_gram_streamer.calculate(syscall_1, syscall_dict)
    with pytest.raises(KeyError):
        syscall_dict[n_gram_streamer.get_id()]

    # SYSCALL 2
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_2, syscall_dict)
    n_gram_streamer.calculate(syscall_2, syscall_dict)
    with pytest.raises(KeyError):
        syscall_dict[n_gram_streamer.get_id()]

    # SYSCALL 3
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_3, syscall_dict)
    n_gram_streamer.calculate(syscall_3, syscall_dict)
    assert syscall_dict[n_gram_streamer.get_id()] == ('open', 'close', 'poll')

    # SYSCALL 4
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_4, syscall_dict)
    n_gram_streamer.calculate(syscall_4, syscall_dict)
    with pytest.raises(KeyError):
        syscall_dict[n_gram_streamer.get_id()]

    # SYSCALL 5
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_5, syscall_dict)
    n_gram_streamer.calculate(syscall_5, syscall_dict)
    with pytest.raises(KeyError):
        syscall_dict[n_gram_streamer.get_id()]

    # SYSCALL 6
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_6, syscall_dict)
    n_gram_streamer.calculate(syscall_6, syscall_dict)
    with pytest.raises(KeyError):
        syscall_dict[n_gram_streamer.get_id()]

    # SYSCALL 7
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_7, syscall_dict)
    n_gram_streamer.calculate(syscall_7, syscall_dict)
    assert syscall_dict[n_gram_streamer.get_id()] == ('close', 'poll', 'mmap')

    # SYSCALL 8
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_8, syscall_dict)
    n_gram_streamer.calculate(syscall_8, syscall_dict)
    assert syscall_dict[n_gram_streamer.get_id()] == ('mmap', 'open', 'open')

    # SYSCALL 9
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_9, syscall_dict)
    n_gram_streamer.calculate(syscall_9, syscall_dict)
    assert syscall_dict[n_gram_streamer.get_id()] == ('poll', 'mmap', 'close')

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        syscall_dict = {}
        for feature in feature_list:
            feature.calculate(syscall_10, syscall_dict)
        n_gram_streamer.calculate(syscall_10, syscall_dict)

    # SYSCALL 11
    syscall_dict = {}
    for feature in feature_list:
        feature.calculate(syscall_11, syscall_dict)
    n_gram_streamer.calculate(syscall_11, syscall_dict)
    assert syscall_dict[n_gram_streamer.get_id()] == ('mmap', 'close', 'hello')
