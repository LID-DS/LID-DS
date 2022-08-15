import pytest

from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.ngram import Ngram

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


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

    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_18 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_19 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_20 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

    n_gram_streamer = Ngram(
        feature_list=[SyscallName()],
        thread_aware=True,
        ngram_length=3
    )

    # SYSCALL 1
    assert n_gram_streamer.get_result(syscall_1) == None

    # SYSCALL 2
    assert n_gram_streamer.get_result(syscall_2) == None

    # SYSCALL 3
    assert n_gram_streamer.get_result(syscall_3) == ('open', 'close', 'poll')

    # SYSCALL 4
    assert n_gram_streamer.get_result(syscall_4) == None

    # SYSCALL 5
    assert n_gram_streamer.get_result(syscall_5) == None

    # SYSCALL 6
    assert n_gram_streamer.get_result(syscall_6) == None

    # SYSCALL 7    
    assert n_gram_streamer.get_result(syscall_7) == ('close', 'poll', 'mmap')

    # SYSCALL 8
    assert n_gram_streamer.get_result(syscall_8) == ('mmap', 'open', 'open')

    # SYSCALL 9
    assert n_gram_streamer.get_result(syscall_9) == ('poll', 'mmap', 'close')

    # SYSCALL 10 - str instead of int as thread id
    with pytest.raises(ValueError):
        n_gram_streamer.get_result(syscall_10)

    # SYSCALL 11
    assert n_gram_streamer.get_result(syscall_11) == ('mmap', 'close', 'hello')

    # 2019 Syscalls
    n_gram_streamer = Ngram(
        feature_list=[ThreadID()],
        thread_aware=False,
        ngram_length=3
    )
    
    assert n_gram_streamer.get_result(syscall_12) == None
    assert n_gram_streamer.get_result(syscall_13) == None
    assert n_gram_streamer.get_result(syscall_14) == (1, 2, 3)
    assert n_gram_streamer.get_result(syscall_15) == (2, 3, 4)
    assert n_gram_streamer.get_result(syscall_16) == (3, 4, 5)
    assert n_gram_streamer.get_result(syscall_17) == (4, 5, 1)
    assert n_gram_streamer.get_result(syscall_18) == (5, 1, 2)
    assert n_gram_streamer.get_result(syscall_19) == (1, 2, 3)
    assert n_gram_streamer.get_result(syscall_20) == (2, 3, 4)
