"""
    test function of and decider 
"""
import pytest
from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.and_decider import AndDecider
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.ngram import Ngram


def test_and_decider():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 1 apache2 0 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 0 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 0 close < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 2 apache2 0 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 2 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 1 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 1 apache2 2 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # no int as thread id
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 XXX apache2 XXX close < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 1 apache2 1 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_12 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 2 apache2 4 mmap < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_13 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_14 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 open < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_15 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 open > fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_16 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 read < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_17 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 read > fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_18 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 fcntl < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_19 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 fcntl > fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_20 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 futex < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_21 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 close > fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_22 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3 apache2 3 mmap < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    train_syscalls = [
        syscall_1, syscall_2, syscall_3, syscall_4,
        syscall_5, syscall_6, syscall_7, syscall_8
        ]
    val_syscalls = [
        syscall_9, syscall_10, syscall_11, syscall_12
        ]
    test_syscalls = [
        syscall_13, syscall_14, syscall_15, syscall_16,
        syscall_17, syscall_18, syscall_19, syscall_20,
        syscall_21, syscall_22
        ]

    syscall_name = SyscallName()
    ngram = Ngram([syscall_name], thread_aware = False, ngram_length = 2)
    ngram_2 = Ngram([syscall_name], thread_aware = False, ngram_length = 3)
    stide = Stide(ngram)
    stide_2 = Stide(ngram_2)
    stream_sum = StreamSum(stide, False, 2, False)
    stream_sum_2 = StreamSum(stide_2, False, 2, False)
    decider = MaxScoreThreshold(stream_sum)
    decider_2 = MaxScoreThreshold(stream_sum_2)
    and_decider = AndDecider([decider, decider_2])

    for syscall in train_syscalls:
        ngram.train_on(syscall)
        ngram_2.train_on(syscall)
    for syscall in train_syscalls:
        stide.train_on(syscall)
        stide_2.train_on(syscall)
    for syscall in val_syscalls:
        decider.val_on(syscall)
        decider_2.val_on(syscall)

    stream_sum.new_recording()
    stream_sum_2.new_recording()
    ngram.new_recording()
    ngram_2.new_recording()
    stide.new_recording()
    stide_2.new_recording()

    # normal database of stide is
    # {('close', 'close'), ('mmap', 'open'), ('close', 'mmap'),
    #  ('select', 'mmap'), ('open', 'select'), ('open', 'close')}

    # normal database of stide_2 is
    # {('close', 'mmap', 'open'), ('open', 'select', 'mmap'), ('open', 'close', 'close'), ('close', 'close', 'mmap'), ('select', 'mmap', 'open'), ('mmap', 'open', 'select')}
    # threshold is 1

    # Stide1: None -> 0 -> keine Anomaly
    # Stide2: None -> 0 -> keine Anomaly
    # 0 AND 0 -> 0
    assert and_decider.get_result(test_syscalls[0]) is False
    # Stide1: (close, open) -> unknown ngram other uninitilized (x,_)-> 1 + 0 = 1 !>1 -> keine Anomaly
    # Stide2: None (_,_) 0 -> 0
    # 0 AND 0 -> 0
    assert and_decider.get_result(test_syscalls[1]) is False
    # Stide1: (open, open) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (close, open, open) -> (_,x) -> 1+0 = 1 !> 1 -> keine Anomaly
    # 1 AND 0 -> 0
    assert and_decider.get_result(test_syscalls[2]) is False
    # Stide1: (open, read) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (open, open, read) -> (x) -> 1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[3]) is True
    # Stide1: (read, read) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (open, read, read) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[4]) is True
    # Stide1: (read, fcntl) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (read, read, fcntl) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[5]) is True
    # Stide1: (fcntl, fcntl) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (read, fcntl, fcntl) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[6]) is True
    # Stide1: (fcntl, futex) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (fcntl, fcntl, futex) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[7]) is True
    # Stide1: (futex, close) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (fcntl, futex, close) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 1 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[8]) is True
    # Stide1: (close, mmap) -> (x,x) -> 1+1 = 2 > 1 -> Anomaly
    # Stide2: (futex, close, mmap) -> (x) -> 1+1 = 1 !> 1 -> Anomaly
    # 0 AND 1 -> 1
    assert and_decider.get_result(test_syscalls[9]) is True
