from algorithms.features.impl.aabb import AABB
from algorithms.features.impl.k_center import KCenter
from dataloader.syscall_2021 import Syscall2021
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.int_embedding import IntEmbedding


def test_k_center():
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

    name = SyscallName()
    inte = IntEmbedding(name)
    ngram = Ngram([inte], thread_aware=False, ngram_length=3)

    k_center = KCenter(ngram, 2)

    val_syscalls = [
        syscall_1, syscall_2, syscall_3, syscall_4,
        syscall_5, syscall_6, syscall_7, syscall_8
    ]
    test_syscalls = [
        syscall_9, syscall_10, syscall_11, syscall_12,
        syscall_13, syscall_14, syscall_15, syscall_16,
        syscall_17, syscall_18, syscall_19, syscall_20,
        syscall_21, syscall_22
    ]

    # show all syscalls to int embedding
    for syscall in val_syscalls + test_syscalls:
        inte.train_on(syscall)

    for syscall in val_syscalls[0:2]:
        ngram.get_result(syscall)
    for syscall in val_syscalls[3:]:
        k_center.val_on(syscall)

    k_center.fit()

    # centers are [[1, 2, 3], [4, 3, 1]]
    # max radius = 2.449489742783178

                                                     # point   distance to nearest center
                                                     # ----------------------------------
    assert k_center.get_result(syscall_9) is False   # [3,1,2] 2.449489742783178
    assert k_center.get_result(syscall_10) is False  # [1,2,2] 1.0
    assert k_center.get_result(syscall_11) is False  # [2,2,2] 1.4142135623730951
    assert k_center.get_result(syscall_12) is False  # [2,2,3] 1.0
    assert k_center.get_result(syscall_13) is False  # [2,3,2] 1.7320508075688772
    assert k_center.get_result(syscall_14) is False  # [3,2,1] 1.4142135623730951
    assert k_center.get_result(syscall_15) is False  # [2,1,1] 2.449489742783178
    assert k_center.get_result(syscall_16) is False  # [1,1,5] 2.23606797749979
    assert k_center.get_result(syscall_17) is True   # [1,5,5] 3.6055512754639896
    assert k_center.get_result(syscall_18) is True   # [5,5,6] 5.47722557505166
    assert k_center.get_result(syscall_19) is True   # [5,6,6] 5.916079783099616
    assert k_center.get_result(syscall_20) is True   # [6,6,7] 7.0
    assert k_center.get_result(syscall_21) is True   # [6,7,2] 4.58257569495584
    assert k_center.get_result(syscall_22) is True   # [7,2,3] 3.741657386773941


if __name__ == '__main__':
    test_k_center()
