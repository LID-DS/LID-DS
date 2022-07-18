from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.process_name import ProcessName

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def test_w2v_embedding():
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
                            "1631209047762064269 0 3686303 apache2 3686303 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # legit
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # unknown
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 3686303 gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # int instead of string
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             "1631209047762064269 0 3686303 apache2 3686303 627272 < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_12 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 apache2 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11 flags=test5')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 apache2 1 < write res=11 data=......:.... flags=test6')
    syscall_14 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 1 > setsockopt flags=test6')
    syscall_15 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 1 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16 flags=test7')
    syscall_16 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 1 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4 flags=test8')
    syscall_17 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) flags=test8')
    syscall_18 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL) flags=test10')
    syscall_19 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 2 < fcntl res=0(<f>/dev/null) flags=test11')
    syscall_20 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 python 2 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4 flags=test6')

    vector_size = 3
    name = SyscallName()
    embedding = W2VEmbedding(
        word=name,
        vector_size=vector_size,
        window_size=4,
        epochs=50
    )

    training_syscalls = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5, syscall_6, syscall_7, syscall_8]

    for syscall in training_syscalls:
        embedding.train_on(syscall)
    print(embedding._sentences)
    embedding.fit()

    
    assert type(embedding._calculate(syscall_9)) == tuple
   
    assert embedding._calculate(syscall_10) == tuple([0] * vector_size)

    assert embedding._calculate(syscall_11) == tuple([0] * vector_size)

    vector_size = 3
    name = ProcessName()
    embedding_2019 = W2VEmbedding(
        word=name,
        vector_size=vector_size,
        window_size=3,
        epochs=50
    )

    training_syscalls = [syscall_12, syscall_13, syscall_14,
                         syscall_15, syscall_16, syscall_17]

    for syscall in training_syscalls:
        embedding_2019.train_on(syscall)
    embedding_2019.fit()

    assert type(embedding_2019._calculate(syscall_18)) == tuple
    assert type(embedding_2019._calculate(syscall_19)) == tuple
    assert embedding_2019._calculate(syscall_20) == tuple([0] * vector_size) 
