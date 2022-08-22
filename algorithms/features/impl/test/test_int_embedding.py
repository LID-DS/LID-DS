from algorithms.features.impl.threadID import ThreadID 
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.int_embedding import IntEmbedding

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

def test_int_embedding():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762210355 33 4686302 apache2 3686302 unknown < uid=33(www-data) ")

    syscall_5 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_6 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')
    syscall_7 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36589 00:15:56.976998042 6 999 mysqld 3 > setsockopt')
    syscall_8 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36590 00:15:56.976999081 6 999 mysqld 4 < setsockopt res=0 fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) level=1(SOL_SOCKET) optname=20(SO_RCVTIMEO) val=28800000000000(28800s) optlen=16')
    syscall_9 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36591 00:15:56.977001060 6 999 mysqld 5 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')
    syscall_10 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36592 00:15:56.977002483 6 999 mysqld 1 < read res=-11(EAGAIN) data=')
    syscall_11 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36593 00:15:56.977003699 6 999 mysqld 2 > fcntl fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) cmd=5(F_SETFL)')
    syscall_12 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
            '36594 00:15:56.977004485 6 999 mysqld 3 < fcntl res=0(<f>/dev/null)')
    syscall_13 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
        '36595 00:15:56.977005435 6 999 mysqld 4 > read fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=4')

    si = IntEmbedding()
    # trianing
    si.train_on(syscall_1)
    si.train_on(syscall_2)
    si.train_on(syscall_3)
    si.fit()

    # detection
    assert si._calculate(syscall_1) == 1
    assert si._calculate(syscall_2) == 1
    assert si._calculate(syscall_3) == 2
    assert si._calculate(syscall_4) == 0

    pid = ProcessID()
    si = IntEmbedding(building_block=pid)
    si._syscall_dict = {}
    si.train_on(syscall_1)
    si.train_on(syscall_2)
    si.train_on(syscall_3)

    assert si._calculate(syscall_1) == 1
    assert si._calculate(syscall_2) == 2
    assert si._calculate(syscall_3) == 1
    assert si._calculate(syscall_4) == 0

    tid = ThreadID()
    si = IntEmbedding(building_block=tid)
    
    si.train_on(syscall_5) # 1
    si.train_on(syscall_6) # 2
    si.train_on(syscall_7) # 3

    assert si._calculate(syscall_8) == 0 # 4
    assert si._calculate(syscall_9) == 0 # 5
    assert si._calculate(syscall_10) == 1 # 1
    assert si._calculate(syscall_11) == 2 # 2
    assert si._calculate(syscall_12) == 3 # 3
    assert si._calculate(syscall_13) == 0 # 4
