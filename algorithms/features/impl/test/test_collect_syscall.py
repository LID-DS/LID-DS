from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.collect_syscall import CollectSyscall

from dataloader.syscall_2021 import Syscall2021


def test_collect_syscall():
    # legit

    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 futex < res=10')

    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 futex > addr=7FE7FC0011B8 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 futex < res=0')
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-2 30532 futex < res=-110(ETIMEDOUT)')
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-2 30532 futex > addr=7FE87C0D6F28 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 futex > addr=7FE7FC00120C op=128(FUTEX_PRIVATE_FLAG) val=0')
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31393 stat >')
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31393 stat < res=0 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31393 stat >')
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Process-1 31393 stat < res=0 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Process-1 31393 stat >')
    syscall_12 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Process-1 31393 stat < res=0 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_13 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Process-1 31393 openat > ')
    syscall_14 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Process-1 31393 openat < fd=64(<f>/usr/local/tomcat/conf/tomcat-users.xml) dirfd=-100(AT_FDCWD) name=/usr/local/tomcat/conf/tomcat-users.xml flags      =1(O_RDONLY) mode=0 dev=802 ')
    syscall_15 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Catalina-utilit 31393 fstat > fd=64(<f>/usr/local/tomcat/conf/tomcat-users.xml) ')
    syscall_16 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1 0 30244 Catalina-utilit 31393 fstat < res=0 ')

    training_syscalls = [syscall_1, syscall_2,
                         syscall_3, syscall_4,
                         syscall_4, syscall_5,
                         syscall_6, syscall_7,
                         syscall_8, syscall_9,
                         syscall_10]

    pe = PathEvilness(scenario_path='Test/test',
                      path='algorithms/Models',
                      force_retrain=True)
    rv = ReturnValue()

    for syscall in training_syscalls:
        pe.train_on(syscall)
        rv.train_on(syscall)
    pe.fit()
    rv.fit()

    col = CollectSyscall(feature_list=[pe, rv])

    assert col._calculate(syscall_1) == 10  # 10
    assert min._calculate(syscall_2) == 10  # 11
