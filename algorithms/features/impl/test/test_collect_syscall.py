from algorithms.features.impl.flags import Flags
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.features.impl.return_value import ReturnValue
from algorithms.features.impl.path_evilness import PathEvilness
from algorithms.features.impl.stream_maximum import StreamMaximum
from algorithms.features.impl.collect_syscall import CollectSyscall

from dataloader.syscall_2021 import Syscall2021


def test_collect_syscall():
    # legit

    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209147761484609 0 30244 Process-1 31394 writev > addr=7FE7FC0011B8 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209247761482610 0 30244 Process-1 31394 writev < res=10')
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidiys_bhaskara_7006.zip',
                            '1631209347761487611 0 30244 Process-2 30532 read > addr=7FE87C0D6F28 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209447761489612 0 30244 Process-1 31394 read > addr=7FE7FC00120C op=128(FUTEX_PRIVATE_FLAG) val=0')
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209547761481613 0 30244 Process-1 31394 read < res=0')
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209647761482614 0 30244 Process-2 30532 read < res=-110(ETIMEDOUT)')
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209747761483615 0 30244 Process-1 31393 read >')
    syscall_8 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209847761484616 0 30244 Process-1 31393 read < res=100 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_9 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631210047761485617 0 30244 Process-1 31393 read >')
    syscall_10 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631211047761464618 0 30244 Process-1 31393 stat < res=100 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_11 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631209147761484609 0 30244 Process-1 31394 writev < addr=7FE7FC0011B8 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_12 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631221047761464618 0 30244 Process-1 31393 writev >')
    syscall_13 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631239047761464619 0 30244 Process-1 31393 writev < res=100 path=/usr/local/tomcat/conf/tomcat-users.xml')
    syscall_14 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631249047761414620 0 30244 Process-1 31393 write > ')
    syscall_15 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631259047761424621 0 30244 Process-1 31393 write < fd=64(<f>/usr/local/tomcat/conf/tomcat-users.xml) dirfd=-100(AT_FDCWD) name=/usr/local/tomcat/conf/tomcat-users.xml flags=1(O_RDONLY) mode=0 dev=802 ')
    syscall_16 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631269047761434622 0 30244 Catalina-utilit 31393 read > fd=64(<f>/usr/local/tomcat/conf/tomcat-users.xml) ')
    syscall_17 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                             '1631279047761444623 0 30244 Catalina-utilit 31393 read < res=0 ')

    training_syscalls = [syscall_1, syscall_2,
                         syscall_3, syscall_4,
                         syscall_5, syscall_6,
                         syscall_7, syscall_8,
                         syscall_9, syscall_10]

    pe = PathEvilness(scenario_path='Test/test',
                      path='algorithms/Models',
                      force_retrain=True)
    rv = ReturnValue()

    for syscall in training_syscalls:
        pe.train_on(syscall)
        rv.train_on(syscall)
    pe.fit()

    col = CollectSyscall(feature_list=[pe, rv])

    assert col._calculate(syscall_11) is None    # closing syscall
    assert col._calculate(syscall_12) is None  # opening syscall 
    assert col._calculate(syscall_13) == (0, 10)  # closing (pe=0,rv=10)

    pe = PathEvilness(scenario_path='Test/test',
                      path='algorithms/Models',
                      force_retrain=True)
    rv = ReturnValue()

    flag = Flags()
    time_delta = TimeDelta(thread_aware=True)
    str_max = StreamMaximum(feature=time_delta,
                            thread_aware=True, window_length=2)

    print('start training')
    for syscall in training_syscalls:
        pe.train_on(syscall)
        rv.train_on(syscall)
        time_delta.train_on(syscall)
    print('end training')
    pe.fit()
    time_delta.fit()

    col = CollectSyscall(feature_list=[pe, rv, flag, str_max])

    # starts with closed syscall
    assert col._calculate(syscall_11) is None
    assert col._calculate(syscall_12) is None
    assert col._calculate(syscall_13) == (0, 10.0, '0', 18.000000377983007) 
    assert col._calculate(syscall_14) is None
    assert col._calculate(syscall_15) == (1.0, 0, '1(O_RDONLY)', 10.000000219991005)
    assert col._calculate(syscall_16) is None
    assert col._calculate(syscall_17) == (0, 0.0, '0', 10.000000219991005)
