from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

from algorithms.features.impl.entropy import Entropy
from algorithms.features.impl.processID import ProcessID
from algorithms.features.impl.data_buffer import DataBuffer
from algorithms.features.impl.syscall_name import SyscallName


def test_entropy():
    # legit
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 10 apache2 10 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 11 apache2 11 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 12 apache2 12 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_4 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "2569 00:10:50.488781617 2 999 mysqld 22545 < write res=78 data=J....5.5.23....hJyAy_PR...................*yE-M}Q\Z0|E.mysql_native_password.")

    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591921358 33 604836 apache2 604836 read < res=338 data=FwMDAU1v8Mm2YkhDrBPnVbzCG33b1N3hnXmeVAZ9/VXFkW1dIv44P2/krMovxnOHA/bkoZ6zJiCN/mmuYj8wAH8U4Cl5qDMLmlHvjr/YBMQ=")
    # legit
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591700272 33 604836 apache2 604836 writev < res=274 data=FgMDANoEAADWAAABLADQiKBNVJWsSrM3g2cncm+h9cvVmHhqIHNBIaAHZ9NxylaHczULmo/S4GWzIM70XmqcGG+SWQLpstg+fd7loxUnpHQ=")

    pid = ProcessID()
    ent = Entropy(feature=pid)

    assert ent._calculate(syscall_1) == 0               # 10
    assert ent._calculate(syscall_2) == 0               # 11
    assert ent._calculate(syscall_3) == 0               # 12
    assert ent._calculate(syscall_4) is None            # Syscall 2019 has no pid

    name = SyscallName()
    ent = Entropy(feature=name)

    assert ent._calculate(syscall_1) == 2       # open
    assert round(ent._calculate(syscall_2), 2) == 2.32    # close
    assert ent._calculate(syscall_3) == 1.5     # poll

    data_buffer = DataBuffer()
    ent = Entropy(feature=data_buffer)

    assert ent._calculate(syscall_1) is None              # No data buffer
    assert ent._calculate(syscall_2) is None              # No data buffer
    assert ent._calculate(syscall_3) is None              # No data buffer
    assert round(ent._calculate(syscall_4), 2) == 3.94
    assert round(ent._calculate(syscall_5), 2) == 4.03
    assert round(ent._calculate(syscall_6), 2) == 4.02
