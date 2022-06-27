import base64

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

from algorithms.features.impl.data_buffer import DataBuffer


def test_data_buffer():
    syscall_1 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "2569 00:10:50.488781617 2 999 mysqld 22545 < write res=78 data=J....5.5.23....hJyAy_PR...................*yE-M}Q\Z0|E.mysql_native_password.")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591921358 33 604836 apache2 604836 read < res=338 data=FwMDAU1v8Mm2YkhDrBPnVbzCG33b1N3hnXmeVAZ9/VXFkW1dIv44P2/krMovxnOHA/bkoZ6zJiCN/mmuYj8wAH8U4Cl5qDMLmlHvjr/YBMQ=")
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591700272 33 604836 apache2 604836 writev < res=274 data=FgMDANoEAADWAAABLADQiKBNVJWsSrM3g2cncm+h9cvVmHhqIHNBIaAHZ9NxylaHczULmo/S4GWzIM70XmqcGG+SWQLpstg+fd7loxUnpHQ=")

    db = DataBuffer()
    assert db.get_result(syscall_1) is None  # syscall 2019
    assert db.get_result(syscall_2) == "J....5.5.23....hJyAy_PR...................*yE-M}Q\Z0|E.mysql_native_password."
    assert db.get_result(syscall_3) is None
    data_buffer = str(base64.b64decode(syscall_4.param(param_name='data')))
    assert db.get_result(syscall_4) == data_buffer
    data_buffer = str(base64.b64decode(syscall_5.param(param_name='data')))
    assert db.get_result(syscall_5) == data_buffer
    db = DataBuffer(decode=False)
    assert db.get_result(syscall_5) == 'FgMDANoEAADWAAABLADQiKBNVJWsSrM3g2cncm+h9cvVmHhqIHNBIaAHZ9NxylaHczULmo/S4GWzIM70XmqcGG+SWQLpstg+fd7loxUnpHQ='
