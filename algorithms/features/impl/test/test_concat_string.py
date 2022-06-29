import base64
import pytest

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019

from algorithms.features.impl.concat import Concat
from algorithms.features.impl.threadID import ThreadID
from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.syscall_name import SyscallName 
from algorithms.features.impl.concat_strings import ConcatStrings


def test_concat_strings():
    syscall_1 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '21617 17:53:04.874175829 5 101 nginx 13776 > switch next=16427 pgft_maj=0 pgft_min=119 vm_size=42976 vm_rss=2480 vm_swap=0')
                            
    syscall_2 = Syscall2019('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "21576 17:53:04.193807617 7 101 nginx 13775 > sendfile out_fd=13(<4t>172.17.0.1:51756->172.17.0.5:8080) in_fd=14(<f>/tmp/nginx/5/77/42e5373cc524f2ebe558749ab23c7775) offset=613 size=612")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591921358 33 604836 apache2 604836 read < res=338 data=FwMDAU1v8Mm2YkhDrBPnVbzCG33b1N3hnXmeVAZ9/VXFkW1dIv44P2/krMovxnOHA/bkoZ6zJiCN/mmuYj8wAH8U4Cl5qDMLmlHvjr/YBMQ=")
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591700272 33 604836 apache2 604836 writev < res=274 data=FgMDANoEAADWAAABLADQiKBNVJWsSrM3g2cncm+h9cvVmHhqIHNBIaAHZ9NxylaHczULmo/S4GWzIM70XmqcGG+SWQLpstg+fd7loxUnpHQ=")

    sys_name = SyscallName()
    proc_name = ProcessName()
    con = Concat([sys_name, proc_name])
    cs = ConcatStrings(con)
    assert cs.get_result(syscall_1) == 'switchnginx'
    assert cs.get_result(syscall_2) == 'sendfilenginx'
    assert cs.get_result(syscall_3) == 'openapache2'
    assert cs.get_result(syscall_4) == 'readapache2'
    assert cs.get_result(syscall_5) == 'writevapache2'
    sys_name = SyscallName()
    tid = ThreadID()
    con = Concat([sys_name, tid])
    cs = ConcatStrings(con)
    assert cs.get_result(syscall_1) == 'switch13776'
    cs = ConcatStrings(sys_name)
    # Not giving concat BB as input
    with pytest.raises(ValueError) as error:
        cs.get_result(syscall_1)
