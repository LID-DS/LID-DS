from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.select import Select
from algorithms.features.impl.int_embedding import IntEmbedding

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


def test_select():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 close < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591921358 33 604836 apache2 604836 read < res=338 data=FwMDAU1v8Mm2YkhDrBPnVbzCG33b1N3hnXmeVAZ9/VXFkW1dIv44P2/krMovxnOHA/bkoZ6zJiCN/mmuYj8wAH8U4Cl5qDMLmlHvjr/YBMQ=")
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631064318591700272 33 604836 apache2 604836 writev < res=274 data=FgMDANoEAADWAAABLADQiKBNVJWsSrM3g2cncm+h9cvVmHhqIHNBIaAHZ9NxylaHczULmo/S4GWzIM70XmqcGG+SWQLpstg+fd7loxUnpHQ=")

    training_syscalls = [
        syscall_1,
        syscall_2,
        syscall_3,
        syscall_4,
    ]
    inte = IntEmbedding()
    # because of singleton int embedding already includes {'open': 1, 'getuid': 2}
    inte._syscall_dict = {}
    for syscall in training_syscalls:
        inte.train_on(syscall)
    ngram = Ngram(feature_list=[inte], thread_aware=False, ngram_length=3)
    sel = Select(input_vector=ngram, start=2, end=3, step=1)

    assert sel.get_result(syscall_1) is None   # No ngram yet
    assert sel.get_result(syscall_2) is None   # No ngram yet
    assert sel.get_result(syscall_3) == (3,)   # (1,2,3)
    assert sel.get_result(syscall_4) == (4,)     # (2,3,4)

    ngram = Ngram(feature_list=[inte], thread_aware=False, ngram_length=4)
    sel = Select(input_vector=ngram, start=0, end=4, step=2)

    assert sel.get_result(syscall_1) is None   # No ngram yet
    assert sel.get_result(syscall_2) is None   # No ngram yet
    assert sel.get_result(syscall_3) is None   # No ngram yet
    assert sel.get_result(syscall_4) == (1, 3)     # (1,2,3,4)
