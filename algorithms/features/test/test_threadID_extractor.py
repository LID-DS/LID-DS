from algorithms.features.threadID import ThreadID
from dataloader.syscall import Syscall
import pytest

def test_syscall_thread_id_extract():
    # legit
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    # legit
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 717 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    # str instead of int
    syscall_3 = Syscall("1631209047762210355 33 3686303 apache2 gibberish getuid < uid=33(www-data) ")

    extractor = ThreadID()

    id = extractor.extract(syscall_1)
    assert id == (ThreadID.get_id(), 3686302)

    id = extractor.extract(syscall_2)
    assert id == (ThreadID.get_id(), 717)

    with pytest.raises(ValueError):
        id = extractor.extract(syscall_3)
