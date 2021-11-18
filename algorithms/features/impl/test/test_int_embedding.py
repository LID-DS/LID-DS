from algorithms.features.impl.int_embedding import IntEmbedding
from dataloader.syscall import Syscall


def test_int_embedding():
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")
    syscall_3 = Syscall("1631209047762210355 33 3686302 apache2 3686302 getuid < uid=33(www-data) ")
    syscall_4 = Syscall("1631209047762210355 33 3686302 apache2 3686302 unknown < uid=33(www-data) ")

    si = IntEmbedding()
    features = {}

    # trianing
    si.train_on(syscall_1, features)
    si.train_on(syscall_2, features)
    si.train_on(syscall_3, features)
    si.fit()

    # detection
    si.extract(syscall_1, features)
    assert (features[IntEmbedding.get_id()] == 1)
    si.extract(syscall_2, features)
    assert (features[IntEmbedding.get_id()] == 1)
    si.extract(syscall_3, features)
    assert (features[IntEmbedding.get_id()] == 2)

    si.extract(syscall_4, features)
    assert (features[IntEmbedding.get_id()] == 0)
