from algorithms.features.w2v_embedding import W2VEmbedding
from dataloader.syscall import Syscall


def test_path_evilness():
    # legit
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # legit
    syscall_2 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_3 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_4 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_5 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_6 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 select < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_7 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 mmap < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_8 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # legit
    syscall_9 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # unknown
    syscall_10 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 gibberish < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # int instead of string
    syscall_11 = Syscall(
        "1631209047762064269 0 3686303 apache2 3686303 627272 < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")


    vector_size = 3
    embedding = W2VEmbedding(
        vector_size=vector_size,
        window_size=4,
        epochs=50,
        scenario_path='/test/test',  # mock that is only used for model name
        path='algorithms/Models',
        force_train=True
    )

    training_syscalls = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5, syscall_6, syscall_7, syscall_8]

    for syscall in training_syscalls:
        embedding.train_on(syscall)

    embedding.fit()

    return_value = embedding.extract(syscall_9)
    assert return_value[0] == W2VEmbedding.get_id()
    assert type(return_value[1]) == list

    return_value = embedding.extract(syscall_10)
    assert return_value[0] == W2VEmbedding.get_id()
    assert return_value[1] == [0] * vector_size

    return_value = embedding.extract(syscall_11)
    assert return_value[0] == W2VEmbedding.get_id()
    assert return_value[1] == [0] * vector_size

