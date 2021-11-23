from algorithms.features.syscalls_in_time_window import SyscallsInTimeWindow
from dataloader.syscall import Syscall


def test_syscalls_in_time_window():
    syscall_1 = Syscall(
        "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    syscall_2 = Syscall(
        "1631209048762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_3 = Syscall(
        "1631209049762064269 0 3686303 apache2 3686304 open < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_4 = Syscall(
        "1631209050762064269 0 3686303 apache2 3686304 open < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_5 = Syscall(
        "1631209051762064269 0 3686303 apache2 3686303 open < out_fd=9(<f>/etc/password) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_6 = Syscall(
        "1631209052762064269 0 3686303 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/evil) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_7 = Syscall(
        "1000000001000000000 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_8 = Syscall(
        "1000000002000000000 0 3686303 apache2 3686303 open < fd=9(<f>gibberish) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_9 = Syscall(
        "1000000003000000000 0 3686303 apache2 3686303 open < fd=9(<f>wackawacka) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_10 = Syscall(
        "1000000004000000000 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_11 = Syscall(
        "1000000005000000000 0 3686303 apache2 3686303 open < fd=53(<4t>172.19.0.1:36368->172.19.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    syscall_12 = Syscall(
        "1000000008000000000 0 3686303 apache2 3686303 open < name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")


    training_syscalls = [syscall_1, syscall_2, syscall_3, syscall_4, syscall_5, syscall_6]
    extractor = SyscallsInTimeWindow(window_length_in_s=3)

    for syscall in training_syscalls:
        extractor.train_on(syscall)

    extractor.fit()

    print(extractor._training_max)

    id = extractor.get_id()
    # assert extractor.extract(syscall_7) == (id, 0)
    print(extractor.extract(syscall_7))
    print(extractor._syscall_buffer)

    # assert extractor.extract(syscall_8) == (id, 0)
    print(extractor.extract(syscall_8))
    print(extractor._syscall_buffer)

    # assert extractor.extract(syscall_9) == (id, 0)
    print(extractor.extract(syscall_9))
    print(extractor._syscall_buffer)

    # assert extractor.extract(syscall_10) == (id, 0)
    print(extractor.extract(syscall_10))
    print(extractor._syscall_buffer)

    print(extractor.extract(syscall_11))
    print(extractor._syscall_buffer)

    print(extractor.extract(syscall_12))
    print(extractor._syscall_buffer)




if __name__ == '__main__':
    test_syscalls_in_time_window()




