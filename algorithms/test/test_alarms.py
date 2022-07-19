from algorithms.alarms import Alarms
from dataloader.syscall_2021 import Syscall2021


def test_alarms():
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686303 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024",
                            1)

    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 close < fd=9(<f>/proc/sys/kernel/ngroups_min) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ",
                            2)

    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047862064269 0 3686303 apache2 3686303 poll < fd=9(<f>/etc/group) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ",
                            3)

    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047962064269 0 3686303 apache2 3686304 mmap < in_fd=9(<f>/etc/test) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ",
                            4)

    alarms = Alarms()

    # testing of two consecutive alarms
    alarms.add_or_update_alarm(syscall_1, True)
    assert vars(alarms.current_alarm) == {'first_line_id': 1, 'first_timestamp': 1631209047761484608, 'correct': True,
                                          'last_line_id': 1, 'last_timestamp': 1631209047761484608,
                                          'scenario': 'CVE-2017-7529', 'dataset': 'LID-DS-2021',
                                          'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}

    alarms.add_or_update_alarm(syscall_2, True)
    assert vars(alarms.current_alarm) == {'first_line_id': 1, 'first_timestamp': 1631209047761484608, 'correct': True,
                                          'last_line_id': 2, 'last_timestamp': 1631209047762064269,
                                          'scenario': 'CVE-2017-7529', 'dataset': 'LID-DS-2021',
                                          'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}

    # testing of alarm end
    alarms.end_alarm()
    assert len(alarms.alarm_list) == 1
    assert alarms.current_alarm is None

    # testing of false alarm
    alarms.add_or_update_alarm(syscall_3, False)
    assert vars(alarms.current_alarm) == {'first_line_id': 3, 'first_timestamp': 1631209047862064269, 'correct': False,
                                          'last_line_id': 3, 'last_timestamp': 1631209047862064269,
                                          'scenario': 'CVE-2017-7529', 'dataset': 'LID-DS-2021',
                                          'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}

    # testing of switch from false alarm to correct alarm but consecutive calls
    alarms.add_or_update_alarm(syscall_4, True)
    assert len(alarms.alarm_list) == 2
    assert vars(alarms.current_alarm) == {'first_line_id': 4, 'first_timestamp': 1631209047962064269, 'correct': True,
                                          'last_line_id': 4, 'last_timestamp': 1631209047962064269,
                                          'scenario': 'CVE-2017-7529', 'dataset': 'LID-DS-2021',
                                          'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}
