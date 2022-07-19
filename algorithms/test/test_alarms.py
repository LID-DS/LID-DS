from algorithms.alarms import Alarms

from dataloader.syscall_2021 import Syscall2021
from dataloader.syscall_2019 import Syscall2019


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

    syscall_5 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36587 00:15:56.976976340 6 999 mysqld 1 > write fd=36(<4t>172.17.0.1:37032->172.17.0.13:3306) size=11')
    syscall_6 = Syscall2019('CVE-2017-7529/acidic_bhaskara_7006.zip',
            '36588 00:15:56.976995212 6 999 mysqld 2 < write res=11 data=......:....')

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
    assert vars(alarms.current_alarm) == {
            'first_line_id': 4,
            'first_timestamp': 1631209047962064269,
            'correct': True,
            'last_line_id': 4,
            'last_timestamp': 1631209047962064269,
            'scenario': 'CVE-2017-7529',
            'dataset': 'LID-DS-2021',
            'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}

    alarms.add_or_update_alarm(syscall_5, True)
    print(vars(alarms.current_alarm))
    assert vars(alarms.current_alarm) == {
    'first_line_id': 4,
    'first_timestamp': 1631209047962064269,
    'correct': True,
    'last_line_id': -1,
    'last_timestamp': -2643999023024.0,
    'scenario': 'CVE-2017-7529',
    'dataset': 'LID-DS-2021',
    'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}

    alarms.add_or_update_alarm(syscall_6, True)
    print(vars(alarms.current_alarm))
    assert vars(alarms.current_alarm) == {'first_line_id': 4,
    'first_timestamp': 1631209047962064269,
    'correct': True,
    'last_line_id': -1,
    'last_timestamp': -2643999023005.0,
    'scenario': 'CVE-2017-7529',
    'dataset': 'LID-DS-2021',
    'filepath': 'CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip'}
