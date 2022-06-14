import os

from tqdm import tqdm

from algorithms.features.impl.filedescriptor import FileDescriptor, FDMode
from algorithms.features.impl.syscall_name import SyscallName
from dataloader.dataloader_factory import dataloader_factory
from dataloader.syscall_2019 import Syscall2019
from dataloader.syscall_2021 import Syscall2021


def test_filedescriptor():
    # LID-DS 2021
    # normal fd with file
    syscall_1 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=9(<f>/proc/sys/kernel/ngroups_max) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # normal fd with ip
    syscall_2 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047762064269 0 3686303 apache2 3686303 open < fd=53(<4t>172.17.0.1:36368->172.17.0.3:3306) name=/etc/group flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=200021 ")

    # out_fd and in_fd mixed ip with file
    syscall_3 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1631161014801307269 65534 3384228 nginx 3384228 sendfile > out_fd=9(<4t>172.21.0.3:50122->172.21.0.7:80) in_fd=20(<f>/etc/nginx/html/images/dashboard_full_2.jpg) offset=0 size=250749')

    # no fd
    syscall_4 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # only id
    syscall_5 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631106104749261739 4294967295 182896 sh 182896 fcntl > fd=10 cmd=3(F_SETFD)")

    # fd but no <marker>
    syscall_6 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=3(fd) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # fd=-1(EPERM)
    syscall_7 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            "1631209047761484608 0 3686302 apache2 3686302 open < fd=-1(EPERM) name=/proc/sys/kernel/ngroups_max flags=1(O_RDONLY) mode=0 dev=200024")

    # LID-DS 2019
    syscall_8 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                            "1631042440442667302 0 1488641 gs 1488641 mmap > addr=0 length=237568 prot=3(PROT_READ|PROT_WRITE) flags=10(MAP_PRIVATE|MAP_ANONYMOUS) fd=9(<f>/proc/sys/kernel/ngroups_max) offset=0",
                            1)

    syscall_9 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                            "31971 16:15:08.028039855 1 101 nginx 22454 > sendfile out_fd=13(<4t>172.17.0.1:45440->172.17.0.5:8080) in_fd=14(<f>/tmp/nginx/5/77/42e5373cc524f2ebe558749ab23c7775) offset=613 size=612",
                            1)

    syscall_10 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "31971 16:15:08.028039855 1 101 nginx 22454 > sendfile fd=13(<4t>172.17.0.1:45440->172.17.0.5:8080) offset=613 size=612",
                             1)

    syscall_11 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "31971 16:15:08.028039855 1 101 nginx 22454 > sendfile offset=613 size=612",
                             1)

    syscall_12 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "31971 16:15:08.028039855 1 101 nginx 22454 > sendfile fd=13(<4t>172.17.0.1:45440->172.17.0.5:8080) offset=613 size=612",
                             1)

    syscall_13 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "10832 19:07:21.859231950 5 0 gs 749 > mmap addr=0 length=237568 prot=3(PROT_READ|PROT_WRITE) flags=10(MAP_PRIVATE|MAP_ANONYMOUS) fd=-1(EPERM) offset=0",
                             1)

    syscall_14 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "157462 19:08:39.730662843 0 0 python3 7839 > close fd=5(<p>)",
                             1)

    syscall_15 = Syscall2019('CVE-2017-7529/microscopic_cocks_8401.txt',
                             "126960 19:30:31.111336634 5 0 gs 5666 > read fd=9 size=4096",
                             1)

    fd = FileDescriptor(mode=FDMode.Content)

    # print(fd_content.get_result(syscall_1))
    # print(fd_content.get_result(syscall_2))

    assert fd.get_result(syscall_1) == ('/proc/sys/kernel/ngroups_max',)

    assert fd.get_result(syscall_2) == ('172.17.0.1:36368', '172.17.0.3:3306')

    assert fd.get_result(syscall_3) ==  ('/etc/nginx/html/images/dashboard_full_2.jpg', '172.21.0.3:50122', '172.21.0.7:80')

    assert fd.get_result(syscall_4) == None

    assert fd.get_result(syscall_5) == None

    assert fd.get_result(syscall_6) == ('fd',)

    assert fd.get_result(syscall_7) == ('EPERM',)

    assert fd.get_result(syscall_8) == ('/proc/sys/kernel/ngroups_max',)

    assert fd.get_result(syscall_9) == ('/tmp/nginx/5/77/42e5373cc524f2ebe558749ab23c7775', '172.17.0.1:45440', '172.17.0.5:8080')

    assert fd.get_result(syscall_10) ==  ('172.17.0.1:45440', '172.17.0.5:8080')

    assert fd.get_result(syscall_11) == None

    assert fd.get_result(syscall_12) == ('172.17.0.1:45440', '172.17.0.5:8080')

    assert fd.get_result(syscall_13) == ('EPERM',)

    assert fd.get_result(syscall_14) ==  ('',)

    assert fd.get_result(syscall_15) == None


"""
if __name__ == '__main__':
    test_filedescriptor()

    path = os.environ['LID_DS_BASE'] + '/LID-DS-2021'
    scenarios = os.listdir(path)

    substrings = ['<f>', '<d>', 'EPERM', '<4t>', '<p>']

    for scenario in scenarios:
        dataloader = dataloader_factory(os.environ['LID_DS_BASE'] + '/LID-DS-2021/' + scenario)

        for recording in tqdm(dataloader.validation_data()):
            for syscall in recording.syscalls():
                if 'fd' in syscall.params():
                    if not any(x in syscall.param('fd') for x in substrings):
                        print(syscall.syscall_line)
"""
