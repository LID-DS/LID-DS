from algorithms.features.impl.return_value import ReturnValue
from dataloader.syscall_2019 import Syscall2019 as Syscall
from dataloader.syscall_2021 import Syscall2021


def test_return_value():
    syscall_1 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19965 10:24:48.091933080 6 33 apache2 1461 < open fd=13(<f>/dev/urandom) name=/dev/urandom flags=4097(O_RDONLY|O_CLOEXEC) mode=0')
    syscall_2 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19967 10:24:48.091958326 6 33 apache2 1461 < read res=512 data=`...4..6...v$P..B..._8 .D...j6.5.$....:.Z0....*.M.@.&.".M.aK..+%.>.s....N=i(X...')
    syscall_3 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19969 10:24:48.092021576 6 33 apache2 1461 < close res=0')
    syscall_4 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19971 10:24:48.092081831 6 33 apache2 1461 < fcntl res=2(<f>/var/log/apache2/error.log)')
    syscall_5 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19973 10:24:48.092086950 6 33 apache2 1461 < fcntl res=0(<f>/dev/pts/0)')
    syscall_6 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19975 10:24:48.092161111 6 33 apache2 1461 < read res=206 data=...................j.-.xV:..qhFg...F.........\\..0.+./...................$.(....')
    syscall_7 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19976 10:24:48.092470998 1 33 apache2 4153 < semop res=0 nsops=1 sem_num_0=0 sem_op_0=-1 sem_flg_0=2(SEM_UNDO) sem_num_1=0 sem_op_1=0 sem_flg_1=0')
    syscall_8 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19980 10:24:48.100611695 6 33 apache2 1461 < writev res=1525 "data=....5...1..\\.o...;...(......?..M....3...QC............#.................0...0.."')
    syscall_9 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                        '19983 10:24:48.104166132 3 33 apache2 1461 < poll res=1 fds=12:41')
    syscall_10 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19985 10:24:48.104191152 3 33 apache2 1461 < read res=190 "data=............4..5e`=...go..ek.ef>gP~.}btL#.......x|p.......DW...o`.....A...8..2."')
    syscall_11 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19987 10:24:48.107961648 3 33 apache2 1461 < writev res=258 data=...............j......I.}.b...f.?).....0.lA......X...h.....1z..!+.........f.~26')
    syscall_12 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19990 10:24:48.108743795 3 33 apache2 1461 < poll res=1 fds=12:41')
    syscall_13 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19992 10:24:48.108761998 3 33 apache2 1461 < read res=335 data=....Jp...7...tq.X...8........9C.v.B.......@....B.|rYF....R.}...>......b.l?}x/..-')
    syscall_14 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19994 10:24:48.108892314 3 33 apache2 1461 < stat res=0 path=/var/www/private/upload.php')
    syscall_15 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19996 10:24:48.108940616 3 33 apache2 1461 < open fd=-2(ENOENT) name=/var/www/private/.htaccess flags=4097(O_RDONLY|O_CLOEXEC) mode=0')
    syscall_16 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '19998 10:24:48.108958603 3 33 apache2 1461 < open fd=-20(ENOTDIR) name=/var/www/private/upload.php/.htaccess flags=4097(O_RDONLY|O_CLOEXEC) mode=0')
    syscall_17 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20000 10:24:48.109063501 3 33 apache2 1461 < open fd=13(<f>/etc/apache2/.htpasswd) name=/etc/apache2/.htpasswd flags=4097(O_RDONLY|O_CLOEXEC) mode=0')
    syscall_18 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20002 10:24:48.109078685 3 33 apache2 1461 < fstat res=0')
    syscall_19 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20004 10:24:48.109091028 3 33 apache2 1461 < read res=227 data=FUVSXW:$apr1$op6xtN3b$vaDs6F5DnMZ8sQRThkBNM/.HXUPXI:$apr1$OO6XOIe.$k0RuEZLlnnZBX')
    syscall_20 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20006 10:24:48.109105388 3 33 apache2 1461 < read res=-104(ECONNRESET)')
    syscall_21 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20008 10:24:48.110844264 3 33 apache2 1461 < writev res=-32(EPIPE)')
    syscall_22 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20010 10:24:48.110850315 3 33 apache2 1461 < recvmsg res=-11(EAGAIN)')
    syscall_23 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20012 10:24:48.110856014 3 33 apache2 1461 < sendfile res=-22(EINVAL)')
    syscall_24 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20014 10:24:48.111053057 3 33 apache2 1461 < poll res=1 fds=12:41')
    syscall_25 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '20016 10:24:48.111068240 3 33 apache2 1461 < read res=268 data=.....p..')
    syscall_26 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '4578 11:09:03.156969938 7 33 apache2 19902 < getdents res=576')
    syscall_27 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '4579 11:09:03.156979938 7 33 apache2 19902 < getdents res=570')
    syscall_28 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '10425 15:47:36.627360967 6 101 nginx 8184 < recvfrom res=118 data=GET / HTTP/1.1..Accept-Encoding: identity..User-Agent: Python-urllib/3.6..Host:  tuple=NULL')
    syscall_29 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '10454 15:47:36.663316131 6 101 nginx 8184 < recvfrom res=118 data=GET / HTTP/1.1..Accept-Encoding: identity..User-Agent: Python-urllib/3.6..Host:  tuple=NULL')
    syscall_30 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '38630 14:46:58.001251755 6 101 nginx 24055 < sendfile res=612 offset=1225')
    syscall_31 = Syscall('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                         '38659 14:46:58.017850228 6 101 nginx 24055 < sendfile res=400 offset=1225')

    syscall_32 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 write < res=10')
    syscall_33 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 write > addr=7FE7FC0011B8 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')
    syscall_34 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-1 31394 read < res=0')
    syscall_35 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-2 30532 read < res=5')
    syscall_36 = Syscall2021('CVE-2017-7529/test/normal_and_attack/acidic_bhaskara_7006.zip',
                            '1 0 30244 Process-2 30532 read > addr=7FE87C0D6F28 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1')

    syscalls = [
        syscall_1,
        syscall_2,
        syscall_3,
        syscall_4,
        syscall_5,
        syscall_6,
        syscall_7,
        syscall_8,
        syscall_9,
        syscall_10,
        syscall_11,
        syscall_12,
        syscall_13,
        syscall_14,
        syscall_15,
        syscall_16,
        syscall_17,
        syscall_18,
        syscall_19,
        syscall_20,
        syscall_21,
        syscall_22,
        syscall_23,
        syscall_24,
        syscall_25,
        syscall_26,
        syscall_27,
        syscall_28,
        syscall_29,
        syscall_30,
        syscall_31
    ]

    rv = ReturnValue()
    for syscall in syscalls:
        rv.train_on(syscall)


    
    assert rv._calculate(syscall_1) == 0
    assert rv._calculate(syscall_2) == 512/rv._max['read']
    assert rv._calculate(syscall_3) == 0
    assert rv._calculate(syscall_4) == -1
    assert rv._calculate(syscall_5) == -1
    assert rv._calculate(syscall_6) == 206/rv._max['read']
    assert rv._calculate(syscall_7) == 0
    assert rv._calculate(syscall_8) == 1525/rv._max['writev']
    assert rv._calculate(syscall_9) == 1
    assert rv._calculate(syscall_10) == 190/rv._max['read']
    assert rv._calculate(syscall_11) == 258/rv._max['writev']
    assert rv._calculate(syscall_12) == 1
    assert rv._calculate(syscall_13) == 335/rv._max['read']
    assert rv._calculate(syscall_14) == 0
    assert rv._calculate(syscall_15) == 0
    assert rv._calculate(syscall_16) == 0
    assert rv._calculate(syscall_17) == 0
    assert rv._calculate(syscall_18) == 0
    assert rv._calculate(syscall_19) == 227/rv._max['read']
    assert rv._calculate(syscall_20) == -1
    assert rv._calculate(syscall_21) == -1
    assert rv._calculate(syscall_22) == -1
    assert rv._calculate(syscall_23) == -1
    assert rv._calculate(syscall_24) == 1
    assert rv._calculate(syscall_25) == 268/rv._max['read']
    assert rv._calculate(syscall_26) == 576/rv._max['getdents']
    assert rv._calculate(syscall_27) == 570/rv._max['getdents']
    assert rv._calculate(syscall_28) == 118/rv._max['recvfrom']
    assert rv._calculate(syscall_29) == 118/rv._max['recvfrom']
    assert rv._calculate(syscall_30) == 612/rv._max['sendfile']
    assert rv._calculate(syscall_31) == 400/rv._max['sendfile']
    # Syscall2021
    assert rv._calculate(syscall_32) == -1  # write not in training data 
    assert rv._calculate(syscall_33) == 0 
    assert rv._calculate(syscall_34) == 0/rv._max['read']
    assert rv._calculate(syscall_35) == 5/rv._max['read']
    assert rv._calculate(syscall_36) == 0/rv._max['read']
