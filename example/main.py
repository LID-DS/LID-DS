import requests
import sys
import json
import base64
import random
import subprocess

import pymysql

from requests.auth import HTTPBasicAuth
from lid_ds.core import Scenario
from lid_ds.sim import Behaviour

warmt = int(sys.argv[1])
rect = int(sys.argv[2])

min_user_count = 10
max_user_count = 25
user_count = random.randint(min_user_count, max_user_count)

total_duration = warmt+rect
warmup_time = warmt
exploit_time = random.randint(int(rect * .3), int(rect * .8))
print("Exploit time : {}".format(str(exploit_time)))

class CVE_2012_2122(Scenario):
    def exploit(self, container):
        subprocess.Popen(r'''#!/bin/bash
                for i in `seq 1 1000`;
                do
                    mysql -uroot -pwrong -h 127.0.0.1 -P3306 ;
                done''', shell=True, executable='/bin/bash')

    def wait_for_availability(self, container):
        try:
            db = pymysql.connect("localhost", "root", "123456")
        except Exception:
            print('MySQL Server is still down!')
            return False
        print('MySQL server is up - we can start simulating users!')
        return True

class MySQLUser(Behaviour):
    def __init__(self, host, uname, passwd, total_duration):
        super().__init__([], total_duration)
        self.host = host
        self.uname = uname
        self.passwd = passwd
        self.actions.append(self._init_normal)
        for wait_time in self.wait_times[1:]:
            self.actions.append(self.do_normal)

    def _init_normal(self):
        try:
            self.db = pymysql.connect("localhost", uname, passwd)
            try:
                self.db.cursor().execute('create database testdb')
            except Exception as e:
                print(e)
            self.db = pymysql.connect("localhost", uname, passwd, "testdb")
        except:
            pass

    def do_normal(self):
        try:
            pass
        except Exception as Error:
            pass
            #print(Error)

behaviours = []
for i in range(user_count):
    duration = random.random() * total_duration
    behaviours.append(MySQLUser("localhost", "root", "123456", total_duration * (i/user_count)))
    print('creating {}.th user with duration: {}'.format(i, duration))

scenario = CVE_2012_2122(
        'vulhub/mysql:5.5.23',
        port_mapping={
            '3306/tcp' : 3306
        },
        warmup_time=warmup_time,
        recording_time=(total_duration-warmup_time),
        behaviours=behaviours,
        exploit_start_time=exploit_time # Comment this line if you don't want the exploit to be executed
    )
scenario()
