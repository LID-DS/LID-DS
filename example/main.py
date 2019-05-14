import sys
import json
import base64
import random
import subprocess

import pymysql

from requests.auth import HTTPBasicAuth
from lid_ds.core import Scenario
from lid_ds.sim import Behaviour

warmup_time = int(sys.argv[1])
recording_time = int(sys.argv[2])
total_duration = warmup_time + recording_time
exploit_time = random.randint(int(recording_time * .3), int(recording_time * .8))
print("Exploit time : {}".format(str(exploit_time)))


db_name = "textDB"
min_user_count = 10
max_user_count = 25
user_count = random.randint(min_user_count, max_user_count)

words = open('./words.txt').read().splitlines()
print(len(words))
host = "localhost"

class CVE_2012_2122(Scenario):
    def exploit(self, container):
        subprocess.Popen(r'''#!/bin/bash
                for i in `seq 1 1000`;
                do
                    mysql -uroot -pwrong -h 127.0.0.1 -P3306 2>/dev/null;
                done''', shell=True, executable='/bin/bash')

    def wait_for_availability(self, container):
        try:
            db = pymysql.connect(host, "root", "123456")
        except Exception:
            print('MySQL Server is still down!')
            return False
        print('MySQL server is up - we can start simulating users!')
        return True


class MySQLUser(Behaviour):
    def __init__(self, host, uname, passwd, rec_time):
        super().__init__([], rec_time)
        self.host = host
        self.uname = uname
        self.passwd = passwd
        self.actions.append(self._init_normal)
        print("Behavior with actions: " + str(len(self.wait_times)))
        for wt in self.wait_times[1:]:
            self.actions.append(self.do_normal)

    def _init_normal(self):
        try:
            self.db = pymysql.connect(self.host, self.uname, self.passwd)
            try:
                self.db.cursor().execute('create database ' + db_name)
            except:
                pass

            self.db = pymysql.connect(self.host, self.uname, self.passwd, db_name)
            sql = """CREATE TABLE `texts` (
                         `id` int(11) NOT NULL AUTO_INCREMENT, 
                         `text` varchar(255) COLLATE utf8_bin NOT NULL, 
                         PRIMARY KEY (`id`)
                     ) 
                     ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin 
                     AUTO_INCREMENT=1 ;"""
            self.db.cursor().execute(sql)
        except Exception as e:
            pass

    def do_normal(self):
        try:
            if random.random() > 0.5:
                word = random.choice(words).replace("'", "")
                sql = "INSERT INTO `texts` (`text`) VALUES ('" + word + "');"
                print("Insert: " + word )
                with self.db.cursor() as cursor:
                    self.db.begin()
                    cursor.execute(sql)
                self.db.commit()
            else:
                sql = "SELECT * FROM `texts` ORDER BY RAND() LIMIT 1"
                with self.db.cursor() as cursor:
                    cursor.execute(sql)
                result = cursor.fetchone()
                print("Got: " + result[1])
        except Exception as e:
            print("Exception: " + str(e))
            
   	    #sys.exit()
            #try:
            #    self.db = pymysql.connect(self.host, self.uname, self.passwd, db_name)
            #except:


behaviours = []
for i in range(user_count):
    behaviours.append(MySQLUser("localhost", "root", "123456", recording_time))

scenario_normal = CVE_2012_2122(
    'vulhub/mysql:5.5.23',
    port_mapping={
        '3306/tcp': 3306
    },
    warmup_time=warmup_time,
    recording_time=recording_time,
    behaviours=behaviours,
    exploit_start_time=exploit_time
)
scenario_normal()

"""
scenario_exploit = CVE_2012_2122(
    'vulhub/mysql:5.5.23',
    port_mapping={
        '3306/tcp': 3306
    },
    warmup_time=warmup_time,
    recording_time=recording_time,
    behaviours=behaviours,
    exploit_start_time=exploit_time  # Comment this line if you don't want the exploit to be executed
)
scenario_exploit()
"""
