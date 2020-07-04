import sys
import random
import subprocess

import pymysql

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.core.image import StdinCommand, Image
from lid_ds.utils.docker_utils import get_host_port

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
    def init_victim(self, container, logger):
        port = get_host_port(container, "3306")
        try:
            db = pymysql.connect("localhost", "root", "123456", port=port)
            try:
                db.cursor().execute('create database ' + "textDB")
            except:
                pass

            self.db = pymysql.connect("localhost", "root", "123456", "textDB", port)
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
            db = pymysql.connect("localhost", "root", "123456", port=get_host_port(container, "3306"))
        except Exception as e:
            return False
        return True


storage_services = [JSONFileStorage()]

victim = Image('vulhub/mysql:5.5.23')
exploit = Image("exploit_mysql", command="sh /app/nmap.sh ${victim}")
normal = Image("normal_mysql", command=StdinCommand(""), init_args="${victim} root 123456")

if do_exploit:
    scenario_normal = CVE_2012_2122(
        victim=victim,
        normal=normal,
        exploit=exploit,
        user_count=1,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time
    )
else:
    scenario_normal = CVE_2012_2122(
        victim=victim,
        normal=normal,
        exploit=exploit,
        user_count=1,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
    )

scenario_normal()
