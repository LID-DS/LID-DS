import sys
import random
import requests
from couchdb_example.victim.init import init
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
exploit_time = random.randint(int(recording_time * .3),
                              int(recording_time * .5))

min_user_count = 10
max_user_count = 25
user_count = random.randint(min_user_count, max_user_count)


class CouchDBChain(Scenario):
    def init_victim(self, container, logger):
        init("localhost:%s" % get_host_port(container, "5984"), logger)

    def wait_for_availability(self, container):
        try:
            return requests.get("http://localhost:%s" % get_host_port(container, "5984")).status_code == 200
        except Exception as e:
            return False


storage_services = [JSONFileStorage()]

victim = Image('vulhub/couchdb:2.1.0')
exploit = Image("exploit_couchdb", command="sh /app/hydra.sh ${victim}")
normal = Image("normal_couchdb",
               command=StdinCommand(""),
               init_args="${victim}:5984")

if do_exploit:
    scenario_normal = CouchDBChain(
        victim=victim,
        normal=normal,
        exploit=exploit,
        user_count=1,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time)
else:
    scenario_normal = CouchDBChain(
        victim=victim,
        normal=normal,
        exploit=exploit,
        user_count=1,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services)

scenario_normal()
