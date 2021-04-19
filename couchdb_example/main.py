import sys
import random
import requests
from victim.init import init
from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.core.image import StdinCommand, Image, ChainImage, ExecCommand
from lid_ds.postprocessing.tcpdump import TCPPacketPartsMatcher
from lid_ds.sim.sampler import Sampler
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

wait_times = Sampler("Jul95").extraction_sampling(total_duration)

full_chain = int(sys.argv[4]) > 1


class CouchDBChain(Scenario):
    def init_victim(self, container, logger):
        init("localhost:%s" % get_host_port(container, "5984"), logger, full_chain)

    def wait_for_availability(self, container):
        try:
            return requests.get("http://localhost:%s" % get_host_port(container, "5984")).status_code == 200
        except Exception as e:
            return False


storage_services = [JSONFileStorage()]

victim = Image('vulhub/couchdb:2.1.0')

# Attack steps

portscan = ExecCommand("sh /app/nmap.sh ${victim}", name="port-scan")

bruteforce = ExecCommand("sh /app/hydra.sh ${victim}", name="brute-force",
                         after_packet=TCPPacketPartsMatcher(["GET /", "User-Agent: curl"],
                                                            forbidden_parts=["Authorization"]))

privilege_escalation = ExecCommand("python3 /app/exploit.py ${victim}:5984", name="privilege-escalation",
                                   after_packet=TCPPacketPartsMatcher(["GET /", "User-Agent: curl"],
                                                                      forbidden_parts=["Authorization"]))

privilege_escalation_full = ExecCommand("python3 /app/exploit.py ${victim}:5984", name="privilege-escalation",
                                   after_packet=TCPPacketPartsMatcher(["GET /_all_dbs", "User-Agent: curl",
                                                                       "Authorization"]))
remote_code = ExecCommand("python3 /app/reverse-shell.py ${victim}:5984", name="remote-code",
                          after_packet=TCPPacketPartsMatcher(["GET /_users/_all_docs",
                                                              "Authorization"]))

# Szenarios

exploit_full = ChainImage("exploit_couchdb",
                          commands=[portscan, bruteforce, privilege_escalation_full, remote_code])

exploit_short = ChainImage("exploit_couchdb",
                           commands=[portscan,
                                     privilege_escalation,
                                     remote_code,
                                     ])

normal = Image("normal_couchdb",
               command=StdinCommand(""),
               init_args="${victim}:5984")

if do_exploit:
    scenario_normal = CouchDBChain(
        victim=victim,
        normal=normal,
        exploit=exploit_full if full_chain else exploit_short,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time)
else:
    scenario_normal = CouchDBChain(
        victim=victim,
        normal=normal,
        exploit=exploit_full if full_chain else exploit_short,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services)

scenario_normal()
