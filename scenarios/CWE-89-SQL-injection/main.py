import docker
import random
import sys
import urllib.request

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.sim import gen_schedule_wait_times
from lid_ds.core.image import StdinCommand, Image, ExecCommand


warmup_time = int(sys.argv[1])
recording_time = int(sys.argv[2])
is_exploit = int(sys.argv[3])
do_exploit = True
if is_exploit < 1:
    do_exploit = False

total_duration = warmup_time + recording_time
exploit_time = random.randint(int(recording_time * .3),
                              int(recording_time * .8))

min_user_count = 10
max_user_count = 25
user_count = random.randint(min_user_count, max_user_count)

wait_times = \
    [gen_schedule_wait_times(total_duration) for _ in range(user_count)]


def get_container_ip(container):
    """
    Returns the ip adress of the server container
    """
    client = docker.APIClient(base_url='unix://var/run/docker.sock')
    server_ip = \
        client.inspect_container(container.id)['NetworkSettings']['IPAddress']
    return server_ip


class SQLInjection(Scenario):
    victim_ip = ""

    def init_victim(self, container, logger):
        pass

    def wait_for_availability(self, container):
        global victim_ip
        try:
            victim_ip = get_container_ip(container)
            url = "http://" + victim_ip + "/login.php"
            print("checking... is victim ready?")
            with urllib.request.urlopen(url) as response:
                data = response.read().decode("utf8")
                if "Login :: Damn Vulnerable Web Application" in data:
                    print("is ready...")
                    return True
                else:
                    print("not ready yet...")
                    return False
        except Exception:
            print("not ready yet...")
            return False


storage_services = [JSONFileStorage()]


victim = Image('victim_injection')
exploit = Image("exploit_injection",
                command=ExecCommand("sh exploit.sh ${victim}"))
normal = Image("normal_injection",
               command=StdinCommand(""),
               init_args="-ip ${victim} -v")


if do_exploit:
    scenario_normal = SQLInjection(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time
    )
else:
    scenario_normal = SQLInjection(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services
    )

scenario_normal()
