import sys
import random
import urllib.request

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.core.image import StdinCommand, Image, ExecCommand
from lid_ds.sim import gen_schedule_wait_times, Sampler
from lid_ds.utils.docker_utils import get_ip_address

class EPS_CWE_434(Scenario):

    def init_victim(self, container, logger):
        pass

    def wait_for_availability(self, container):
        try:
            victim_ip = get_ip_address(container)
            url = "http://" + victim_ip + ":8000"
            print("checking... is victim ready?")
            with urllib.request.urlopen(url) as response:
                data = response.read().decode("utf8")
                if "Directory listing for " in data:
                    print("is ready...")
                    print("configuring and creating clients...")
                    return True
                else:
                    print("not ready yet...")
                    return False
        except Exception as error:
            print("not ready yet with error: " + str(error))
            return False

if __name__ == '__main__':
    do_normal = bool(int(sys.argv[1]))
    recording_time = int(sys.argv[2])
    is_exploit = int(sys.argv[3])

    if is_exploit < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3),
                                      int(recording_time * .8)) if recording_time != -1 else random.randint(5, 15)
    min_user_count = 10
    max_user_count = 15
    user_count = random.randint(min_user_count, max_user_count)

    if not do_normal:
        wait_times = {}
    elif recording_time == -1:
        # 1800s = 5hrs -> normal behaviour needs to be generated for a long time until exploit ends
        wait_times = Sampler("Aug28").ip_timerange_sampling(user_count, 1800)
    else:
        wait_times = Sampler("Aug28").ip_timerange_sampling(user_count, recording_time, 5)

    storage_services = [JSONFileStorage()]

    victim = Image("victim_eps")
    normal = Image("normal_eps", command=StdinCommand(""), init_args="-ip ${victim}")
    exploit = Image("exploit_eps", command=ExecCommand("python3 /home/exploit.py -ip ${victim}"))

    eps_scenario = EPS_CWE_434(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=3,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time)
    eps_scenario()
