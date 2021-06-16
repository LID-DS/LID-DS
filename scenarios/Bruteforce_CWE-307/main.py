import sys
import random
import urllib.request

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.core.image import StdinCommand, Image
from lid_ds.sim import gen_schedule_wait_times
from lid_ds.utils.docker_utils import get_ip_address


class Bruteforce_CWE_307(Scenario):

    def init_victim(self, container, logger):
        pass

    def wait_for_availability(self, container):
        try:
            victim_ip = get_ip_address(container)
            url = "http://" + victim_ip + "/private/index.html"
            print("checking... is victim ready?")
            with urllib.request.urlopen(url) as response:
                data = response.read().decode("utf8")
                if "Simple Web App" in data:
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
    warmup_time = int(sys.argv[1])
    recording_time = int(sys.argv[2])
    do_exploit = int(sys.argv[3])
    if do_exploit < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3), int(recording_time * .8))

    min_user_count = 10
    max_user_count = 25
    user_count = random.randint(min_user_count, max_user_count)

    wait_times = [gen_schedule_wait_times(recording_time) for _ in range(user_count)]

    storage_services = [JSONFileStorage()]
    post_freq = "20"

    victim = Image("victim_bruteforce")
    normal = Image("normal_bruteforce", command=StdinCommand(""), init_args="-ip ${victim} -post " + str(post_freq))
    exploit = Image("exploit_bruteforce", command=StdinCommand(""), init_args="${victim}")

    bruteforce_scenario = Bruteforce_CWE_307(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time
    )
    bruteforce_scenario()
