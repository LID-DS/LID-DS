import sys
import random
import urllib
import pymysql

from lid_ds.core import Scenario
from lid_ds.core.collector.json_file_store import JSONFileStorage
from lid_ds.core.image import StdinCommand, Image, ExecCommand
from lid_ds.sim.sampler import Sampler
from lid_ds.utils.docker_utils import get_ip_address


class Juice(Scenario):
    def init_victim(self, container, logger):
        pass

    def wait_for_availability(self, container):
        try:
            victim_ip = get_ip_address(container)
            url = "http://" + victim_ip + ":3000/"
            print(f"checking {url}... is victim ready?")
            with urllib.request.urlopen(url) as response:
                data = response.read().decode("utf8")
                print(data)
                if "Ruby" in data:
                    print("is ready...")
                    return True
                else:
                    print("not ready yet...")
                    return False
        except Exception as error:
            print("not ready yet with error: " + str(error))
            return False
        return True


if __name__ == '__main__':
    warmup_time = int(sys.argv[1])
    recording_time = int(sys.argv[2])
    do_exploit = int(sys.argv[3])
    if do_exploit < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3),
                                      int(recording_time * .8))
    total_duration = warmup_time + recording_time

    min_user_count = 10
    max_user_count = 25
    user_count = random.randint(min_user_count, max_user_count)

    wait_times = Sampler("Jul95").extraction_sampling(total_duration)

    storage_services = [JSONFileStorage()]

    victim = Image('bkimminich/juice-shop')
    # exploit = Image("exploit_mysql",
    # command=ExecCommand("sh exploit.sh ${victim}"))
    exploit = None
    normal = Image("normal_juice",
                   command=StdinCommand(""),
                   init_args="${victim}")

    juice_scenario = Juice(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time
    )
    juice_scenario()
