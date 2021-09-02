import sys
import random
import urllib

from lid_ds.core import Scenario
from lid_ds.sim import gen_schedule_wait_times, Sampler
from lid_ds.utils.docker_utils import get_ip_address
from lid_ds.core.image import StdinCommand, Image
from lid_ds.core.collector.json_file_store import JSONFileStorage


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
                if "OWASP Juice Shop" in data:
                    print("is ready...")
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
    do_exploit = int(sys.argv[3])
    attack = ""
    attacks = ["SQLInjectionUser", "SQLInjectionSchema", "SQLInjectionCred"]
    if do_exploit:
        try:
            attack = sys.argv[4]
            if attack not in attacks:
                print("Please choose Attack as 4th parameter")
                print("Possible attacks: SQLInjectionCred, \
                       SQLInjectionSchema, \
                       SQLInjectionUser")
                sys.exit()

        except IndexError:
            print("Please choose Attack as 4th parameter")
            print("Possible attacks: SQLInjectionCred, \
                   SQLInjectionSchema, \
                   SQLInjectionUser")
            sys.exit()
    if do_exploit < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3),
                                      int(recording_time * .8)) if recording_time != -1 else random.randint(5, 15)

    user_count = 2

    if not do_normal:
        wait_times = {}
    elif recording_time == -1:
        # 1800s = 5hrs -> normal behaviour needs to be generated for a long time until exploit ends
        wait_times = Sampler("Jul95").timerange_sampling(user_count, 1800)
    else:
        wait_times = Sampler("Jul95").timerange_sampling(user_count, recording_time)

    storage_services = [JSONFileStorage()]

    # use specific version
    victim = Image("bkimminich/juice-shop:v10.0.0")
    exploit = Image("exploit_juice",
                    command=StdinCommand(""),
                    init_args="-ip ${victim} -a " + f"{attack} -v 1")
    normal = Image("normal_juice",
                   command=StdinCommand(""),
                   init_args="-ip ${victim} -v 1")

    juice_scenario = Juice(
        victim=victim,
        normal=normal,
        exploit=exploit,
        wait_times=wait_times,
        warmup_time=3,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time,
        exploit_name=attack
    )
    juice_scenario()
