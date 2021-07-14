import sys
import random
import urllib

from lid_ds.core import Scenario
from lid_ds.sim import gen_schedule_wait_times
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
        return True


if __name__ == '__main__':
    warmup_time = int(sys.argv[1])
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
            print("Please choose Attack as 4th parameter")
            print("Possible attacks: SQLInjectionCred, \
                   SQLInjectionSchema, \
                   SQLInjectionUser")
            sys.exit()
    if do_exploit < 1:
        exploit_time = 0
    else:
        exploit_time = random.randint(int(recording_time * .3),
                                      int(recording_time * .8))
    total_duration = warmup_time + recording_time

    min_user_count = 2
    max_user_count = 4
    user_count = random.randint(min_user_count, max_user_count)

    wait_times = [gen_schedule_wait_times(total_duration) for _ in range(user_count)]

    storage_services = [JSONFileStorage()]

    # use specific version
    victim = Image("bkimminich/juice-shop")
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
        warmup_time=warmup_time,
        recording_time=recording_time,
        storage_services=storage_services,
        exploit_start_time=exploit_time,
        exploit_name=attack
    )
    juice_scenario()
