import docker
import random
import sys
import urllib.request

from lid_ds.core import Scenario
from lid_ds.sim import Behaviour
from lid_ds.core.image import StdinCommand, Image, ExecCommand

target_port = "9200"
imagename_victim = "sql_victim:latest"
imagename_client = "sql_client:latest"
imagename_attacker = "sql_attacker:latest"
victim_ip = ""


def get_container_ip(container):
    """
    Returns the ip adress of the server container
    """
    client = docker.APIClient(base_url='unix://var/run/docker.sock')
    server_ip = client.inspect_container(container.id)['NetworkSettings']['IPAddress']
    return server_ip


class SQLInjection(Scenario):

    def __init__(self,
                 image_name,
                 port_mapping={},
                 warmup_time=60,
                 recording_time=300,
                 behaviours=[],
                 **kwargs):
        super().__init__(image_name,
                         port_mapping,
                         warmup_time,
                         recording_time,
                         behaviours, **kwargs)
        self.user = kwargs.get('user')
        self.pwd = kwargs.get('pwd')
        self.attack_container = None

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

    def exploit(self, container):
        """ start exploit """
        global victim_ip
        try:
            client = docker.from_env()
            self.attack_container = client.containers.run(imagename_attacker,
                                                          detach=True,
                                                          name="attacker_1337",
                                                          stdin_open=True,
                                                          tty=True)
            print("start container for user: " + self.user)
            command = 'sh -c \'python3 /home/attacker.py' \
                      + ' -ip ' + victim_ip \
                      + ' -u ' + self.user \
                      + ' -p ' + self.pwd \
                      + ' > py.log 2>&1\''
            self.attack_container.exec_run(command, detach=True)
            print("start attack behaviour on attacker_1337 with command: ")
            print(command)
        except Exception as error:
            print(error)


class SQLBehaviour(Behaviour):

    def __init__(self, warmup, recording, user, pwd):
        self.wait_times = [1]
        self.actions = [self.do_normal]
        self.runningtime = warmup + recording
        self.user = user
        self.pwd = pwd
        self.container = None

    def do_normal(self):
        """ starts a client """
        global victim_ip
        print("starting normal behaviour...")
        try:
            client = docker.from_env()
            self.container = client.containers.run(imagename_client,
                                                   detach=True,
                                                   name=self.user,
                                                   stdin_open=True,
                                                   tty=True)
            print('start container for user: ' + self.user)
            command = 'sh -c \'python3 /home/client.py' \
                      + ' -ip ' + victim_ip \
                      + ' -u ' + self.user \
                      + ' -p ' + self.pwd \
                      + ' > py.log 2>&1\''
            self.container.exec_run(command, detach=True)
            print('start normal behaviour on client '
                  + self.user
                  + ' with command: ')
            print(command)
        except Exception as error:
            print(error)


victim = Image('victim_injection')
exploit = Image("exploit_injection",
                command=ExecCommand("sh exploit.sh ${victim}"))
normal = Image("normal_injection",
               command=StdinCommand(""),
               init_args="-ip ${victim} -u user -p 123456")

#####################################################
warmup_time = int(sys.argv[1])
recording_time = int(sys.argv[2])
is_exploit = int(sys.argv[3])
do_exploit = True
if is_exploit < 1:
    do_exploit = False


exploit_time = random.randint(int(recording_time * .3),
                              int(recording_time * .8))

# logins for dvwa
logins = {}
logins["Admin"] = "password"
logins["gordonb"] = "abc123"
logins["pablo"] = "letmein"
logins["smithy"] = "password"
logins["1337"] = "charley"

behaviours = []

for user in logins.keys():
    behaviours.append(SQLBehaviour(warmup_time,
                                   recording_time,
                                   user,
                                   logins[user]))

if do_exploit:
    scenario = SQLInjection(
        imagename_victim,
        port_mapping={
        },
        warmup_time=warmup_time,
        recording_time=recording_time,
        behaviours=behaviours,
        exploit_start_time=exploit_time,
        user="1337",
        pwd=logins["1337"]
    )
else:
    scenario = SQLInjection(
        imagename_victim,
        port_mapping={
        },
        warmup_time=warmup_time,
        recording_time=recording_time,
        behaviours=behaviours,
        user="1337",
        pwd=logins["1337"]
    )

scenario()
# Removes all client and attacker containers
try:
    print('removing clients')
    for b in behaviours:
        print('removing client: ' + b.user)
        b.container.remove(force=True)
    if scenario.attack_container is not None:
        print('removing attacker: ' + scenario.attack_container.name)
        scenario.attack_container.remove(force=True)
except Exception as error:
    print(error)
