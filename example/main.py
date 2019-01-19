import requests

from lid_ds.core import Scenario
from lid_ds.sim import Behaviour

class NginxScenario(Scenario):
    def exploit(self, container):
        print('hello i wanted to exploit {}'.format(container))

    def wait_for_availability(self, container):
        return True


total_duration = 100
warmup_time = 20

def getAction(i):
    def action():
        r = requests.get('localhost:80')
        r.json()
        print('hello this is A {}'.format(str(i)))

    return action

def getBction(i):
    def action():
        print('hello this is B {}'.format(str(i)))

    return action

actions = []
for i in range(50):
    actions.append(getAction(i))

behaviour1 = Behaviour(actions, total_duration)

actions = []
for i in range(50):
    actions.append(getBction(i))

behaviour2 = Behaviour(actions, total_duration)

behaviours = [behaviour1, behaviour2]

scenario = NginxScenario(
    'nginx_lidds',
    port_mapping={
        '80/tcp':80
    },
    warmup_time=warmup_time,
    recording_time=(total_duration-warmup_time),
    behaviours=behaviours
    )
scenario()