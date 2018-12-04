from lidds import Simulator, LIDArgparser
import docker
from time import sleep

parser = LIDArgparser()
args = parser.parse_args()

config = vars(args)
config["portMapping"] = {
    '9200/tcp': 9200
}
config["imagename"] = "sql_victim:latest"
config["imagename_client"] = "sql_client:latest"

# List of all client containers
client_containers = []

# logins for dvwa
logins = {}
logins["Admin"] = "password"
logins["gordonb"] = "abc123"
logins["1337"] = "charley"
logins["pablo"] = "letmein"
logins["smithy"] = "password"


def initHook(container, resolve, reject):
    """
    start client containers
    """
    try:
        client = docker.from_env()
        for username in logins.keys():
            container = client.containers.run(config["imagename_client"], detach=True, name=username, stdin_open=True,
                                              tty=True)
            client_containers.append(container)
            print('start client for user: ' + username)
        resolve(None)
    except Exception as error:
        reject(error)


def normalBehavior(container):
    """
    Executes the client simulation on each client container
    """
    server_ip = __getContainerIp(container)
    for client in client_containers:
        command = 'sh -c \'python3 /home/client.py' \
                  + ' -ip ' + server_ip \
                  + ' -u ' + client.name \
                  + ' -p ' + logins[client.name] \
                  + ' > py.log 2>&1\''
        client.exec_run(command, detach=True)
        print('start normal behaviour on client ' + client.name + ' with command: ')
        print(command)


def __getContainerIp(container):
    """
    Returns the ip adress of the server container
    """
    client = docker.APIClient(base_url='unix://var/run/docker.sock')
    server_ip = client.inspect_container(container.id)['NetworkSettings']['IPAddress']
    return server_ip


def exploit(container):
    sleep(1)


def terminateHook(resolve, reject):
    """
    Removes all client containers
    """
    try:
        print('removing clients')
        for client in client_containers:
            print('removing client: ' + client.name)
            client.remove(force=True)
        resolve(None)
    except Exception as error:
        reject(error)


simulator = Simulator(config)
simulator.registerInitHook(initHook)
simulator.registerNormalBehaviour(normalBehavior)
simulator.registerExploit(exploit)
simulator.registerTerminateHook(terminateHook)
simulator.startSimulation()
