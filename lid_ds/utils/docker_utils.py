from lid_ds.core.objects.environment import ScenarioEnvironment


def get_host_port(container, port, protocol="tcp"):
    container.reload()
    return int(container.ports[f'{port}/{protocol}'][0]['HostPort'])


def get_ip_address(container):
    container.reload()
    return container.attrs['NetworkSettings']['Networks'][ScenarioEnvironment().network.name]['IPAddress']


def format_command(command):
    env = ScenarioEnvironment()
    replaces = {
        'victim': env.victim_hostname,
    }
    for k, replace in replaces.items():
        command = command.replace("${%s}" % k, replace)
    return command
