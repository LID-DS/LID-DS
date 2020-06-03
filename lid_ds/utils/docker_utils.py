from lid_ds.core.objects.environment import ScenarioEnvironment


def get_host_port(container, port, protocol="tcp"):
    container.reload()
    return int(container.ports['%s/%s' % (str(port), protocol)][0]['HostPort'])


def format_command(command):
    env = ScenarioEnvironment()
    replaces = {
        'victim': env.victim_hostname,
    }
    for k, replace in replaces.items():
        command = command.replace("${%s}" % k, replace)
    return command