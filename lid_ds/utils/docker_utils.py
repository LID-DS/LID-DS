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


def extract_resource_usage(container):
    data = container.stats(decode=False, stream=False)
    cpu_usage = data["cpu_stats"]["cpu_usage"]["total_usage"]
    memory_usage = data["memory_stats"]["usage"]
    network_received = data["networks"]["eth0"]["rx_bytes"]
    network_send = data["networks"]["eth0"]["tx_bytes"]
    storage_read = None
    storage_written = None

    storage_objects = data["blkio_stats"]["io_service_bytes_recursive"]
    for obj in storage_objects:
        if obj["op"] == "Read":
            storage_read = obj["value"]
        if obj["op"] == "Write":
            storage_written = obj["value"]
    return cpu_usage, memory_usage, network_received, network_send, storage_read, storage_written
