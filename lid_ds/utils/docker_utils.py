import csv
import os
import subprocess
from datetime import datetime
from threading import Thread

from lid_ds.core.objects.environment import ScenarioEnvironment


def get_host_port(container, port, protocol="tcp"):
    container.reload()
    return int(container.ports[f'{port}/{protocol}'][0]['HostPort'])


def get_ip_address(container):
    container.reload()
    return container.attrs['NetworkSettings']['Networks'][ScenarioEnvironment().network.name]['IPAddress']


def get_pid_namespace(container):
    container.reload()
    pid = container.attrs["State"]["Pid"]
    pid_ns = os.popen(f"lsns -n -t pid -o NS -p {pid}").read()
    return pid_ns


def format_command(command):
    env = ScenarioEnvironment()
    replaces = {
        'victim': env.victim_hostname,
    }
    for k, replace in replaces.items():
        command = command.replace("${%s}" % k, replace)
    return command


def calc_cpu_usage(pre_cpu, pre_sys_cpu, cpu, sys_cpu):
    percent = 0.0
    cpu_delta = cpu - pre_cpu
    sys_cpu_delta = sys_cpu - pre_sys_cpu
    if sys_cpu_delta > 0.0 and cpu_delta > 0.0:
        percent = (cpu_delta / sys_cpu_delta) * 100.0
    return percent


def diff_or_none(a, b):
    if a and b:
        return a - b
    else:
        return "NULL"


class ResourceLoggingThread(Thread):
    def __init__(self, container):
        super().__init__()
        self._container = container
        self._running = True

    def stop_it(self):
        self._running = False

    def run(self):
        data = self._container.stats(decode=False, stream=False)
        num_cpu = data["cpu_stats"]["online_cpus"]
        resources = []
        for data in self._container.stats(decode=True, stream=True):
            # should this thread end?
            if not self._running:
                # yes:
                # write to file
                with open(os.path.join(ScenarioEnvironment().out_dir, ScenarioEnvironment().recording_name + ".res"),
                          "w") as file:
                    header = ["timestamp", "cpu_usage", "memory_usage", "network_received", "network_send",
                              "storage_read", "storage_written"]
                    csv_writer = csv.writer(file)
                    csv_writer.writerow(header)
                    last = None
                    for current in resources:
                        if last is not None:
                            output = list()
                            # timestamp
                            output.append(current[0])
                            # cpu usage in percent
                            output.append(calc_cpu_usage(last[1], last[2], current[1], current[2]))
                            # mem
                            output.append(current[3])
                            # net rec
                            output.append(diff_or_none(current[4], last[4]))
                            # net sent
                            output.append(diff_or_none(current[5], last[5]))
                            # storage read
                            output.append(diff_or_none(current[6], last[6]))
                            # storage write
                            output.append(diff_or_none(current[7], last[7]))
                            # write to file
                            csv_writer.writerow(output)
                        last = current
                # end the thread
                return
            else:
                # log resources
                timestamp = data["read"]
                # 2021-04-22T12:14:40.944559557Z
                timestamp = timestamp[:23]
                # 2021-04-22T12:14:40.944
                timestamp = datetime.fromisoformat(timestamp)
                timestamp = (timestamp - datetime(1970, 1, 1)).total_seconds()
                cpu_usage = data["cpu_stats"]["cpu_usage"]["total_usage"]
                cpu_system_usage = data["cpu_stats"]["system_cpu_usage"]
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
                resources.append(
                    [timestamp, cpu_usage, cpu_system_usage, memory_usage, network_received, network_send, storage_read,
                     storage_written])
