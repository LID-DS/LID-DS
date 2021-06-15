import collections
import os
import time
from datetime import datetime
import random

import dateutil.parser
import docker
from docker.models.containers import Container
from requests.exceptions import HTTPError


from lid_ds.utils import log

client = docker.from_env()
this_dir = os.path.dirname(os.path.realpath(__file__))


def run_image(image, network, name, port_mapping=None, command="", volumes=None, privileged=False) -> Container:
    network_name = network if isinstance(network, str) else network.name
    ports, publish_all = (None, True) if port_mapping == "all" else (port_mapping, False)
    container = client.containers.run(
        image,
        command=command,
        name=name,
        network=network_name,
        ports=ports,
        publish_all_ports=publish_all,
        volumes=volumes,
        detach=True,
        stdin_open=True,
        tty=True,
        remove=True,
        privileged=privileged)
    return container


def show_logs(container: Container, logger):
    last = datetime.fromtimestamp(1)
    last_lines = collections.deque(maxlen=500)
    while True:
        try:
            time.sleep(random.uniform(1.0, 2.0))
            for line in container.logs(timestamps=True, since=last).splitlines():
                ts, content = line.split(b" ", 1)
                if line not in last_lines and len(content.strip()) > 1:
                    logger.info(content.decode())
                    last_lines.append(line)
                last = dateutil.parser.isoparse(ts).replace(tzinfo=None)
        except HTTPError:
            logger.debug("Offline")
            break
        except Exception as e:
            logger.debug(e)


