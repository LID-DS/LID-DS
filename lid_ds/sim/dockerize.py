import collections
import os
import time
from datetime import datetime
import random

import dateutil.parser
import docker
from docker.models.containers import Container

from lid_ds.utils import log

client = docker.from_env()
this_dir = os.path.dirname(os.path.realpath(__file__))


def create_network(name):
    print("Creating network %s" % name)
    return client.networks.create(name)


def run_image(image, network, name, port_mapping=None, command="") -> Container:
    container = client.containers.run(
        image,
        command=command,
        name=name,
        network=network.name,
        detach=True,
        stdin_open=True,
        tty=True,
        remove=True,
        ports=port_mapping)
    return container


def show_logs(container: Container, name, queue):
    logger = log.get_logger(name, queue)
    logger.info("Showing logs")
    last = datetime.fromtimestamp(1)
    last_lines = collections.deque(maxlen=50)
    while True:
        try:
            time.sleep(random.uniform(1.0, 2.0))
            for line in container.logs(timestamps=True, since=last).splitlines():
                ts, content = line.split(b" ", 1)
                if line not in last_lines and len(content.strip()) > 1:
                    logger.info(content.decode())
                    last_lines.append(line)
                last = dateutil.parser.isoparse(ts).replace(tzinfo=None)
        except:
            logger.debug("SHUTDOWN")
            break

def show_logs_old(container: Container, name, lock):
    logger = log.get_logger(name)
    logger.info("Showing logs")
    current_line = ""
    lines_to_flush = []
    next_flush = time.time() + 2
    for char in container.logs(stream=True):
        if len(char) > 1:
            logger.info(char.decode().replace("\n", ""))
        else:
            if char is b'\r':
                continue
            if char is b'\n':
                if len(current_line) == 0:
                    continue
                lines_to_flush.append(current_line)
                current_line = ""
            else:
                current_line += char.decode()
        if time.time() > next_flush:
            lock.acquire()
            for line in lines_to_flush:
                logger.info(line)
            lock.release()
            lines_to_flush = []
            next_flush = time.time() + 2
    lock.acquire()
    for line in lines_to_flush:
        logger.info(line)
    lock.release()
