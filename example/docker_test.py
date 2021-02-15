import asyncio
import collections
import time
from threading import Thread

from datetime import datetime
import dateutil.parser
import docker
from docker.models.containers import Container


def show_logs(container: Container, i):
    current_line = ""
    for ts, char in container.logs(timestamps=True):
        if len(char) > 1:
            print(i, ts, char.decode().replace("\n", ""))
        else:
            if char is b'\r':
                continue
            if char is b'\n':
                if len(current_line) == 0:
                    continue
                print(i, ts, current_line)
                current_line = ""
            else:
                current_line += char.decode()


def show_timestamp_logs(container, i):
    last = datetime.fromtimestamp(1)
    last_lines = collections.deque(maxlen=50)
    while True:
        try:
            print("show after " + str(last))
            for line in container.logs(timestamps=True, since=last).splitlines():
                ts, content = line.split(b" ", 1)
                if line not in last_lines and len(content.strip()) > 1:
                    print(i, ts.decode(), content.decode())
                    last_lines.append(line)
                last = dateutil.parser.isoparse(ts).replace(tzinfo=None)
            time.sleep(2)
        except:
            break


def write(container):
    s = container.attach_socket(params={'stdin': 1, 'stream': 1})
    s._writing = True
    wts = [0.0003519952444073504, 3.7160083063590736, 0.006018354183099326, 0.24879327064221524, 2.3091246244436094, 0.04885424380311123, 0.03926578356361604, 0.336661327217098, 2.542263915292599, 0.3862333037632021]
    print("WTS:", len(wts))
    for x in wts:
        s.write(b"\n")
        time.sleep(x)


if __name__ == '__main__':
    d = docker.from_env()
    containers = []
    for i in range(1):
        container: Container = d.containers.run(
                "normal_mysql",
                command="x y z",
                name="test_image_%d" % i,
                detach=True,
                tty=True,
                stdin_open=True,
                remove=True)

        t_logs = Thread(target=show_timestamp_logs, args=(container, i))
        t_logs.start()
        t_write = Thread(target=write, args=(container,))
        t_write.start()
        containers.append(container)

    print("Sleeping")
    time.sleep(15)


    # _, out = container.exec_run("ls")
    # for l in out.decode("utf-8").split("\n"):
    #    print("[test_image]:", l)
    for i, container in enumerate(containers):
        print("Removing", i)
        container.remove(force=True)


