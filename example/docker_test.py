from socket import SocketIO
from threading import Thread
import docker
from docker.models.containers import Container
import time


def show_logs(container: Container):
    collected_line = []
    for char in container.logs(stream=True):
        if char is b'\r':
            continue
        if char is b'\n':
            if len(collected_line) == 0:
                continue
            print("[logs]:", "".join(collected_line))
            collected_line.clear()
        else:
            collected_line.append(char.decode())

if __name__ == '__main__':
    d = docker.from_env()
    container: Container = d.containers.run(
            "normal_mysql",
            command="x y",
            name="test_image",
            detach=True,
            tty=True,
            stdin_open=True,
            remove=True)

    t_logs = Thread(target=show_logs, args=(container,))
    t_logs.start()

    s = container.attach_socket(params={'stdin': 1, 'stream': 1})
    s._writing = True
    for x in range(4):
        s.write(b"\n")
        time.sleep(x)

    # _, out = container.exec_run("ls")
    # for l in out.decode("utf-8").split("\n"):
    #    print("[test_image]:", l)
    container.remove(force=True)
