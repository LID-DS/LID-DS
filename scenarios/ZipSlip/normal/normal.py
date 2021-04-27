import glob
import subprocess
import sys
from random import random


def send_file(file, victim):
    """ sends the given file to the victim"""
    print("start sending: " + file + " to " + victim)
    subprocess.run(["curl", "-X", "PUT", "--upload-file", file, victim])
    print("finished sending: " + file + " to " + victim)


def do_normal(file_list, victim_ip, victim_port):
    choice = random.choice(file_list)
    send_file(choice, victim_ip + ":" + victim_port)


if __name__ == '__main__':
    """
    main loop of zip slip normal behaviour
    """
    victim_ip = sys.argv[1]
    victim_port = "8000"
    print("sending files to: " + victim_ip + ":" + victim_port)

    files = glob.glob("/home/*.zip")
    while True:
        sys.stdin.readline()
        try:
            do_normal(files, victim_ip, victim_port)
        except Exception as e:
            print(e)
