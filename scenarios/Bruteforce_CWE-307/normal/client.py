import argparse
import time
import random
import os
import tempfile
import requests
import sys

import webbrowser
from threading import Thread
from heartbeat import Heartbeat


def vprint(string):
    """
    prints the given string if the verbose flag is set
    """
    if args.verbose:
        print(string)


def heartbeat():
    """
    sends heartbeat to victim
    """
    hb = Heartbeat(args.server_ip, 443, False)
    heartbeat_freq = random.randrange(60, 120)
    while True:
        try:
            vprint(' '.join(['Heartbeat:', username, '-->', args.server_ip]))
            hb.do_heartbeat()
            time.sleep(heartbeat_freq)
        # handling victim shutdown before own shutdown
        except Exception:
            time.sleep(heartbeat_freq)


def https_requests(post_user, post_password):
    """
    main loop for normal behaviour
    """
    while True:
        try:
            sys.stdin.readline()
            do_request(post_user, post_password)
        # handling victim shutdown before own shutdown
        except Exception:
            time.sleep(5)


def do_request(post_user, post_password):
    """
    executes POST and GET Requests randomly
    """
    requestMethod = random.randrange(1, 100)
    if requestMethod <= args.post_freq:
        do_POST(post_user, post_password)
    else:
        do_GET()


def do_POST(post_user, post_password):
    """
    executes POST request to victim
    """
    url = ''.join(['https://', args.server_ip, '/private/upload.php'])

    x = random.randrange(1, 100)
    if x <= prob_invalid_login:
        post_password = "wrong-password-123"

    # Create a random tempfile and upload it
    file_size = random.randint(1000, 10000)
    file = tempfile.NamedTemporaryFile(mode='w+b')
    file.write(os.urandom(file_size))

    # Send POST request to the server
    session = requests.Session()
    session.auth = (post_user, post_password)
    payload = {'press': 'OK'}
    files = {'userfile': open(file.name, 'rb')}
    session.post(url, files=files, data=payload, verify=False)
    vprint(' '.join(['POST:', post_user, 'file', file.name]))
    file.close()


def do_GET():
    """
    executes GET request to victim
    """
    url = ''.join(['https://', args.server_ip, '/', random.choice(server_paths)])
    webbrowser.open(url)
    vprint(' '.join(['GET:', url]))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTPS-Client Simulation.')

    parser.add_argument('-ip',
                        dest='server_ip',
                        action='store',
                        type=str,
                        required=True,
                        help='The IP address of the target server')
    parser.add_argument('-post',
                        dest='post_freq',
                        action='store',
                        type=int,
                        required=False,
                        default=20,
                        help='The POST frequency of the client in % (GET is 100 - POST)')
    parser.add_argument('-v',
                        dest='verbose',
                        action='store',
                        type=bool,
                        required=False,
                        default=False,
                        help='Make the operations more talkative')

    args = parser.parse_args()

    server_paths = ['index.html',
                    'work.html',
                    'about.html',
                    'blog.html',
                    'services.html',
                    'shop.html']

    # same users as in victims 'create_users.sh'
    users = {
        "user1": "password1",
        "user2": "password2",
        "user3": "password3",
        "user4": "password4",
        "user5": "password5",
        "user6": "password6",
        "user7": "password7",
        "user8": "password8",
        "user9": "password9",
        "user10": "password10"
    }

    # Disable requests warnings (caused by self signed server certificate)
    requests.packages.urllib3.disable_warnings()

    # Probability of invalid logins
    prob_invalid_login = 5

    # pick random user
    user_list = list(users.keys())
    username = random.choice(user_list)
    password = users[username]

    # start heartbeat as thread and requests as main process
    Thread(target=heartbeat).start()
    https_requests(username, password)
