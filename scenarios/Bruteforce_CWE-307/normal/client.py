import argparse
import time
import random
import os
import tempfile
import requests
import sys

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from pyvirtualdisplay import Display
from threading import Thread
from heartbeat import Heartbeat

parser = argparse.ArgumentParser(description='HTTPS-Client Simulation.')

parser.add_argument('-ip', dest='server_ip', action='store', type=str, required=True,
                    help='The IP address of the target server')
parser.add_argument('-post', dest='post_freq', action='store', type=int, required=False, default=20,
                    help='The POST frequency of the client in % (GET is 100 - POST)')
parser.add_argument('-v', dest='verbose', action='store', type=bool, required=False, default=False,
                    help='Make the operations more talkative')

args = parser.parse_args()

server_paths = ['index.html', 'work.html', 'about.html', 'blog.html', 'services.html', 'shop.html']

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

# Virtual display to run chrome-browser
display = Display(visible=0, size=(800, 800))
display.start()

# Headless chrome-browser settings
chrome_options = Options()
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument('--ignore-certificate-errors')
driver = webdriver.Chrome(chrome_options=chrome_options)

# Probability of invalid logins
prob_invalid_login = 5


def heartbeat():
    hb = Heartbeat(args.server_ip, 443, False)
    heartbeat_freq = random.randrange(60, 120)
    while True:
        try:
            if args.verbose:
                print(' '.join(['Heartbeat:', username, '-->', args.server_ip]))
            hb.do_heartbeat()
            time.sleep(heartbeat_freq)
        # handling victim shutdown before own shutdown
        except Exception as e:
            if args.verbose:
                print(e)
            time.sleep(heartbeat_freq)


def https_requests(post_user, post_password):
    while True:
        try:
            sys.stdin.readline()
            do_request(post_user, post_password)
        # handling victim shutdown before own shutdown
        except Exception as e:
            if args.verbose:
                print(e)
            time.sleep(5)


def do_request(post_user, post_password):
    requestMethod = random.randrange(1, 100)
    if requestMethod <= args.post_freq:
        do_POST(post_user, post_password)
    else:
        do_GET()


def do_POST(post_user, post_password):
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
    auth = session.post(url, files=files, data=payload, verify=False)
    if args.verbose:
        print(' '.join(['POST:', 'user', post_user, 'file', file.name]))
    file.close()


def do_GET():
    url = ''.join(['https://', args.server_ip, '/', random.choice(server_paths)])
    driver.get(url)
    if args.verbose:
        print(' '.join(['GET:', url]))


# pick random user
user_list = list(users.keys())
username = random.choice(user_list)
password = users[username]

# start heartbeat as thread and requests as main process
Thread(target=heartbeat).start()
https_requests(username, password)
