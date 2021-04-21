import argparse
import time
import requests
import numpy as np
import logging
import string
import random
import lidds

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from pyvirtualdisplay import Display

logging.basicConfig(filename='client.log', level=logging.DEBUG)

parser = argparse.ArgumentParser(description='HTTPS-Client Simulation.')

parser.add_argument('-ip',
                    dest='server_ip',
                    action='store',
                    type=str,
                    required=True,
                    help='The IP address of the target server')
parser.add_argument('-u',
                    dest='username',
                    action='store',
                    type=str,
                    required=True,
                    help='The username of the client')
parser.add_argument('-p',
                    dest='password',
                    action='store',
                    type=str,
                    required=True,
                    help='The password of the client')

args = parser.parse_args()

# Disable requests warnings (caused by self signed server certificate)
requests.packages.urllib3.disable_warnings()

# Virtual display to run chrome-browser
display = Display(visible=0, size=(800, 800))
display.start()

# Headless chrome-browser settings
chrome_options = Options()
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument('--ignore-certificate-errors')
browser = webdriver.Chrome(chrome_options=chrome_options)

# probability to log off:
prob_log_off = 0.05

# probability to enter valid input into the sql_injection form
sqli_valid_input_probability = 0.75
# if no valid value is send, whats the probability of it been a random string
sqli_random_string_probability = 0.5

# states:
logged_off = 0
logged_in = 1

# initially the client is logged off
client_state = logged_off

# links to exclude when randomly choosing one
exclude_links = ['/logout.php',
                 '/captcha/',
                 '/security.php',
                 '/phpinfo.php',
                 '.pdf']


def generate_random_string(size=6, chars=string.printable):
    """
    generates a random printable string
    of the given size using the given characters
    :param size: length of the string to be generated
    :param chars: set of characters to be used
    :return: a random string
    """
    return ''.join(random.choice(chars) for _ in range(size))


def wait_for_dvwa():
    done = False
    logging.info('wait till dvwa is up und running...')
    while not done:
        # wait till dvwa is up und running
        url = 'http://' + args.server_ip + '/login.php'
        browser.get(url)
        logging.info("get url: " + url)
        if 'Login :: Damn Vulnerable Web Application' in browser.title:
            done = True
            logging.info('dvwa is ready...')
        else:
            logging.info(
                'dvwa not ready yet, waiting 2 seconds, current title: \n'
                + browser.title)
            time.sleep(2)


def random_browsing():
    """
    main loop of random browsing normal behaviour
    """
    wait_for_dvwa()
    # now start the "normal routine"
    lidds.scheduler_sync(normal_step)


def normal_step(arg):
    global client_state
    # is the client logged in?
    # yes, its logged in
    if client_state == logged_in:
        # decide what to do:
        x = np.random.random()
        if x <= prob_log_off:
            log_off()
        else:
            follow_link()
            do_things()
    # no, its not logged in:
    else:
        log_in()


def do_things():
    """
    do things depending on the current active site
    - "vulnerabilities/sqli/" in path:
        <input type="text" size="15" name="id">
        <input type="submit" name="Submit" value="Submit">
        Values 1 to 5 are ok
    """
    if 'vulnerabilities/sqli/' in browser.current_url:
        logging.info(' SQL injection form found')
        sending_value = ''
        if np.random.random() <= sqli_valid_input_probability:
            # enter a valid integer value (valid is from 1 to 5)
            sending_value = str(np.random.randint(low=1, high=6))
        else:
            if np.random.random() <= sqli_random_string_probability:
                # enter a random string
                sending_value = generate_random_string(
                    np.random.randint(low=1, high=40))
            else:
                # enter a "not" valid number
                sending_value = str(np.random.randint(low=-10000, high=10000))

        logging.info(' sending: %s', sending_value)
        browser.find_element_by_name('id').send_keys(sending_value)
        browser.find_element_by_name('Submit').click()


def follow_link():
    """
    iterates all "internal" links and chooses a random one to follow
    """
    # list all available local links
    logging.info('follow link...')
    link_list = list()
    for link in browser.find_elements_by_xpath('.//a'):
        link_url = link.get_attribute('href')
        if args.server_ip in link_url:
            if not any(e in link_url for e in exclude_links):
                link_list.append(link)
                logging.info('%d. %s', len(link_list)-1, link_url)
    # randomly select one link to follow
    i = np.random.randint(0, high=len(link_list))
    logging.info('    selected: [%d] of %d links', i, len(link_list))
    selected_link = link_list[i]
    selected_link.click()


def log_in():
    """
    logs into dvwa with the given username and password
    (args.username and args.password)
    changes client_state to logged_in
    """
    global client_state
    url = 'http://' + args.server_ip + '/login.php'
    logging.info('login... ' + url)
    browser.get(url)
    logging.info('    got response')
    browser.find_element_by_name('username').send_keys(args.username)
    browser.find_element_by_name('password').send_keys(args.password)
    logging.info('    filled form and click')
    browser.find_element_by_name('Login').click()
    logging.info('    logged in')
    client_state = logged_in


def log_off():
    """
    logs the current user out from dvwa
    changes client_state to logged_off
    """
    global client_state
    logging.info('logut...')
    browser.find_element_by_link_text('Logout').click()
    logging.info('    logged out')
    client_state = logged_off


random_browsing()
