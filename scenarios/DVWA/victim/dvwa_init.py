import requests
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# dvwa init script - to create the dvwa database

requests.packages.urllib3.disable_warnings()

# Virtual display to run chrome-browser
display = Display(visible=False, size=(800, 800))
display.start()

chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
browser = webdriver.Chrome(options=chrome_options)

# create DATABASE
print("creating database...")
url = 'http://localhost/setup.php'
browser.get(url)
browser.find_element('name', 'create_db').click()

# Login
url = 'http://localhost/login.php'
print("logging in...")
browser.get(url)
browser.find_element('name', 'username').send_keys('admin')
browser.find_element('name', 'password').send_keys('password')
browser.find_element('name', 'Login').click()

# Set security level low
print("setting security level low...")
url = 'http://localhost/security.php'
browser.get(url)
browser.find_element('name', 'security').send_keys('low')
browser.find_element('name', 'seclev_submit').click()

# shut down
browser.quit()
display.stop()
