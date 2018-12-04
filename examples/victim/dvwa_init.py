from time import sleep
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from pyvirtualdisplay import Display
import requests
import os

# dvwa init script - to create the dvwa database

requests.packages.urllib3.disable_warnings()

# Virtual display to run chrome-browser
display = Display(visible=0, size=(800, 800))
display.start()

chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
browser = webdriver.Chrome(chrome_options=chrome_options)

# create DATABASE ###
url = 'http://localhost/setup.php'
browser.get(url)
browser.find_element_by_name('create_db').click()

# shut down
browser.quit()
display.popen.kill()

os._exit(os.EX_OK)
