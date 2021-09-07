import os
import os.path
import sys
import time
from datetime import datetime


def check_scenario(base, scenario):
    path = os.path.join(base, scenario + "runs/")
    if os.path.exists(path):
        num_files = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
        expected_number = 1000 + 100 + 20 + 30        
        done = num_files / 4 / expected_number * 100.0
        print(scenario.rjust(24), end='')
        bar = "-" * int(done)
        print(bar, end='')
        print(f" {done:.2f}%")


if __name__ == '__main__':
    path = sys.argv[1]
    while True:
        os.system('clear')
        now = datetime.now()        
        print(now.strftime("%H:%M:%S"))
        check_scenario(path, "Bruteforce_CWE-307/")
        check_scenario(path, "CVE-2012-2122/")
        check_scenario(path, "CVE-2014-0160/")
        check_scenario(path, "CVE-2017-12635_6/")
        check_scenario(path, "CVE-2017-7529/")
        check_scenario(path, "CVE-2018-3760/")
        check_scenario(path, "CVE-2019-5418/")
        check_scenario(path, "CVE-2020-13942/")
        check_scenario(path, "CVE-2020-23839/")
        check_scenario(path, "CVE-2020-9484/")
        check_scenario(path, "CWE-89-SQL-injection/")
        check_scenario(path, "EPS_CWE-434/")
        check_scenario(path, "Juice-Shop/")
        check_scenario(path, "PHP_CWE-434/")
        check_scenario(path, "ZipSlip/")
        time.sleep(5)
