import os
import wget
import shutil
import gzip
import glob
import zipfile
from fsplit.filesplit import FileSplit
import random
import subprocess
from lid_ds.core import Scenario
from lid_ds.sim import Behaviour
import sys
import time

# needs
# pip3 install wget
# pip3 install filesplit
# pip3 install git+https://github.com/LID-DS/LID-DS
# sudo apt install curl

unpacked_filename = "dewiki-latest-abstract.xml"
filename = "dewiki-latest-abstract.xml.gz"
download_url = "https://dumps.wikimedia.org/dewiki/latest/dewiki-latest-abstract.xml.gz"
file_splits = "filesplits/"
block_size = 65536
target_port = "8000"
target_url = "http://localhost"
dir_path = os.path.dirname(os.path.realpath(__file__))


class ZipSlip(Scenario):

    def wait_for_availability(self, container):
        print("wait for avail.")
        self.prepare_files()
        return True

    def exploit(self, container):
        """ sends the malicious evil.zip to the victim """
        os.chdir(dir_path)
        evil = "evil.zip"
        send_file(evil, target_url + ":" + target_port)

    def prepare_files(self):
        """ prepares the zip files send to the ZipService, called by wait_for_availability """
        print("prepare files...")
        if not os.path.isfile("./" + unpacked_filename):

            # check for file: dewiki-latest-abstract.xml.gz
            # if not there download it: https://dumps.wikimedia.org/dewiki/latest/dewiki-latest-abstract.xml.gz
            if not os.path.isfile("./" + filename):
                print("start downloading wikipedia de abstract xml from: " + download_url)
                wget.download(download_url)
                print("done")
            else:
                print("file already exists: " + filename)

            # unzip
            print("unzipping file: " + filename)
            with gzip.open("./" + filename, 'rb') as s_file, open("./" + unpacked_filename, 'wb') as d_file:
                shutil.copyfileobj(s_file, d_file, block_size)
            print("done")
        else:
            print("file already exists: " + unpacked_filename)

        # split the xml and zip each file split
        if not os.path.isfile(file_splits + "dewiki-latest-abstract_1.xml.zip"):
            print("splitting the file...")
            os.mkdir(file_splits)
            fs = FileSplit(file=unpacked_filename, splitsize=2097152, output_dir=file_splits)
            fs.splitbyencoding()
            print("done")

            # zip all files
            print("zipping all files...")
            os.chdir(file_splits)
            for file in glob.glob("*.xml"):
                print("zipping: " + file)
                zipfile.ZipFile(file + ".zip", mode='w').write(file, compress_type=zipfile.ZIP_DEFLATED)
                os.remove(file)
            print("done")
        else:
            print("zip files already created")


class UnpackerBehaviour(Behaviour):
    def __init__(self, warmup, recording):
        self.wait_times = [1]
        self.actions = [self.do_normal]
        self.runningtime = warmup + recording

    def do_normal(self):
        """ sends random zip files from file_splits to the victim """
        print("starting normal behaviour...")
        os.chdir(dir_path + "/" + file_splits)
        file_list = glob.glob("*.zip")
        start_time = time.time()
        while time.time() < start_time + self.runningtime -1:
            os.chdir(dir_path + "/" + file_splits)
            choice = random.choice(file_list)
            send_file(choice, target_url + ":" + target_port)
        print("END do_normal")


def send_file(file, victim):
    """ sends the given file to the victim"""
    print("sending: " + file + " to " + victim)
    subprocess.run(["curl", "-X", "PUT", "--upload-file", file, victim])

##################################################
warmup_time = int(sys.argv[1])
recording_time = int(sys.argv[2])
is_exploit= int(sys.argv[3])
do_exploit = True
if is_exploit < 1:
    do_exploit = False

exploit_time = random.randint(int(recording_time * .3), int(recording_time * .8))
behaviours = []
behaviours.append(UnpackerBehaviour(warmup_time, recording_time))

if do_exploit:
    scenario = ZipSlip(
        'zipslip_victim',
        port_mapping={
            target_port + '/tcp': target_port
        },
        warmup_time=warmup_time,
        recording_time=recording_time,
        behaviours=behaviours,
        exploit_start_time=exploit_time
    )
else:
    scenario = ZipSlip(
        'zipslip_victim',
        port_mapping={
            target_port + '/tcp': target_port
        },
        warmup_time=warmup_time,
        recording_time=recording_time,
        behaviours=behaviours
    )

scenario()
