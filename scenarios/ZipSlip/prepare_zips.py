import glob
import gzip
import os
import shutil
import zipfile

import wget
from fsplit.filesplit import Filesplit


def prepare_files():
    filename = "dewiki-latest-abstract1.xml.gz"
    unpacked_filename = filename[:-3]
    download_url = "https://dumps.wikimedia.org/dewiki/latest/" + filename
    file_splits = "normal/filesplits/"

    # change to filesplits dir
    print("[00]: chdir to " + file_splits)
    if not os.path.isdir(file_splits):
        os.mkdir(file_splits)
    os.chdir(file_splits)

    # check 1
    if os.path.isfile("dewiki-latest-abstract1_1.xml.zip"):
        print("zip files ready...")
        return

    print("[01]: get wiki abstract xml")
    if not os.path.isfile("./" + unpacked_filename):
        # check for file: dewiki-latest-abstract.xml.gz
        # if not there download it: https://dumps.wikimedia.org/dewiki/latest/dewiki-latest-abstract1.xml.gz
        if not os.path.isfile("./" + filename):
            print("start downloading wikipedia de abstract 1 xml from: " + download_url)
            wget.download(download_url)
            print(" done")
        else:
            print("file already exists: " + filename)

        # unzip
        print("unzipping file: " + filename)
        block_size = 65536
        with gzip.open("./" + filename, 'rb') as s_file, open("./" + unpacked_filename, 'wb') as d_file:
            shutil.copyfileobj(s_file, d_file, block_size)
        print("done")
        os.remove(filename)
    else:
        print("file already exists: " + unpacked_filename)

    # split the xml and zip each file split
    print("[02]: split xml")
    if not os.path.isfile("dewiki-latest-abstract1_1.xml"):
        print("splitting the file...")
        fs = Filesplit()
        fs.split(file=unpacked_filename, split_size=2097152, output_dir="./")
        # files are named like: dewiki-latest-abstract1_305.xml
        print("done")
        os.remove(unpacked_filename)

    print("[04]: zip splits ")
    if not os.path.isfile("dewiki-latest-abstract1_1.xml.zip"):
        # zip all files
        print("zipping all files...")
        for file in glob.glob("dewiki-latest-abstract1_*.xml"):
            print("zipping: " + file)
            zipfile.ZipFile(file + ".zip", mode='w').write(file, compress_type=zipfile.ZIP_DEFLATED)
            os.remove(file)
        print("done")
    else:
        print("zip files already created")

    print("done")
    print("")


if __name__ == '__main__':
    prepare_files()
