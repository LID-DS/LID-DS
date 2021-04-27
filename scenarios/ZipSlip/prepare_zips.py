import glob
import gzip
import os
import shutil
import zipfile

import wget
from fsplit.filesplit import Filesplit


def prepare_files():
    """ prepares the zip files send to the ZipService """

    unpacked_filename = "dewiki-latest-abstract.xml"
    filename = "dewiki-latest-abstract.xml.gz"
    download_url = "https://dumps.wikimedia.org/dewiki/latest/dewiki-latest-abstract.xml.gz"
    file_splits = "filesplits/"

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
        block_size = 65536
        with gzip.open("./" + filename, 'rb') as s_file, open("./" + unpacked_filename, 'wb') as d_file:
            shutil.copyfileobj(s_file, d_file, block_size)
        print("done")
    else:
        print("file already exists: " + unpacked_filename)

    # split the xml and zip each file split
    if not os.path.isfile(file_splits + "dewiki-latest-abstract_1.xml.zip"):
        print("splitting the file...")
        os.mkdir(file_splits)
        fs = Filesplit()
        fs.split(file=unpacked_filename, split_size=2097152, output_dir=file_splits)
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

    print("done")
    print("")


if __name__ == '__main__':
    prepare_files()
