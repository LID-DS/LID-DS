import os
import wget
import glob
import subprocess

download_url = "https://picsum.photos/400/300"
path_download_images = "normal/images/"
number_of_images = 500


def prepare_files():
    """ prepares the images, called by build_images.sh"""
    print("prepare files...")
    # check for number of eps in current folder... needs min 1000
    image_list = glob.glob(path_download_images + "/*.eps")
    if len(image_list) < number_of_images:
        # check for number_of_images jpgs
        image_list = glob.glob(path_download_images + "/*.jpg")
        if len(image_list) < number_of_images:
            # if not there download them like: wget -O test.jpg http://lorempixel.com/1920/1080/
            print("start downloading jpgs from http://picsum.com")
            for num in range(number_of_images):
                filename = path_download_images + "image_" + str(num).zfill(4) + ".jpg"
                if not os.path.isfile("./" + filename):
                    print("loading file: " + filename)
                    wget.download(download_url, out=filename, bar=None)
            print("done")
        else:
            print("jpgs already downloaded")
        # ...
        print("converting jpgs to eps:")

        jpgfiles = glob.glob(path_download_images + "/*.jpg")
        for filename in jpgfiles:
            epsname = filename.replace('jpg', 'eps')
            if not os.path.isfile("./" + epsname):
                print(f"Converting {filename} to {epsname}")
                subprocess.run(["convert", filename, "eps2:" + epsname])

        print("cleaning jpg files")
        for filename in jpgfiles:
            os.remove(filename)

        print("done")
    else:
        print("eps files already created.")

prepare_files()
