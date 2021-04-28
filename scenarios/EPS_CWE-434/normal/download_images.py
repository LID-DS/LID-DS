import os
import wget
import glob
import subprocess


def prepare_files(url, download_path, image_number):
    """
    downloads and prepares images for normal behaviour, called by build_images.sh
    """
    print("prepare files...")

    # create image directory if not exists
    if not os.path.exists(download_path):
        os.makedirs(download_path)

    image_list = glob.glob(download_path + "/*.eps")
    if len(image_list) < image_number:
        # check for number_of_images jpgs
        image_list = glob.glob(download_path + "/*.jpg")
        if len(image_list) < image_number:
            print("start downloading jpgs from http://picsum.com")
            for num in range(image_number):
                filename = download_path + "image_" + str(num).zfill(4) + ".jpg"
                if not os.path.isfile("./" + filename):
                    print("loading file: " + filename)
                    wget.download(url, out=filename, bar=None)
            print("done")
        else:
            print("jpgs already downloaded")

        print("converting jpgs to eps:")
        jpgfiles = glob.glob(download_path + "/*.jpg")
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


if __name__ == '__main__':
    download_url = "https://picsum.photos/400/300"
    path_download_images = "normal/images/"
    number_of_images = 500

    prepare_files(download_url, path_download_images, number_of_images)
