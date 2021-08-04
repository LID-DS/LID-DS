#!/bin/bash
# check if run with root rights
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
# change into scenarios, find all subdirectories with maxdepth of 1 (exclude current folder) and run bash
# bash changes into folder and runs build_images with sudo.
cd scenarios && find . -maxdepth 1 -type d \( ! -name . \) -exec bash -c "cd '{}' && sudo ./build_images.sh" \;
