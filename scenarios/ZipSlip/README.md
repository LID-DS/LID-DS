# ZipSlip 

## Description / Overview of scenario
Victim hosting uploading portal which unzips uploaded files without checking content, which can lead to unwanted overwriting of files.

## victim:
Running Ubuntu 16.04 hosting a server with the possibiliy to unzip files using a java unpacker. 

## normal:
Sending files for victim to unzip.

## exploit:
Upload malicious zipped file with malicious content (../../../../.../etc/passwd). 
This will overwrite any files at specified location.

## cli:

    sudo python3 main.py a b c 
    
    a: boolean run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean run automated exploit