# CWE-434: Unrestricted File Upload of Dangerous EPS File

## Description / Overview of scenario
This scenario is an example for unrestricted file upload for dangerously modified files which lead to remote code execution on the victim.

## victim:
The victim runs a small service with the purpose of converting uploaded EPS files to SVG file and save these. Because the service does not check the integrity of the uploaded file, it is possible for an attacker to upload files including code that then gets executed on the victim.

## normal:
While building the containers 500 random stock photos are downloaded and converted to EPS files. The normal behaviour picks randomly from this pool and sends them to the victim's converting service via HTTP PUTs.

## exploit:
When the exploit is triggered it sends a malicious EPS file to the victim using  HTTP PUT. This leads to the execution of a wget statement on the victim. 

#### Further information:
* https://cwe.mitre.org/data/definitions/434.html

## cli:

    sudo python3 main.py a b c
    
    a: boolean (0/1) run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean (0/1) run automated exploit