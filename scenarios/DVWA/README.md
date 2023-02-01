# PHP_CWE-434 Unrestricted File Upload

## Description / Overview of scenario
Running Damn Vulnerable Web Application (DVWA). With possibility to log in, upload files and send sql queries. 

## victim:
Running [DVWA](https://dvwa.co.uk/) with unrestricted file upload possibility.

## normal:
Consists of user randomly browsing website. 

Including following actions:
* log_in:         Logging user with predefinded credentials.
* log_off:        If user is logged in randomly log off.
* follow_link:    Click random link on current site.
* do_things:
  * If on /vulnerabilities/sqli: Sending either valid or random SQL queries. 
  * If on /vulnerabilities/upload: Create tempfile and upload it.

## exploit:
Upload malicious php file. 
Execute it by visiting page vulnerabilities/upload/evil_script.php

## cli:

    sudo python3 main.py a b c
    
    a: boolean (0/1) run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean (0/1) run automated exploit
