# Damn Vulnerable Web Application

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

4 exploits are available for this scenario:

SQL Injection:
- insert malicious SQL statement using SQLMap 
- extracts User and Admin Passwords

Remote Code Execution (RCE):
- Upload malicious php file. 
- Execute it by visiting page vulnerabilities/upload/evil_script.php

Bruteforce:
- uses a List of common usernames and passwords to find out valid user credentials

Command Injection:
- prints /etc/passwd by appending the command to a ping function in DVWA


## cli:

    sudo python3 main.py a b c d
    
    a: boolean (0/1) run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean (0/1) run automated exploit
    d: index of attack to be executed, choose from [SQLI, RCE, Bruteforce, CommandInjection]
