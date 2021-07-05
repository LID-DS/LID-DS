# PHP_CWE-434 

## Description / Overview of scenario
Running Damn Vulnerable Web Application (DVWA). With possibility to log in, upload files and send sql queries. 

## victim:
Running [DVWA](https://dvwa.co.uk/) with unrestricted file upload possibility.

## normal:
Consists of user randomly browsing website. 
Including following actions:
    log_in:         Logging user with predefinded credentials.
    log_off:        If user is logged in randomly log off.
    follow_link:    Click random link on current site.
    do_things:      If on /vulnerabilities/sqli  :Sending either valid or random SQL queries. 
                        If on /vulnerabilities/upload:Create tempfile and upload it.

## exploit:
Logging in as 1337 with password charley.
Go through links on site and visit /vulnerabilities/sqli if available.
Extract cookie information. 
Run sqlmap with cookie information to automatically inject malicious sql queries.
