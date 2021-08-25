# CVE-2020-23839: XSS leading to RCE in GetSimple CMS v3.3.16

## Description / Overview of scenario
A Reflected Cross-Site Scripting (XSS) vulnerability in GetSimple CMS v3.3.16, in the admin/index.php login portal webpage, allows remote attackers to execute JavaScript code in the client's browser and harvest login credentials after a client clicks a link, enters credentials, and submits the login form.
## victim:
The victim runs version 3.3.16 of the GetSimple CMS in a docker container built on apache2. The running app is a small custom website including 3 landingpages and the GetSimpleCMS admin backend including a XSS vulnerability in the login form for the admin backend.  

## normal:
The normal behaviour is built as a selenium auto clicker that in the first step opens the website, iterates through available links and picks and clicks one randomly. With a chance of 10 percent the random surfer logs in as admin and performs clicks in the admin backend. This is necessary because the exploit step requires an admin login. Normal behaviour without admin could lead to an anomaly when the admin logs in even without doing evil things.

## exploit:
The exploit happens in two steps:
1. Tricking the admin into clicking on an evil url including JavaScript Payload. This leads to injection of the XSS.
2. A reverse shell opens for the attacker making it able to execute commands like 'cat /etc/passwd'

Payload functionality taken from https://github.com/boku7/CVE-2020-23839:
1. performs an XHR POST request in the background, which logs the browser into the GetSimple CMS Admin panel
2. then performs a 2nd XHR GET request to admin/edit-theme.php, and collects the CSRF Token & Configured theme for the webpages hosted on the CMS
3. then performs a 3rd XHR POST request to admin/edit-theme.php, which injects a PHP backdoor WebShell to all pages of the CMS

Further Information:
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-23839
* https://github.com/boku7/CVE-2020-23839

## cli:

    sudo python3 main.py a b c
    
    a: boolean (0/1) run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean (0/1) run automated exploit