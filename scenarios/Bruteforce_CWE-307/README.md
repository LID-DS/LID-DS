# Bruteforce (CWE-307)

## Description / Overview of scenario
This scenario implements one of the most common attacks, brute forcing. It includes a simple web app, basic GET and POST normal behaviour and brute forcing with the metasploit framework. Victim and normal behaviour are identical to CVE-2014-0160.

## victim:
A simple web app building on top of a free wordpress template (https://colorlib.com/wp/themes/unapp/) is hosted in a docker container running apache2 which also includes a self-signed ssl certificate. In addition to the basic wordpress template a simple service is implemented that accepts POST requests with authentication.

## normal:
The normal behaviour consists of random GET and POST requests to the victim by picking one of 10 possible normal users. 

## exploit:
The exploit brute forces (tries to log in repeatedly with different credentials) the POST endpoint of the victim. This is done by using the metasploit framework's bruteforce automation that has a builtin credential library.

Further information:
* https://cwe.mitre.org/data/definitions/307.html
* https://owasp.org/www-community/attacks/Brute_force_attack
* https://docs.rapid7.com/metasploit/bruteforce-attacks/
