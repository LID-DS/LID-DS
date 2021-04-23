#!/bin/bash
# this script is the entry point for the dvwa victim

echo '[+] Starting mysql...'
service mysql start

echo '[+] Starting apache'
service apache2 start

echo '--> init dvwa script'
python3 /tmp/dvwa_init.py

sleep 1d
