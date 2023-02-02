#!/bin/bash

chown -R mysql:mysql /var/lib/mysql /var/run/mysqld

echo '[+] Starting mysql...'
service mysql start

echo '[+] Starting apache...'
service apache2 start

echo '--> init dvwa script'
python3 /tmp/dvwa_init.py

while true
do
    tail -f /var/log/apache2/*.log
    exit 0
done