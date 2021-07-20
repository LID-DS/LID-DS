#!/bin/bash

user=$(shuf -n 1 http_default_users.txt)
password=$(shuf -n 1 http_default_pass.txt)

htpasswd -b /etc/apache2/.htpasswd "$user" "$password"