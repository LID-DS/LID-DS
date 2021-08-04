#!/bin/bash
declare -A users

users=( ["user1"]="password1" ["user2"]="password2" ["user3"]="password3" ["user4"]="password4" ["user5"]="password5" ["user6"]="password6" ["user7"]="password7" ["user8"]="password8" ["user9"]="password9" ["user10"]="password10")

touch /etc/apache2/.htpasswd

for user in "${!users[@]}"; do htpasswd -b /etc/apache2/.htpasswd "$user" "${users[$user]}"; done