#!/usr/bin/env bash

cd /service/upload
python3 ../ImageConverter.py &> server.log

sleep 1d
