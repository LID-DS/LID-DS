#!/bin/bash

python3 ./prepare_zips.py
docker build -t victim_zipslip victim
docker build -t normal_zipslip normal
docker build -t exploit_zipslip exploit
