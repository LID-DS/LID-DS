#!/bin/bash

# normal
count=1000
for i in $(seq $count); do
    python3.8 main.py 1 45 0
done

# normal and attack
count=100
for i in $(seq $count); do
    python3.8 main.py 1 -1 1
done

# only attack
count=20
for i in $(seq $count); do
    python3.8 main.py 0 -1 1
done

# idle
count=30
for i in $(seq $count); do
    python3.8 main.py 0 45 0
done
