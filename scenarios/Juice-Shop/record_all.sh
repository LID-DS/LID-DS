#!/bin/bash

# normal
count=1000
for i in $(seq $count); do
    python3.8 main.py 1 45 0 0
done

# normal and attack(0)
count=34
for i in $(seq $count); do
    python3.8 main.py 1 -1 1 SQLInjectionSchema
done

# normal and attack(1)
count=34
for i in $(seq $count); do
    python3.8 main.py 1 -1 1 SQLInjectionCred
done

# normal and attack(2)
count=34
for i in $(seq $count); do
    python3.8 main.py 1 -1 1 SQLInjectionUser
done

# only attack(0)
count=7
for i in $(seq $count); do
    python3.8 main.py 0 -1 1 SQLInjectionSchema
done

# only attack(1)
count=7
for i in $(seq $count); do
    python3.8 main.py 0 -1 1 SQLInjectionCred
done

# only attack(2)
count=7
for i in $(seq $count); do
    python3.8 main.py 0 -1 1 SQLInjectionUser
done


# idle
count=30
for i in $(seq $count); do
    python3.8 main.py 0 45 0 0
done
