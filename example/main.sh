#!/bin/bash

for i in `seq 1`
do
	m=$((i%7))
	t=$((30+5*m))
	sudo python3 main.py 10 $((t)) 0
done


for i in `seq 3`
do
	m=$((i%7))
	t=$((30+5*m))
	sudo python3 main.py 10 $((t)) 1
done
