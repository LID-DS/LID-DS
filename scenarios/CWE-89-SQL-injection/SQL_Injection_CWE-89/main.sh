#!/bin/bash

for i in `seq 2`
do
	m=$((i%7))
	t=$((30+5*m))
	sudo python3 main.py 10 $((t)) 0
done


for i in `seq 2`
do
	m=$((i%7))
	t=$((30+5*m))
	sudo python3 main.py 10 $((t)) 1
done
