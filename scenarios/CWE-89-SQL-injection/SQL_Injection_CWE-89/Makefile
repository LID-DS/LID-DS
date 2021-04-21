images:
	docker build -t sql_victim ./victim/
	docker build -t sql_client ./client/
	docker build -t sql_attacker ./attacker/

normal:
	python3 main.py -wt 20000 -rt 30000

attack:
	python3 main.py -wt 15000 -rt 60000 --exploit -t 1000