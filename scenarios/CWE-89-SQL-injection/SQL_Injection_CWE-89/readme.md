sql injection scenario using DVWA and sqlmap
- currently uses the old LID-DS version
  - pip3 install git+https://github.com/LID-DS/LID-DS@5d16ef9c539ac5323f0088e94ebb80a5cd00993a


- build the images
  - sudo make images
- record normal behaviour
  - sudo make normal
  - python3 main.py -wt 20000 -rt 30000
- record attack behaviour
  - sudo make attack
  - python3 main.py -wt 15000 -rt 60000 --exploit -t 1000