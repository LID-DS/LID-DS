FROM ubuntu:20.04

# Setup python and java and base system
ENV DEBIAN_FRONTEND noninteractive
ENV LANG=en_US.UTF-8
RUN apt-get update && \
  apt-get upgrade -y && \
  apt-get install -q -y openjdk-8-jdk python3-pip libsnappy-dev language-pack-en supervisor && \
  apt-get install iproute2 -y


RUN pip3 install requests
ADD ysoserial-master.jar /home/ysoserial.jar
ADD exploit.py /home/exploit.py

ENTRYPOINT ["python3", "-u", "/home/exploit.py"]
CMD []
