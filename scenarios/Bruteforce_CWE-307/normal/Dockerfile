FROM debian:9.2

RUN apt-get update && apt-get install -y wget python3 python3-pip wget unzip xvfb udev

# chrome in debian
RUN echo 'deb http://dl.google.com/linux/chrome/deb/ stable main' >> /etc/apt/sources.list
RUN wget https://dl-ssl.google.com/linux/linux_signing_key.pub
RUN apt-key add linux_signing_key.pub

# install chrome
RUN apt-get update && apt-get install -y google-chrome-stable git

# python related
RUN pip3 install --upgrade pip setuptools
RUN pip3 install 'urllib3==1.23' --force-reinstall
RUN pip3 install requests
RUN pip3 install numpy

ADD client.py /home/client.py
ADD heartbeat.py /home/heartbeat.py

ENTRYPOINT ["python3", "-u", "/home/client.py"]
CMD []
