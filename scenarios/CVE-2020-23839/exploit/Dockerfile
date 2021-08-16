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
RUN pip3 install selenium
RUN pip3 install 'urllib3==1.23' --force-reinstall
RUN pip3 install pyvirtualdisplay
RUN pip3 install requests
RUN pip3 install numpy

RUN wget https://chromedriver.storage.googleapis.com/2.42/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip -d /usr/bin
RUN chmod +x /usr/bin/chromedriver

ADD trick_admin.py /home/trick_admin.py
ADD reverse_shell.py /home/reverse_shell.py

ENTRYPOINT /bin/bash -c "while true; do sleep infinity || exit 0; done"
