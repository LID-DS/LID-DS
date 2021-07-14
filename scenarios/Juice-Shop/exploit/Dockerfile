FROM debian:10

RUN apt-get update \
    && apt-get install -y wget python3 python3-pip wget unzip xvfb udev curl

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

# add attack handler
ADD run_attacker.py /home/run_attacker.py
# add attacks
ADD sql_injection_cred.sh /home/sql_injection_cred.sh
ADD sql_injection_schema.sh /home/sql_injection_schema.sh
ADD sql_injection_user.py /home/sql_injection_user.py
ADD userAction.py /home/userAction.py
RUN chmod +x /home/sql_injection_cred.sh
RUN chmod +x /home/sql_injection_schema.sh
WORKDIR /home/

ENTRYPOINT ["python3", "-u", "run_attacker.py"]
CMD []
