FROM vulnerables/web-dvwa

RUN sed -i -e 's/impossible/low/g' /var/www/html/config/config.inc.php

RUN apt-get update && apt-get install -y python3 python3-pip wget unzip xvfb udev

# chrome in debian...
RUN echo 'deb http://dl.google.com/linux/chrome/deb/ stable main' >> /etc/apt/sources.list
RUN wget https://dl-ssl.google.com/linux/linux_signing_key.pub
RUN apt-key add linux_signing_key.pub
RUN apt-get update && apt-get install -y google-chrome-stable

RUN pip3 install --upgrade pip setuptools
RUN pip3 install selenium
RUN pip3 install 'urllib3==1.23' --force-reinstall
RUN pip3 install pyvirtualdisplay
RUN pip3 install requests

RUN wget https://chromedriver.storage.googleapis.com/2.42/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip -d /usr/bin
RUN chmod +x /usr/bin/chromedriver

COPY main.sh /
RUN chmod +x /main.sh
COPY dvwa_init.py /tmp/dvwa_init.py

ENTRYPOINT ["./main.sh"]
