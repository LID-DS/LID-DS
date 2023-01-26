FROM vulnerables/web-dvwa

RUN sed -i -e 's/impossible/low/g' /var/www/html/config/config.inc.php

RUN apt-get update && apt-get install -y python3 python3-pip wget unzip xvfb udev

# chrome in debian...
RUN echo 'deb http://dl.google.com/linux/chrome/deb/ stable main' >> /etc/apt/sources.list
RUN wget https://dl-ssl.google.com/linux/linux_signing_key.pub
RUN apt-key add linux_signing_key.pub
ARG CHROME_VERSION="86.0.4240.75"
# had to use third party website because google doesnt provide versions for debian 9, which is used in dvwa docker
RUN wget --no-verbose -O /tmp/chrome.deb https://www.slimjet.com/chrome/download-chrome.php?file=files%2F${CHROME_VERSION}%2Fgoogle-chrome-stable_current_amd64.deb \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb
# RUN google-chrome --version

RUN pip3 install --upgrade pip setuptools
RUN pip3 install selenium
RUN pip3 install 'urllib3==1.23' --force-reinstall
RUN pip3 install pyvirtualdisplay
RUN pip3 install requests

RUN wget https://chromedriver.storage.googleapis.com/86.0.4240.22/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip -d /usr/bin
RUN chmod +x /usr/bin/chromedriver

COPY main.sh /
RUN chmod +x /main.sh
COPY dvwa_init.py /tmp/dvwa_init.py

ENTRYPOINT ["./main.sh"]
