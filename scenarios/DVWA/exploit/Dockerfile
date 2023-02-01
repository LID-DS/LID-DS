FROM alpine:3.14

RUN echo "http://dl-4.alpinelinux.org/alpine/v3.8/main" >> /etc/apk/repositories && \
	echo "http://dl-4.alpinelinux.org/alpine/v3.8/community" >> /etc/apk/repositories

# Install Python3
RUN apk update && apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --upgrade pip setuptools && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    if [[ ! -e /usr/bin/python ]]; then ln -sf /usr/bin/python3 /usr/bin/python; fi && \
    rm -r /root/.cache

# Install chromedriver and selenium driver
RUN apk add curl unzip libexif udev chromium chromium-chromedriver xvfb libffi-dev py3-cffi py3-psutil && \
	pip install selenium && \
	pip install pyvirtualdisplay && \
	pip install nclib

ADD exploit.py /home/exploit.py
ADD evil_script.php /home/evil_script.php

ENTRYPOINT ["python3", "-u", "/home/exploit.py"]
CMD []