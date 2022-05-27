# partly taken from phocean/msf on https://hub.docker.com/r/phocean/msf/ or https://github.com/phocean/dockerfile-msf

FROM ubuntu:bionic-20210702

ARG DEBIAN_FRONTEND=noninteractive

# PosgreSQL DB
COPY db.sql /tmp/

# Startup script
COPY init.sh /usr/local/bin/init.sh

WORKDIR /opt

# Installation
RUN apt-get -qq update \
  && apt-get -yq install --no-install-recommends build-essential patch ruby-bundler ruby-dev zlib1g-dev liblzma-dev git autoconf build-essential libpcap-dev libpq-dev libsqlite3-dev python3-setuptools\
    postgresql postgresql-contrib postgresql-client \
    ruby python \
    dialog apt-utils \
    nmap nasm\
    python3\
    python3-pip \
  && echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections \
  && git clone https://github.com/rapid7/metasploit-framework.git \
  && cd metasploit-framework \
  && git fetch --tags \
  && git checkout 6.1.5 \
  && rm Gemfile.lock \
  && bundle install \
  && /etc/init.d/postgresql start && su postgres -c "psql -f /tmp/db.sql" \
  && apt-get -y remove --purge build-essential patch ruby-dev zlib1g-dev liblzma-dev git autoconf build-essential libpcap-dev libpq-dev libsqlite3-dev \
  dialog apt-utils \
  && apt-get -y autoremove \
  && apt-get -y clean \
  && rm -rf /var/lib/apt/lists/*

# DB config
COPY database.yml /opt/metasploit-framework/config/

RUN pip3 install pymetasploit3

# Configuration and sharing folders
VOLUME /root/.msf4/
VOLUME /tmp/data/

# Locales for tmux
ENV LANG C.UTF-8
WORKDIR /opt/metasploit-framework

RUN sh /usr/local/bin/init.sh

ADD exploit.py exploit.py


ENTRYPOINT ["python3", "-u", "exploit.py"]
CMD []
