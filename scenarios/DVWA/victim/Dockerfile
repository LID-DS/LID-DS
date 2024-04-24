FROM debian:buster

# installing prerequisites
RUN apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    debconf-utils && \
    echo mariadb-server mysql-server/root_password password vulnerables | debconf-set-selections && \
    echo mariadb-server mysql-server/root_password_again password vulnerables | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 \
    mariadb-server \
    mariadb-client \
    php \
    php-mysql \
    php-pgsql \
    php-pear \
    php-gd \
    libapache2-mod-php \
    python3 \
    python3-pip \
    wget \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    libpango-1.0-0 \
    libu2f-udev \
    libvulkan1 \
    libnspr4 \
    libnss3 \
    libgtk-3-0 \
    libgbm1 \
    fonts-liberation \
    libasound2 \
    libcurl3-gnutls \
    unzip \
    xvfb \
    udev \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# install chrome
RUN wget https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_109.0.5414.74-1_amd64.deb
RUN dpkg -i google-chrome-stable_109.0.5414.74-1_amd64.deb

# python related
RUN pip3 install --upgrade pip setuptools
RUN pip3 install selenium==4.8.0 PyVirtualDisplay==3.0 requests==2.28.2 numpy==1.21.6 essential-generators==1.0
RUN pip3 install 'urllib3==1.26' --force-reinstall

# install chrome selenium driver
RUN wget https://chromedriver.storage.googleapis.com/109.0.5414.74/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip -d /usr/bin
RUN chmod +x /usr/bin/chromedriver

# copy config files
COPY php.ini  /etc/php/*/apache2/php.ini
COPY dvwa /var/www/html
COPY config.inc.php /var/www/html/config/

# set permissions and remove old index file
RUN chown www-data:www-data -R /var/www/html && \
    rm /var/www/html/index.html

# start mysql server and init db
RUN service mysql start && \
    sleep 3 && \
    mysql -uroot -pvulnerables -e "CREATE USER dvwa@localhost IDENTIFIED BY 'p@ssw0rd';CREATE DATABASE dvwa;GRANT ALL privileges ON dvwa.* TO 'dvwa'@localhost;"


# copy init script
COPY dvwa_init.py /tmp/dvwa_init.py

EXPOSE 80

COPY main.sh /
ENTRYPOINT ["/main.sh"]