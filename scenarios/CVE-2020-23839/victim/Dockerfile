FROM php:7.4.9-apache-buster
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /var/www/html

# dependencies
RUN apt-get update && \
    apt-get -y install curl zip libzip-dev libgd-dev unzip && \
    apt-get -yq autoremove && \
    apt-get clean && \
    rm -rf /var/lib/{apt,dpkg,cache,log}

COPY app.zip .

# setup GetSimple cms wit simple website
RUN mkdir /tmp/app && \
    unzip app.zip -d /tmp/app && \
    mv /tmp/app/html/* . && \
    mv $PHP_INI_DIR/php.ini-development $PHP_INI_DIR/php.ini && \
    docker-php-ext-configure gd \
        --with-freetype=/usr/lib/ \
        --with-jpeg=/usr/lib/ && \
    docker-php-ext-configure zip && \
    docker-php-ext-install -j$(nproc) gd opcache zip && \
    a2enmod rewrite && \
    chown -R www-data.www-data .

COPY add_hostname.sh .
