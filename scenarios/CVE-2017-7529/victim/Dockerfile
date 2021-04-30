FROM ubuntu:14.04

# install dependencies
RUN apt-get update
RUN apt-get install -y wget build-essential libpcre3 libpcre3-dev openssl libssl-dev openssh-server zlib1g-dev unzip apache2-utils

# download and configure vulnerable nginx 1.6.3
RUN wget http://nginx.org/download/nginx-1.6.3.tar.gz
RUN tar -xzvf nginx-1.6.3.tar.gz
WORKDIR nginx-1.6.3
RUN chmod +x configure
RUN ./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --with-http_ssl_module --with-pcre
RUN make
RUN make install

# unpack and deploy Web App
COPY unapp.zip unapp.zip
RUN unzip unapp.zip
RUN rm /etc/nginx/html/index.html
RUN mv unapp/* /etc/nginx/html/

# check nginx config
RUN /usr/sbin/nginx -t -c /etc/nginx/nginx.conf

# create users
COPY create_users.sh create_users.sh
RUN chmod +x create_users.sh
RUN ./create_users.sh

# start nginx server
ENTRYPOINT /usr/sbin/nginx -c /etc/nginx/nginx.conf && /bin/bash