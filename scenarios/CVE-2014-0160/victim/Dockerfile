FROM ubuntu:13.04

RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list 
RUN sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list 

RUN apt-get update && apt-get install -y apache2 tcpdump php5 libapache2-mod-php5 unzip

RUN mkdir -p /etc/apache2/conf.d/
RUN mkdir /var/run/apache2

RUN mkdir /etc/apache2/ssl
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"  

ADD default-ssl /etc/apache2/sites-available/default-ssl

RUN mkdir /var/www/private
RUN mkdir /var/www/private/uploads
RUN chmod a+w /var/www/private/uploads
ADD upload.php /var/www/private/upload.php
ADD index.html /var/www/private/index.html

COPY unapp.zip /home/unapp.zip
RUN unzip /home/unapp.zip
RUN rm /var/www/index.html
RUN cp -r unapp/* /var/www/

RUN a2enmod ssl
RUN a2ensite default-ssl

EXPOSE 443

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

CMD /usr/sbin/apache2ctl -D FOREGROUND

ADD create_users.sh /home/
RUN chmod +x /home/create_users.sh
RUN ./home/create_users.sh
