FROM apache/unomi:1.5.1

RUN apt-get update && apt-get install -y procps

# Adding user for elasticsearch which can not be executed by root
RUN groupadd --gid 5000 elastic \
&& useradd --home-dir /home/elastic --create-home --uid 5000 \
--gid 5000 --shell /bin/sh --skel /dev/null elastic

# Setting up Elasticsearch
RUN mkdir /home/elastic/elasticsearch
RUN cd /home/elastic/elasticsearch && \
    wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.4.2-linux-x86_64.tar.gz && \
    tar -xf elasticsearch-7.4.2-linux-x86_64.tar.gz -C /home/elastic/elasticsearch && \
    chown -R elastic /home/elastic/elasticsearch/
RUN rm /home/elastic/elasticsearch/elasticsearch-7.4.2/config/elasticsearch.yml
COPY elasticsearch.yml /home/elasticsearch/elasticsearch-7.4.2/config/

WORKDIR /home/elastic/elasticsearch/elasticsearch-7.4.2/bin/

RUN chown -R elastic /opt/apache-unomi

USER elastic

# Starting Elasticsearch and unomi on Startup
ENTRYPOINT ./elasticsearch -d && \
           sh /opt/apache-unomi/entrypoint.sh