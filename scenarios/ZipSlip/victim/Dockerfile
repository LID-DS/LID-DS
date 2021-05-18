FROM ubuntu:16.04

RUN apt-get update \
    && apt-get install -y software-properties-common \
    && add-apt-repository ppa:openjdk-r/ppa \
    && apt-get update \
    && apt-get install -y python3 openjdk-11-jdk

RUN mkdir /service/
RUN mkdir /service/upload/
COPY startup.sh /service/
COPY ZipService.py /service/
COPY zipslip-1.0.0.jar /service/

CMD ["/bin/bash", "/service/startup.sh"]
