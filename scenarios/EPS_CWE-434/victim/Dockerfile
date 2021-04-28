FROM ubuntu:16.04
RUN apt-get update && apt-get install -y python3 pstoedit wget

RUN mkdir /service/
RUN mkdir /service/upload/
COPY startup.sh /service/
COPY ImageConverter.py /service/

ENTRYPOINT ["/bin/bash", "/service/startup.sh"]