FROM debian:9.2

RUN apt-get update && apt-get install -y curl python3 python3-pip

ADD images /home/images
COPY normal.py /home/normal.py

ENTRYPOINT ["python3", "-u", "/home/normal.py"]
CMD []