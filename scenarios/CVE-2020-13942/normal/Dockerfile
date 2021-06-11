FROM debian:9.2

RUN apt-get update && apt-get install -y curl python3 python3-pip

RUN pip3 install requests names

COPY bodies.py /home/bodies.py
COPY normal.py /home/normal.py

ENTRYPOINT ["python3", "/home/normal.py"]
CMD []