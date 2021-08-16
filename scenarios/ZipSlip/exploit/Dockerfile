FROM python:3.8-slim

RUN apt-get update && apt-get install -y curl procps

# copy exploit script
COPY exploit.py /home/exploit.py
# copy evil.zip
COPY evil.zip /home/evil.zip

# start the container
ENTRYPOINT /bin/bash -c "while true; do sleep infinity || exit 0; done"
