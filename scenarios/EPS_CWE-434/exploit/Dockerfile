FROM debian:9.2

RUN apt-get update && apt-get install -y curl python3 python3-pip procps

COPY image_0501.eps /home/image_0501.eps
COPY exploit.py /home/exploit.py

ENTRYPOINT /bin/bash -c "while true; do sleep infinity || exit 0; done"
