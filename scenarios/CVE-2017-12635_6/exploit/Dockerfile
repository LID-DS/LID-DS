FROM alpine:3.14

RUN apk add --upgrade alpine-sdk jq
RUN apk add nmap python3 py3-pip
RUN pip3 install requests
# install hydra
RUN git clone https://github.com/vanhauser-thc/thc-hydra
# RUN tar -xzf tar.gz
RUN cd thc-hydra && ./configure && make && make install


WORKDIR /app
ADD nmap.sh /app
ADD hydra.sh /app
ADD exploit.py /app
ADD reverse-shell.py /app
ADD short-list.txt /app

# keep container alive
ENTRYPOINT /bin/ash -c "while true; do sleep infinity || exit 0; done"
