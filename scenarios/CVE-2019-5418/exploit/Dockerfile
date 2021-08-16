FROM alpine:3.14
WORKDIR /app
RUN apk update \
    && apk add curl
ADD exploit.sh /app
# keep container alive
ENTRYPOINT /bin/ash -c "while true; do sleep infinity || exit 0; done"
