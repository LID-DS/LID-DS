FROM python:alpine

WORKDIR /run

ARG dependencies
ARG requirements

RUN echo ${dependencies}
RUN echo ${requirements}

RUN test -z ${dependencies} || apk add ${dependencies}
RUN test -z ${requirements} || pip3 install ${requirements}

ENTRYPOINT ["python", "-u", "_base.py"]