FROM python:3.7.5-alpine
RUN apk add --update curl gcc g++
RUN ln -s /usr/include/locale.h /usr/include/xlocale.h
RUN pip3 install pycouchdb faker numpy
WORKDIR /app
ADD couchdb_min.py /app
ADD normal.py /app
# IMPORTANT USE UNBUFFERED OUTPUT (-u)
ENTRYPOINT ["python3", "-u", "normal.py"]
CMD []
