FROM python:3.7-alpine

RUN pip3 install requests bs4

COPY normal.py /home/normal.py
COPY upload_files /home/upload_files 

ENTRYPOINT ["python3", "/home/normal.py"]
CMD []


