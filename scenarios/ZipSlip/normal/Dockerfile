FROM python:3.8-slim

RUN apt-get update && apt-get install -y curl

# copy normal scripts
COPY normal.py /home/normal.py
# add wiki data to image
COPY filesplits/ /home/filesplits/

# run the normal behaviour
ENTRYPOINT ["python3", "-u", "/home/normal.py"]
CMD []