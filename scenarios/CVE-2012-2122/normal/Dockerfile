FROM python:3-alpine3.14
RUN pip3 install pymysql
WORKDIR /app
ADD words.txt /app
ADD normal.py /app
# IMPORTANT USE UNBUFFERED OUTPUT (-u)
ENTRYPOINT ["python3", "-u", "normal.py"]
CMD []
