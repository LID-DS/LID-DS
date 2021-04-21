import random
import pymysql
import traceback
import sys

db = None
words = open('./words.txt').read().splitlines()
# Force insertion at beginning
rd = 1

def do_normal(host, uname, passwd, db_name):
    global db, rd
    if db is None:
        try:
            db = pymysql.connect(host, uname, passwd, db_name)
            print("connected to %s" % host)
        except Exception as e:
            print("Connection exception")
            pass
    try:
        if rd > 0.5:
            word = random.choice(words).replace("'", "")
            sql = "INSERT INTO `texts` (`text`) VALUES ('" + word + "');"
            with db.cursor() as cursor:
                db.begin()
                cursor.execute(sql)
            db.commit()
            print("Insert: " + word)
        else:
            sql = "SELECT * FROM `texts` ORDER BY RAND() LIMIT 1"
            with db.cursor() as cursor:
                cursor.execute(sql)
            result = cursor.fetchone()
            print("Got: " + result[1])
    except Exception as e:
        print("Exception while insert or get")
        pass
    finally:
        rd = random.random()
