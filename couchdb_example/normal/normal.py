import random
import sys
import time
import numpy
import couchdb_min
from faker import Faker

faker = Faker()

host = sys.argv[1]

admins = [('admin', 'admin')]
user = [('dbreader', 'dbreader'), ('guest', 'dbpass')]
dbs = {"projects": []}


def _update_doc_data(doc):
    return {
        **doc,
        'name': faker.company(),
        'phrase': faker.catch_phrase(),
        'address': {
            'country': faker.country(),
            'city': faker.city(),
            'postcode': faker.postcode(),
            'street': faker.street_address(),
        }
    }


def connect(admin=False):
    account = random.choice(admins if admin else user)
    return couchdb_min.Server(host, account[0], account[1])


def create_database():
    word = faker.word()
    while word in dbs:
        word = faker.word()
    conn = connect(True)
    new_db = conn.create(word)
    doc = new_db.save(_update_doc_data({}))
    dbs[word] = [doc['_id']]
    print("Created database %s with entry %s" % (word, doc))
    user_db = conn.get('_users')
    # update each user roles
    for u, _ in user:
        user_data = user_db.get('org.couchdb.user:' + u)
        user_data['roles'].append(word)
        user_db.save(user_data)
        print("Gave access for user %s to database %s" % (u, word))


def query(db=None):
    if not db:
        db = random.choice(list(dbs.keys()))
    dbs[db] = connect().get(db).all_ids()
    print("GOT %s from database %s" % (len(dbs[db]), db))


def update_document():
    db = random.choice(list(dbs.keys()))
    if len(dbs[db]) == 0:
        query(db)
    conn = connect().get(db)
    doc = conn.get(random.choice(dbs[db]))
    updated_doc = conn.save(_update_doc_data(doc))
    print("Update of doc %s in database %s" % (updated_doc, db))


def delete_document():
    db = random.choice(list(dbs.keys()))
    if len(dbs[db]) == 0:
        query(db)
    conn = connect().get(db)
    doc_id = random.choice(dbs[db])
    conn.delete(doc_id)
    dbs[db].remove(doc_id)

    print("Deleted doc %s in database %s" % (doc_id, db))


def new_document():
    db = random.choice(list(dbs.keys()))
    conn = connect().get(db)
    inserted_doc = conn.save(_update_doc_data({}))
    dbs[db].append(inserted_doc['_id'])
    print("Inserted %s into %s" % (inserted_doc, db))


def wrong_login():
    couchdb_min.Server(host, faker.first_name(), faker.password(8)).info()
    print("Executed wrong login")


if __name__ == '__main__':
    while True:
        sys.stdin.readline()
        # for distribution check /_stats
        try:
            mapping = {
                'create': create_database,
                'wrong': wrong_login,
                'query': query,
                'delete': delete_document,
                'update': update_document,
                'new': new_document,
            }
            choice = numpy.random.choice(list(mapping.keys()), p=[0.1, 0.1, 0.3, 0.1, 0.2, 0.2])
            mapping[choice]()
        except Exception as e:
            print("Exception", e)

