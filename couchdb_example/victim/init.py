import json
import logging
import os
import couchdb
import requests
from faker import Faker
import numpy

ADMIN_U = "admin"
ADMIN_PW = "admin"
faker = Faker('de_DE')


def _generate_project():
    return {
        'name': faker.company(),
        'phrase': faker.catch_phrase(),
        'address': {
            'city': faker.city(),
            'postcode': faker.postcode(),
            'street': faker.street_address(),
        }
    }


def init(host, logger, valid_user=True):
    URL_PLAIN = "http://%s" % host
    URL_ADMIN = "http://%s:%s@%s" % (ADMIN_U, ADMIN_PW, host)

    # SETUP Server
    requests.post("%s/_cluster_setup" % URL_PLAIN,
                  headers={"Content-Type": "application/json"},
                  data=json.dumps({
                      "action": "enable_single_node",
                      "username": ADMIN_U,
                      "password": ADMIN_PW
                  }))
    requests.post("%s/_node/nonode@nohost/_config/chttpd/bind_address" % URL_ADMIN, data='"::"')
    requests.post("%s/_node/nonode@nohost/_config/couchdb/max_dbs_open" % URL_ADMIN, data='"1000"')

    # Require a valid user
    if valid_user:
        requests.put("%s/_node/nonode@nohost/_config/chttpd/require_valid_user" %
                     URL_ADMIN,
                     data='"true"')
        requests.put("%s/_node/nonode@nohost/_config/httpd/WWW-Authenticate" %
                 URL_ADMIN,
                 data='"Basic realm=\"administrator\""')

    logger.debug("Server Setup")

    COUCH = couchdb.Server(URL_ADMIN)
    db = COUCH.create("projects")
    logger.debug("created projects")
    db.update([_generate_project() for _ in range(int(numpy.random.uniform(45, 55)))])
    db = COUCH['_users']
    local_dir = os.path.dirname(os.path.realpath(__file__))
    db.update(json.load(open(os.path.join(local_dir, "db/_users.json"))))
    logger.debug("inserted users")


if __name__ == '__main__':
    init("localhost:5984", logging)
