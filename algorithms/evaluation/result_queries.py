"""
queries for gathering best results in DB
"""

import os

import pymongo
from tabulate import tabulate


MONGO_IP = os.environ['LID_DS_MONGO_IP']
MONGO_PORT = 27017
MONGO_USER = os.environ['LID_DS_MONGO_USER']
MONGO_PW = os.environ['LID_DS_MONGO_PW']

client = pymongo.MongoClient(
                    MONGO_IP,
                    MONGO_PORT,
                    username=MONGO_USER,
                    password=MONGO_PW)
db = client['experiments']
col = db['experiments']

ae_query = \
    [
        {
            '$match': {
                'algorithm': 'AE'
            }
        }, {
            '$group': {
                '_id': {
                    'dataset': '$dataset',
                    'algorithm': '$algorithm',
                    'ngram_length': '$ngram_length',
                    'stream_sum': '$stream_sum',
                    'flag': '$flag',
                    'embedding': '$embedding'
                },
                'avg_DR': {
                    '$avg': '$detection_rate'
                },
                'avg_FA': {
                    '$avg': {
                        '$add': [
                            '$consecutive_false_positives_exploits',
                            '$consecutive_false_positives_normal'
                        ]
                    }
                },
                'sum_FA': {
                    '$sum': {
                        '$add': [
                            '$consecutive_false_positives_exploits',
                            '$consecutive_false_positives_normal'
                        ]
                    }
                },
                'count': {
                    '$sum': 1
                }
            }
        }, {
            '$sort': {
                'avg_DR': -1,
                'avg_FA': 1
            }
        }
    ]

doc = col.aggregate(ae_query)
table_list = []

for entry in doc:
    dataset = entry['_id']['dataset']
    algorithm = entry['_id']['algorithm']
    ngram_length = entry['_id']['ngram_length']
    stream_sum = entry['_id']['stream_sum']
    embedding = entry['_id']['embedding']
    dr = entry['avg_DR']
    avg_fa = entry['avg_DR']

    table_list.append([dataset, algorithm, ngram_length, stream_sum, embedding, dr, avg_fa])

print(tabulate(table_list,
      headers=['Dataset',
               'Algorithm',
               'Ngram',
               'Stream Sum',
               'Embedding',
               'DR',
               'avg CFA'], tablefmt='orgtbl'))
