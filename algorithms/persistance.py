import json
import os.path

import pandas as pd
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure


def save_to_json(result_dict: dict, path: str):
    """
        convert result dict to correct format
        cut known performance and put the rest into config dict
    """
    performance = {
        "true_positives": int,
        "false_positives": int,
        "true_negatives": int,
        "false_negatives": int,
        "correct_alarm_count": int,
        "exploit_count": int,
        "detection_rate": float,
        "consecutive_false_positives_normal": int,
        "consecutive_false_positives_exploits": int,
        "recall": float,
        "precision_with_cfa": float,
        "precision_with_syscalls": float,
        "f1_cfa": float
    }
    config = {}
    for key in result_dict.keys():
        if key in performance.keys():
            performance[key] = result_dict[key]
        else:
            config[key] = result_dict[key]
    complete_dict = {
        'performance': performance,
        'config': config
    }
    if os.path.exists(path):
        with open(path, 'r') as file:
            result_list = json.load(file)
        result_list.append(complete_dict)
        with open(path, 'w') as file:
            json.dump(result_list, file, indent=2)
    else:
        print('No persistent data yet')
        result_list = [complete_dict]
        with open(path, 'w') as file:
            json.dump(result_list, file, indent=2)


def load_from_json(path: str):
    try:
        with open(path, 'r') as file:
            result_list = json.load(file)
    except IOError:
        print(f'No results at {path}')
        result_list = None
    return result_list


def print_as_table(results: list = None, path: str = None):
    """
    Pretty print a list of dictionaries (myDict) as a dynamically sized table.
    If column names (colList) aren't specified, they will show in random order.
    """
    if results is None and path is None:
        print('Please provide either result list or path to file')
    if results is None:
        results = load_from_json(path)
    config_list = []
    performance_list = []
    for result in results:
        config_list.append(result['config'])
        performance_list.append(result['performance'])
    config = pd.DataFrame(config_list)
    performance = pd.DataFrame(performance_list)
    result_list = pd.concat([performance, config], axis=1)
    print(result_list)


def save_to_mongo(result_dict: dict, db_name: str = 'experiments'):
    """
    opens connection to MongoDB Server and inserts current result document
    """
    try:
        mongo_ip = os.environ['LID_DS_MONGO_IP']
        mongo_user = os.environ['LID_DS_MONGO_USER']
        mongo_pw = os.environ['LID_DS_MONGO_PW']

        client = MongoClient(mongo_ip,
                             username=mongo_user,
                             password=mongo_pw)

        db = client[db_name]
        collection = db[db_name]

        collection.insert_one(result_dict)
        print("Persisted results in MongoDB")
    except ValueError:
        raise ValueError("Please make sure MongoDB Environment Variables are set")
    except ServerSelectionTimeoutError:
        print("Could not connect to Experiment DB")
    except OperationFailure:
        print("Could not persist Data, please check User Credentials. If Credentials are correct please check if your data contains the fields 'config', 'dataset' and 'scenario'")
