import os
import sys
import csv

from algorithms.persistance import load_from_json


def create_header(csv_path: str, results: list):
    """
        iterate through all results and extract keys
    """
    header = []
    for result in results:
        for key in result['config'].keys():
            if key not in header:
                header.append(key)
    for result in results:
        for key in result['performance'].keys():
            if key not in header:
                header.append(key)
    return header

if __name__ == "__main__":

    # retrieve result json path
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = '../algorithms/persistent_data/stide_flag_mode.json'
        print('No result path provided in command -> use default one')
    results = load_from_json(path)
    
    # retrieve csv path
    if len(sys.argv) > 1:
        csv_path = sys.argv[2]
    else:
        csv_path = 'test.csv'
        print('No csv_path provided in command -> use default one')

    # create header
    header_list = create_header(csv_path, results)
    if os.path.exists(csv_path):
        write_header = True
    else:
        write_header = False

    with open(csv_path, 'w') as f:
        if write_header:
            joined_list = ",".join(header_list)
            f.write(joined_list + '\n')
        for result in results:
            row = ''
            for entry in header_list: 
                try:
                    # try to extract current column from config
                    row = row + f"{result['config'][entry]},"
                except KeyError:
                    try:
                        # if column not in config try performance 
                        row = row + f"{result['performance'][entry]},"
                    except KeyError:
                        # if column does not exist write None
                        row = row + 'None,'
            f.write(row + '\n')
        print('CSV created.')
