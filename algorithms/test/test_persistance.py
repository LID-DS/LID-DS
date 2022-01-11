from algorithms.persistance import save_to_json, load_from_json

import os

def test_persistance():
    example_dict_1 = {
        "scenario": "CVE-2021-666",
        "thread_aware": True,
        "n_gram": 7,
        "window_length": 1000,
        "true_positives":10000,
        "false_positives": 0,
        "true_negatives": 10,
        "false_negatives": 0,
        "alarm_count": 667,
        "exploit_count": 667,
        "detection_rate": 0.99999,
        "consecutive_false_positives_normal": 0,
        "consecutive_false_positives_exploits": 0,
        "recall": 0.42,
        "precision_with_cfa": 0.42,
        "precision_with_syscalls": 0.42
    }
    example_dict_2 = {
        "scenario": "CVE-2021-667",
        "thread_aware": True,
        "n_gram": 7,
        "architecture": "small",
        "window_length": 1000,
        "true_positives":10000,
        "false_positives": 0,
        "true_negatives": 10,
        "false_negatives": 0,
        "alarm_count": 667,
        "exploit_count": 667,
        "detection_rate": 0.99999,
        "consecutive_false_positives_normal": 0,
        "consecutive_false_positives_exploits": 0,
        "recall": 0.42,
        "precision_with_cfa": 0.42,
        "precision_with_syscalls": 0.42
    }

    try:
        path = "algorithms/persistent_data/example_config.json"

        save_to_json(example_dict_1, path)

        results = load_from_json(path)

        assert results[0]['performance'] == {'false_positives': example_dict_1['false_positives'],
                                         'true_positives': example_dict_1['true_positives'],
                                         'true_negatives': example_dict_1['true_negatives'],
                                         'false_negatives': example_dict_1['false_negatives'],
                                         'alarm_count': example_dict_1['alarm_count'],
                                         'exploit_count': example_dict_1['exploit_count'],
                                         'detection_rate': example_dict_1['detection_rate'],
                                         'consecutive_false_positives_normal': example_dict_1['consecutive_false_positives_normal'],
                                         'consecutive_false_positives_exploits': example_dict_1['consecutive_false_positives_exploits'],
                                         'recall': example_dict_1['recall'],
                                         'precision_with_cfa': example_dict_1['precision_with_cfa'],
                                         'precision_with_syscalls': example_dict_1['precision_with_syscalls'],
                                         }
        assert results[0]['config'] == {'scenario': example_dict_1['scenario'],
                                        'thread_aware': example_dict_1['thread_aware'],
                                        'n_gram': example_dict_1['n_gram'],
                                        'window_length': example_dict_1['window_length']
                                        }

        save_to_json(example_dict_2, path)

        results = load_from_json(path)

        assert results[1]['performance'] == {'false_positives': example_dict_2['false_positives'],
                                         'true_positives': example_dict_2['true_positives'],
                                         'true_negatives': example_dict_2['true_negatives'],
                                         'false_negatives': example_dict_2['false_negatives'],
                                         'alarm_count': example_dict_2['alarm_count'],
                                         'exploit_count': example_dict_2['exploit_count'],
                                         'detection_rate': example_dict_2['detection_rate'],
                                         'consecutive_false_positives_normal': example_dict_2['consecutive_false_positives_normal'],
                                         'consecutive_false_positives_exploits': example_dict_2['consecutive_false_positives_exploits'],
                                         'recall': example_dict_2['recall'],
                                         'precision_with_cfa': example_dict_2['precision_with_cfa'],
                                         'precision_with_syscalls': example_dict_2['precision_with_syscalls'],
                                         }
        assert results[1]['config'] == {'scenario': example_dict_2['scenario'],
                                        'thread_aware': example_dict_2['thread_aware'],
                                        'n_gram': example_dict_2['n_gram'],
                                        'window_length': example_dict_2['window_length'],
                                        'architecture': example_dict_2['architecture']
                                        }

        os.remove(path)
    except AssertionError as e:
        print(e)
        os.remove(path)
        assert e == 2

