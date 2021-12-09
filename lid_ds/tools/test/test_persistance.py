from lid_ds.tools.persistance import save_to_json, load_from_json

import os

def test_persistance():
    example_dict_1 = {
        "scenario": "CVE-2021-666",
        "thread_aware": True,
        "n_gram": 7,
        "window_length": 1000,
        "false_positives": 0,
        "true_posotives":10000,
        "alarm_count": 667,
        "detection_rate": 0.99999,
        "recall": 0.42,
    }
    example_dict_2 = {
        "scenario": "CVE-2021-667",
        "thread_aware": True,
        "n_gram": 7,
        "architecture": "small",
        "window_length": 1000,
        "false_positives": 0,
        "true_posotives":10000,
        "alarm_count": 667,
        "detection_rate": 0.99999,
        "recall": 0.42,
    }

    try:
        path = "algorithms/persistent_data/example_config.json"

        save_to_json(example_dict_1, path)

        results = load_from_json(path)

        print(results)
        assert results[0]['results'] == {'false_positives': example_dict_1['false_positives'],
                                         'true_positives': example_dict_1['false_positives'],
                                         'alarm_count': example_dict_1['false_positives'],
                                         'detection_rate': example_dict_1['false_positives'],
                                         'recall': example_dict_1['false_positives'],
                                         'false_positives': example_dict_1['false_positives'],
                                         }

        save_to_json(example_dict_2, path)

        results = load_from_json(path)

        print(results)
        assert results[1] == example_dict_2

        assert results == [example_dict_1, example_dict_2]

        print(results)
        os.remove(path)
    except AssertionError as e:
        print(e)
        os.remove(path)
        assert e == 2

