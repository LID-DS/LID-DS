import json
from pprint import pprint

from torch.utils import data

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.average import Average
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.time_delta import TimeDelta
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    # dataloader
    #scenario_path = "/home/grimmer/data/LID-DS-2021/CVE-2017-7529"
    #scenario_path = "/home/grimmer/data/LID-DS-2019/CVE-2017-7529/"
    scenario_path = "/home/felix/repos/LID-DS/LID-DS-2021/CVE-2017-7529"
    # scenario_path = "/home/grimmer/Work/LID-DS-2021/ZipSlip"
    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)

    # features
    syscall_to_int = IntEmbedding()
    ngram = Ngram(
        feature_list=[syscall_to_int],
        thread_aware=True,
        ngram_length=5
    )

    # decision engine (DE)
    # de = Som(epochs=500)
    de = Stide(window_length=1000)

    # the IDS
    ids = IDS(data_loader=dataloader,
              feature_list=[ngram],
              decision_engine=de,
              plot_switch=False,
              create_alarms=True)

    print("feature preparation done")
    # training
    ids.train_decision_engine()
    # threshold
    ids.determine_threshold()
    # detection
    ids.do_detection()
    # print results
    pprint(ids.performance.get_performance())
    # draw plot

    with open('alarms.json', 'w') as jsonfile:
        json.dump(ids.performance.alarms.get_alarms_as_dict(), jsonfile, default=str)
