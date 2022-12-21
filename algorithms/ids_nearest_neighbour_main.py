"""
Example execution of LIDS Framework
"""
import os
import sys
from pprint import pprint

from algorithms.features.impl.nearest_neighbour import NearestNeighbour
from dataloader.dataloader_factory import dataloader_factory

from dataloader.direction import Direction

from algorithms.ids import IDS

from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.ngram import Ngram




if __name__ == '__main__':

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        LID_DS_BASE_PATH = sys.argv[1]
    else:
        try:
            LID_DS_BASE_PATH = os.environ['LID_DS_BASE']
        except KeyError as exc:
            raise ValueError("No LID-DS Base Path given."
                             "Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE") from exc

    LID_DS_VERSION = "LID-DS-2019"
    SCENARIO_NAME = "CVE-2017-7529"


    scenario_path = f"{LID_DS_BASE_PATH}/{LID_DS_VERSION}/{SCENARIO_NAME}"
    dataloader = dataloader_factory(scenario_path, direction=Direction.BOTH)


    THREAD_AWARE = True
    WINDOW_LENGTH = 1000
    NGRAM_LENGTH = 5

    ### building blocks
    syscall_name = SyscallName()
    int_embedding = IntEmbedding(syscall_name)
    ngram = Ngram([int_embedding], True, 5)
    nn = NearestNeighbour(ngram)

    ids = IDS(data_loader=dataloader,
              resulting_building_block=nn,
              create_alarms=True,
              plot_switch=False)

    print("at evaluation:")

    results = ids.detect().get_results()
    pprint(results)

