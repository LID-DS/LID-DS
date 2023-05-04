"""
Example execution of LIDS Framework
"""
import os
import sys
from pprint import pprint

from algorithms.decision_engines.coverage import Coverage
from algorithms.decision_engines.coverage_fast import CoverageFast
from algorithms.features.impl.collect_syscall import CollectSyscall
from algorithms.features.impl.hopping_ngram import HoppingNgram
from algorithms.features.impl.process_name import ProcessName
from algorithms.features.impl.return_value import ReturnValue

from dataloader.dataloader_factory import dataloader_factory

from dataloader.direction import Direction

from algorithms.ids import IDS

from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
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

    #LID_DS_VERSION = "LID-DS-2021"
    LID_DS_VERSION = "LID-DS-2019"
    #SCENARIO_NAME = "Bruteforce_CWE-307"
    #SCENARIO_NAME = "CVE-2017-7529"
    SCENARIO_NAME = "SQL_Injection_CWE-89"    
    #SCENARIO_NAME = "CVE-2012-2122"
    # - - - - 
    #SCENARIO_NAME = "CVE-2014-0160"

    scenario_path = f"{LID_DS_BASE_PATH}/{LID_DS_VERSION}/{SCENARIO_NAME}"
    # just load < closing system calls for this example
    dataloader = dataloader_factory(scenario_path,direction=Direction.BOTH)

    ### features (for more information see Paper:
    # https://dbs.uni-leipzig.de/file/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf
    THREAD_AWARE = True
    WINDOW_LENGTH = 100
    
    ### building blocks
    # first: map each systemcall to an integer
    syscall_name = SyscallName()    
    process_name = ProcessName()    
    return_value = ReturnValue(False)

    features = [syscall_name, process_name, return_value]
    #features = [syscall_int_embedding, process_name_int_embedding]
    #features = [syscall_name, process_name]
    collected_features = CollectSyscall(features)

    # now build ngrams from the collected features
    n19 = Ngram([collected_features], THREAD_AWARE, 10)    
    context_window = HoppingNgram([collected_features], THREAD_AWARE, WINDOW_LENGTH, WINDOW_LENGTH)

    # finally calculate the coverage algorithm using these ngrams
    cov = CoverageFast(n19,context_window)

    # decider
    decider = MaxScoreThreshold(cov)
    
    ### the IDS
    ids = IDS(data_loader=dataloader,
              resulting_building_block=decider,
              create_alarms=False,
              plot_switch=False)

    print("at evaluation:")
    # detection
    # normal / seriell
    # results = ids.detect().get_results()
    # parallel / map-reduce
    #results = ids.detect_parallel().get_results()
    results = ids.detect().get_results()
    
    ### print results
    pprint(results)
    cov.draw_histogram(decider._threshold)
    
