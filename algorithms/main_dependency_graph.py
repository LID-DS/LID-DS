import networkx as nx

from algorithms.features.int_feature import IntEmbedding
from algorithms.features.ngram_feature import Ngram
from algorithms.features.ngram_minus_one_feature import NgramMinusOne
from algorithms.features.threadID_feature import ThreadID
from algorithms.features.thread_change_flag_feature import ThreadChangeFlag
from algorithms.features.w2v_feature import W2VEmbedding


def feature_extractor(list_of_features):
    dependency_grpah = nx.DiGraph()

    todo = []
    tmp_todo = []
    for feature in list_of_features:
        todo.append(feature)

    while len(todo) > 0:
        for source_feature in todo:
            if source_feature != "syscall":
                for destination_feature in source_feature.dependend_on():
                    dependency_grpah.add_edge(type(source_feature).__name__, type(destination_feature).__name__)
                    tmp_todo.append(destination_feature)
        todo = tmp_todo
        tmp_todo = []

    dot = nx.drawing.nx_pydot.to_pydot(dependency_grpah)
    print(dot)

    # determine order of calculation by topological sorting the underliying dag
    topological_sort = list(reversed(list(nx.topological_sort(dependency_grpah))))
    print(topological_sort)



if __name__ == '__main__':
    scenario_path = "/home/grimmer/Work/LID-DS-2021/CVE-2017-7529"
    ngram_length = 5

    w2ve = W2VEmbedding(vector_size=5, epochs=10, path='Models', force_train=True, distinct=True, window_size=7,
                        thread_aware=True, scenario_path=scenario_path)
    inte = IntEmbedding()
    tid = ThreadID()

    ngram = Ngram(feature_list=[w2ve, tid], thread_aware=True, ngram_length=ngram_length)

    tcf = ThreadChangeFlag(feature_list=[tid, ngram], thread_aware=True, ngram_length=5)
    ngramm1 = NgramMinusOne(feature_list=[ngram], thread_aware=True, ngram_length=5)

    feature_list = [inte, ngramm1, tcf]
    feature_extractor(feature_list)
