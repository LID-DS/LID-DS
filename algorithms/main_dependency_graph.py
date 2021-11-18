from algorithms.features.feature_dependency_manager import FeatureDependencyManager
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.ngram_minus_one import NgramMinusOne
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.thread_change_flag import ThreadChangeFlag
from algorithms.features.impl.w2v_embedding import W2VEmbedding

if __name__ == '__main__':
    scenario_path = "/home/grimmer/Work/LID-DS-2021/CVE-2017-7529"
    ngram_length = 5

    # dependencies needed:
    w2v = W2VEmbedding(vector_size=5, epochs=10, path='Models', force_train=True, distinct=True, window_size=7,
                       thread_aware=True, scenario_path=scenario_path)
    ngram = Ngram(feature_list=[w2v, SyscallName()], thread_aware=True, ngram_length=ngram_length)

    # our feature vector consists of:
    ngmo = NgramMinusOne(ngram=ngram)
    ie = IntEmbedding()
    tcf = ThreadChangeFlag()

    fe = FeatureDependencyManager([ie, ngmo, tcf])
