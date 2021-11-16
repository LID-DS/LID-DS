from algorithms.features.FeatureExtractor import FeatureExtractor
from algorithms.features.int_embedding import IntEmbedding
from algorithms.features.ngram import Ngram
from algorithms.features.ngram_minus_one import NgramMinusOne
from algorithms.features.thread_change_flag import ThreadChangeFlag
from algorithms.features.w2v_embedding import W2VEmbedding

if __name__ == '__main__':
    scenario_path = "/home/grimmer/Work/LID-DS-2021/CVE-2017-7529"
    ngram_length = 5

    w2v = W2VEmbedding(vector_size=5, epochs=10, path='Models', force_train=True, distinct=True, window_size=7,
                       thread_aware=True, scenario_path=scenario_path)
    ngram = Ngram(feature_list=[w2v], thread_aware=True, ngram_length=ngram_length)
    ngmo = NgramMinusOne(feature_list=[ngram], thread_aware=True, ngram_length=ngram_length)
    tcf = ThreadChangeFlag()
    ie = IntEmbedding()

    FeatureExtractor([ie, ngmo, tcf])
