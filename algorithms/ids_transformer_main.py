from algorithms.decision_engines.transfromer import Transformer
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    """
    this is an example script to show the usage uf our classes
    """
    ngram_length = 10
    w2v_size = 5
    w2v_window_size = 5
    thread_aware = True
    scenario_path = f"/home/tini/informatik/ma/LID-DS/Datasets/LID-DS-2021/CVE-2014-0160"

    # data loader for scenario
    dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

    # embedding
    name = SyscallName()

    int_embedding = IntEmbedding()

    ngram = Ngram(
        feature_list=[int_embedding],
        thread_aware=thread_aware,
        ngram_length=ngram_length
    )

    distinct_syscalls = dataloader.distinct_syscalls_training_data()

    # decision engine (DE)
    transformer = Transformer(
        input_vector=ngram,
        distinct_syscalls=distinct_syscalls,
    )

    # define the used features and train
    ids = IDS(
        data_loader=dataloader,
        resulting_building_block=transformer,
        plot_switch=True
    )

    # threshold
    ids.determine_threshold()
    # detection
    # ids.do_detection()
    # pprint(ids.performance.get_performance())

    # ids.plot.feed_figure()
    # ids.plot.show_plot()
