import argparse

import torch

from algorithms.evaluation.fluctuation_analysis.utils import ngram_sets, get_anomaly_scores_for_epochs, \
    cache_losses, prepare_ae_ngs, train_ae_model
from dataloader.direction import Direction

learning_rate = 0.001
direction = Direction.OPEN
batch_size = 256


def parse_args():
    parser = argparse.ArgumentParser(
        description='Fluctuation Analysis with Autoencoder\n'
                    'Prepare data, train model, and cache anomaly scores and losses.'
    )

    parser.add_argument(
        '-bp', dest='base_path', action='store', type=str, required=True,
        help='LID-DS base path'
    )
    parser.add_argument(
        '-ds', dest='dataset', action='store', type=str, required=True,
        help='LID-DS version'
    )
    parser.add_argument(
        '-s', dest='scenario', action='store', type=str, required=True,
        help='Scenario name'
    )
    parser.add_argument(
        '-c', dest='checkpoint_dir', action='store', type=str, required=True,
        help='Models checkpoint base directory'
    )
    parser.add_argument(
        '-n', dest='ngram_length', action='store', type=int, required=True,
        help='Ngram length'
    )

    parser.add_argument(
        '-e', dest='evaluate', type=lambda x: (str(x).lower() == 'true'), required=True,
        help='Evaluate'
    )

    parser.add_argument(
        '-cs', dest='custom_split', type=lambda x: (str(x).lower() == 'true'), required=False,
        help='Use custom split'
    )
    parser.add_argument(
        '-eal', dest='eval_after_load', type=lambda x: (str(x).lower() == 'true'), required=False,
        help='Evaluate after loading'
    )
    parser.add_argument(
        '-do', dest='dropout', action='store', type=float, required=False,
        help='Dropout'
    )

    return parser.parse_args()


def main():
    args = parse_args()
    print(args)
    dataset_base = args.base_path
    dataset = args.dataset
    scenario = args.scenario
    checkpoint_dir = args.checkpoint_dir
    ngram_length = args.ngram_length
    evaluate = args.evaluate

    scenario_ngs = prepare_ae_ngs(dataset_base, ngram_length, direction, dataset, scenario, base_path=checkpoint_dir)

    if evaluate:
        custom_split = args.custom_split
        eval_after_load = args.eval_after_load
        dropout = args.dropout
        NGS = ngram_sets(scenario_ngs)
        syscall_dict, _ = scenario_ngs.syscall_dict

        if not torch.cuda.is_available():
            print(
                f"CUDA NOT AVAILABLE redo: "
                f"[AE, '{dataset}', '{scenario}', {ngram_length}, {dropout}, {custom_split}, {eval_after_load}] "
            )
            exit(1)

        torch.manual_seed(42)
        model_ae = train_ae_model(
            scenario,
            dataset,
            ngram_length,
            dropout,
            learning_rate,
            direction,
            custom_split,
            NGS,
            epochs=900,
            base_path=checkpoint_dir
        )
        model_ae.use_cache = True
        if eval_after_load:
            model_ae.use_cache = False
            model_ae.eval_after_load = eval_after_load
        config = ("AE", dataset, scenario, ngram_length, dropout,custom_split, eval_after_load)
        _ = get_anomaly_scores_for_epochs(model_ae, range(1, 900, 5), NGS, scenario_ngs, config, checkpoint_dir)
        cache_losses(model_ae, config, base_path=checkpoint_dir)


if __name__ == '__main__':
    main()
