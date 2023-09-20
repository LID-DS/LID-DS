import os
import pickle
from pprint import pprint
from typing import Iterable

import numpy as np
import torch
from matplotlib import pyplot as plt
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import train_test_split
from tqdm import tqdm

from algorithms.data_preprocessor import DataPreprocessor
from algorithms.decision_engines.ae import AE
from algorithms.decision_engines.transformer import Transformer, AnomalyScore
from algorithms.evaluation.fluctuation_analysis.anomaly_scores import AnomalyScores
from algorithms.evaluation.fluctuation_analysis.ngrams_collector import NgramsCollector
from algorithms.evaluation.fluctuation_analysis.ngs import Ngs
from algorithms.features.impl.int_embedding import IntEmbeddingConcat
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.persistance import ModelCheckPoint
from dataloader.base_data_loader import BaseDataLoader
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
from dataloader.recording_2019 import Recording2019


def collect_ngrams(ngram_bb: Ngram, scenario_path, direction: Direction) -> NgramsCollector:
    collector = NgramsCollector(ngram_bb)

    dataloader: BaseDataLoader = dataloader_factory(scenario_path, direction)
    data_preprocessor = DataPreprocessor(dataloader, collector)

    for recording in tqdm(dataloader.test_data()):
        if recording.metadata()["exploit"]:
            collector.recording(recording.name)
            current_exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            for syscall in recording.syscalls():
                collector.exploit_on(syscall)
                syscall_time = syscall.timestamp_unix_in_ns() * 1e-9
                if syscall_time < current_exploit_time:
                    collector.before_exploit_on(syscall)
                else:
                    collector.after_exploit_on(syscall)
        else:
            for syscall in recording.syscalls():
                collector.normal_on(syscall)
        data_preprocessor.new_recording()
    return collector


def scenario_stats(collector: NgramsCollector) -> Ngs:
    train_set = list(collector.train_set_counts.keys())
    val_set = list(collector.val_set_counts.keys())
    exploit_set = list(collector.exploit_set_counts.keys())
    normal_set = list(collector.normal_set_counts.keys())
    before_exploit_set = list(collector.before_exploit_set_counts.keys())
    after_exploit_set = list(collector.after_exploit_set_counts.keys())
    val_exc_train = list(set(val_set) - set(train_set))
    exploit_exc_train = list(set(exploit_set) - set(train_set))
    normal_exc_train = list(set(normal_set) - set(train_set))
    exploit_exc_val = list(set(exploit_set) - set(val_set))
    normal_exc_val = list(set(normal_set) - set(val_set))
    exploit_exc_train_val = list(set(exploit_set) - (set(train_set) | set(val_set)))
    normal_exc_train_val = list(set(normal_set) - (set(train_set) | set(val_set)))
    before_exploit_exc_train_val = list(set(before_exploit_set) - (set(train_set) | set(val_set)))
    after_exploit_exc_train_val = list(set(after_exploit_set) - (set(train_set) | set(val_set)))
    before_exploit_exc_train = list(set(before_exploit_set) - set(train_set))
    after_exploit_exc_train = list(set(after_exploit_set) - set(train_set))
    train_set_split, val_set_split = train_test_split(
        list(train_set),
        test_size=0.2 - len(val_exc_train) / len(train_set),
        random_state=42
    )
    val_set_split = list(set(val_set_split) | set(val_exc_train))
    all_set = list(set(train_set) | set(val_set) | set(exploit_set) | set(normal_set))
    true_all_len = collector.train_set_length + collector.val_set_length + collector.exploit_set_length + collector.normal_set_length

    result = Ngs()
    result.train_set = train_set
    result.val_set = val_set
    result.exploit_set = exploit_set
    result.normal_set = normal_set
    result.before_exploit_set = before_exploit_set
    result.after_exploit_set = after_exploit_set
    result.val_exc_train = val_exc_train
    result.exploit_exc_train = exploit_exc_train
    result.normal_exc_train = normal_exc_train
    result.exploit_exc_val = exploit_exc_val
    result.normal_exc_val = normal_exc_val
    result.exploit_exc_train_val = exploit_exc_train_val
    result.normal_exc_train_val = normal_exc_train_val
    result.before_exploit_exc_train_val = before_exploit_exc_train_val
    result.after_exploit_exc_train_val = after_exploit_exc_train_val
    result.before_exploit_exc_train = before_exploit_exc_train
    result.after_exploit_exc_train = after_exploit_exc_train
    result.train_set_split = train_set_split
    result.val_set_split = val_set_split
    result.all_set = all_set
    result.true_all_len = true_all_len
    result.train_set_length = collector.train_set_length
    result.val_set_length = collector.val_set_length
    result.exploit_set_length = collector.exploit_set_length
    result.normal_set_length = collector.normal_set_length
    result.before_exploit_set_length = collector.before_exploit_set_length
    result.after_exploit_set_length = collector.after_exploit_set_length
    result.per_rec_after = collector.per_rec_after
    result.per_rec_before = collector.per_rec_before
    result.per_rec_normal = collector.per_rec_normal

    return result


def anomaly_scores_for_epoch(model, epoch, NGS: Ngs) -> AnomalyScores:
    model._epochs = epoch
    model.load_epoch(epoch)
    if not model._checkpoint:
        model.fit()

    anomaly_scores_all = {}
    if model.use_cache:
        anomaly_scores_all = model.get_cached_scores()
    if not len(anomaly_scores_all):
        anomaly_scores_all = model.batched_results(list(NGS.all_set), batch_size=4096)
        model.save_epoch(epoch)

    anomaly_scores_train = [anomaly_scores_all[ng] for ng in NGS.train_set]
    anomaly_scores_val = [anomaly_scores_all[ng] for ng in NGS.val_set]
    anomaly_scores_before_exploit = [anomaly_scores_all[ng] for ng in NGS.before_exploit_set]
    anomaly_scores_after_exploit = [anomaly_scores_all[ng] for ng in NGS.after_exploit_set]
    anomaly_scores_normal = [anomaly_scores_all[ng] for ng in NGS.normal_set]
    anomaly_scores_val_exc_train = [anomaly_scores_all[ng] for ng in NGS.val_exc_train]
    anomaly_scores_before_exploit_exc_train = [anomaly_scores_all[ng] for ng in NGS.before_exploit_exc_train]
    anomaly_scores_normal_exc_train = [anomaly_scores_all[ng] for ng in NGS.normal_exc_train]
    anomaly_scores_after_exploit_exc_train = [anomaly_scores_all[ng] for ng in NGS.after_exploit_exc_train]

    anomaly_scores_after_exploit_per_recording = {}
    for name, rec_ng in NGS.per_rec_after.items():
        if len(rec_ng) == 0:
            anomaly_scores_after_exploit_per_recording[name] = [0]  # TODO: should this be 0
        for ng in rec_ng:
            score = anomaly_scores_all[ng]
            if name in anomaly_scores_after_exploit_per_recording:
                anomaly_scores_after_exploit_per_recording[name].append(score)
            else:
                anomaly_scores_after_exploit_per_recording[name] = [score]

    anomaly_scores_before_exploit_per_recording = {}
    for name, rec_ng in NGS.per_rec_before.items():
        if len(rec_ng) == 0:
            anomaly_scores_before_exploit_per_recording[name] = [0]  # TODO: should this be 0
        for ng in rec_ng:
            score = anomaly_scores_all[ng]
            if name in anomaly_scores_before_exploit_per_recording:
                anomaly_scores_before_exploit_per_recording[name].append(score)
            else:
                anomaly_scores_before_exploit_per_recording[name] = [score]

    anomaly_scores_normal_per_recording = {}
    for name, rec_ng in NGS.per_rec_normal.items():
        if len(rec_ng) == 0:
            anomaly_scores_normal_per_recording[name] = [0]
        for ng in rec_ng:
            score = anomaly_scores_all[ng]
            if name in anomaly_scores_normal_per_recording:
                anomaly_scores_normal_per_recording[name].append(score)
            else:
                anomaly_scores_normal_per_recording[name] = [score]

    anomaly_scores = AnomalyScores(
        epoch,
        anomaly_scores_train,
        anomaly_scores_val,
        anomaly_scores_before_exploit,
        anomaly_scores_after_exploit,
        anomaly_scores_normal,
        anomaly_scores_val_exc_train,
        anomaly_scores_before_exploit_exc_train,
        anomaly_scores_after_exploit_exc_train,
        anomaly_scores_normal_exc_train,
        anomaly_scores_after_exploit_per_recording,
        anomaly_scores_before_exploit_per_recording,
        anomaly_scores_normal_per_recording, )

    return anomaly_scores


def roc_metrics_for_threshold(anos: AnomalyScores):
    threshold = anos.threshold
    num_rec = len(anos.after_exploit_per_recording)
    is_anomaly_before_per_recording = [any([sc > threshold for sc in _scores])
                                       for _scores in anos.before_exploit_per_recording.values()]
    is_anomaly_after_per_recording = [any([sc > threshold for sc in _scores])
                                      for _scores in anos.after_exploit_per_recording.values()]

    fp = sum(is_anomaly_before_per_recording)
    tp = sum(is_anomaly_after_per_recording)

    tn = num_rec - fp
    fn = num_rec - tp

    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    return tpr, fpr


def roc_metrics_for_epoch(anos: AnomalyScores):
    num_rec = len(anos.before_exploit_per_recording)
    y_true = [0] * num_rec + [1] * num_rec
    y_score = [max(scores) for scores in anos.before_exploit_per_recording.values()] \
              + [max(scores) for scores in anos.after_exploit_per_recording.values()]
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    return thresholds, tpr, fpr, roc_auc


def anomalies_counts(anos: AnomalyScores, NGS: Ngs):
    is_anomaly = lambda score: score > anos.threshold

    before_exploit = [is_anomaly(score) for score in anos.before_exploit]
    after_exploit = [is_anomaly(score) for score in anos.after_exploit]
    normal = [is_anomaly(score) for score in anos.normal]

    anomal_ngs_after_exploit = [ng for ng, is_anormal in zip(NGS.after_exploit_set, after_exploit) if is_anormal]
    return {
        "before_exploit": sum(before_exploit),
        "after_exploit": sum(after_exploit),
        "normal": sum(normal),
        "anomal_ngs_after_exploit": anomal_ngs_after_exploit,
    }


def get_anomaly_scores_for_epochs(_model, epochs, _NGS, _collector, config: Iterable[int], base_path=""):
    anos_per_epoch = {}

    cache_path = f"anomaly_scores/{'_'.join((str(c) for c in config))}.pickle"
    cache_path = os.path.join(base_path, cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    if _model.use_cache:
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                anos_per_epoch = pickle.load(f)
            return anos_per_epoch

    for epoch in tqdm(epochs):
        anos: AnomalyScores = anomaly_scores_for_epoch(_model, epoch, _NGS)
        anos.true_anomal_ngs_count = 0
        if anos.has_detected:
            counts = anomalies_counts(anos, _NGS)
            for ng in counts["anomal_ngs_after_exploit"]:
                anos.true_anomal_ngs_count += _collector.after_exploit_set_counts[ng]
        anos_per_epoch[epoch] = anos

    with open(cache_path, "wb") as f:
        pickle.dump(anos_per_epoch, f)
    return anos_per_epoch


def get_cached_anomaly_scores(config: Iterable[int], base_path=""):
    cache_path = f"anomaly_scores/{'_'.join((str(c) for c in config))}.pickle"
    cache_path = os.path.join(base_path, cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            anos_per_epoch = pickle.load(f)
        return anos_per_epoch
    else:
        print(f"no cache for {config}")
        return {}


def cache_losses(_model, config: Iterable[int], base_path="" ):
    cache_path = f"losses/{'_'.join((str(c) for c in config))}.pickle"
    cache_path = os.path.join(base_path, cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    if os.path.exists(cache_path):
        return
    losses = _model.train_losses, _model.val_losses
    with open(cache_path, "wb") as f:
        pickle.dump(losses, f)


def get_cached_losses(config: Iterable[int], base_path=""):
    cache_path = f"losses/{'_'.join((str(c) for c in config))}.pickle"
    cache_path = os.path.join(base_path, cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            losses = pickle.load(f)
        return losses
    else:
        print(f"no cache for {config}")
        return None, None


def prepare_tf_ngs(dataset_base,
                   ngram_length: int,
                   direction: Direction,
                   dataset: str,
                   scenario: str,
                   base_path="") -> NgramsCollector:
    path = f"ngrams/tf_{dataset}_{scenario}_{ngram_length}_{direction}.pickle"
    path = os.path.join(base_path, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            collector = pickle.load(f)
        print(f"skip {scenario}")
        return collector

    scenario_path = os.path.join(dataset_base, dataset, scenario)
    if not os.path.exists(scenario_path):
        raise FileNotFoundError(f"scenario {scenario} not found")

    sys_name = SyscallName()
    int_emb = IntEmbeddingConcat([sys_name])
    ngram = Ngram(
        feature_list=[int_emb],
        ngram_length=ngram_length,
        thread_aware=True,
    )

    collector = collect_ngrams(ngram, scenario_path, direction)
    syscall_dict = {v: k for k, v in int_emb._encoding_dict[0].items()}
    syscall_dict[0] = "<unk>"
    ng_syscall = int_emb._encoding_dict[0]
    ng_syscall = {v: k for k, v in ng_syscall.items()}
    collector.syscall_dict = syscall_dict, ng_syscall

    with open(path, "wb") as f:
        pickle.dump(collector, f)

    return collector


def prepare_ae_ngs(dataset_base,
                   ngram_length: int,
                   direction: Direction,
                   dataset: str,
                   scenario: str,
                   base_path="") -> NgramsCollector:
    path = f"ngrams/ae_{dataset}_{scenario}_{ngram_length}_{direction}.pickle"
    path = os.path.join(base_path, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            collector = pickle.load(f)
        print(f"skip {scenario}")
        return collector

    if os.path.exists(path):
        with open(path, "rb") as f:
            collector = pickle.load(f)
        print(f"skip {scenario}")
        return collector

    scenario_path = os.path.join(dataset_base, dataset, scenario)
    if not os.path.exists(scenario_path):
        raise FileNotFoundError(f"scenario {scenario} not found")

    sys_name = SyscallName()
    ohe = OneHotEncoding(sys_name)
    ngram = Ngram(
        feature_list=[ohe],
        ngram_length=ngram_length,
        thread_aware=True,
    )

    collector = collect_ngrams(ngram, scenario_path, direction)
    syscall_dict = {v: k for k, v in ohe._input_to_int_dict.items()}
    syscall_dict[len(syscall_dict)] = "<unk>"
    ng_ohe = ohe._int_to_ohe_dict
    ng_ohe = {v: k for k, v in ng_ohe.items()}
    collector.syscall_dict = syscall_dict, ng_ohe

    with open(path, "wb") as f:
        pickle.dump(collector, f)

    return collector


def convert_list_of_ng_enc_to_syscalls(list_of_enc_ngs, ng_to_enc, syscall_dict, ngram_length):
    result = []
    for ngs in list_of_enc_ngs:
        split_len = len(ngs) // ngram_length
        ngs_split = [ngs[i:i + split_len] for i in range(0, len(ngs), split_len)]
        ng_split_ohe = [ng_to_enc[ng] for ng in ngs_split]
        ng_split_syscall_name = [syscall_dict[ng] for ng in ng_split_ohe]
        result.append(ng_split_syscall_name)
    return result


def train_ae_model(scenario,
                   dataset,
                   ngram_length,
                   dropout,
                   learning_rate,
                   direction,
                   custom_split,
                   NGS: Ngs,
                   epochs=3000,
                   base_path=""
                   ):
    checkpoint = ModelCheckPoint(
        scenario_name=scenario,
        models_dir=os.path.join(base_path, "models"),
        lid_ds_version_name=dataset,
        algorithm="ae",
        algo_config={
            "ngram_length": ngram_length,
            "dropout": dropout,
            "learning_rate": learning_rate,
            "direction": direction,
            "split": custom_split
        },
    )
    model = AE(
        input_vector=None,
        epochs=epochs,
        dropout=dropout,
        use_early_stopping=False,
        checkpoint=checkpoint,
        learning_rate=learning_rate,
    )
    if not custom_split:
        model._training_set = NGS.train_set
        model._validation_set = NGS.val_set
    else:
        model._training_set = NGS.train_set_split
        model._validation_set = NGS.val_set_split

    model._input_size = len(NGS.train_set[0])
    model.fit()
    return model


def train_tf_model(
        scenario,
        dataset,
        ngram_length,
        dropout,
        learning_rate,
        direction,
        custom_split,
        model_dim,
        batch_size,
        emb,
        NGS: Ngs,
        epochs,
        num_heads=2,
        layers=2,
        base_path=""
):
    checkpoint = ModelCheckPoint(
        scenario_name=scenario,
        models_dir=os.path.join(base_path, "models"),
        lid_ds_version_name=dataset,
        algorithm="tf",
        algo_config={
            "ngram_length": ngram_length,
            "dropout": dropout,
            "model_dim": model_dim,
            "lr": learning_rate,
            "direction": direction,
            "split": custom_split,
            "batch_size": batch_size,
            "heads": num_heads,
            "layers": layers,
        },
    )

    model = Transformer(
        input_vector=None,
        epochs=epochs,
        anomaly_scoring=AnomalyScore.LOSS,
        batch_size=batch_size,
        num_heads=num_heads,
        layers=layers,
        model_dim=model_dim,
        dropout=dropout,
        feedforward_dim=model_dim * 4,
        pre_layer_norm=True,
        dedup_train_set=True,
        retrain=False,
        checkpoint=checkpoint,
        concat_int_embedding=emb,
        learning_rate=learning_rate
    )

    if not custom_split:
        model._training_set = NGS.train_set
        model._validation_set = NGS.val_set
    else:
        model._training_set = NGS.train_set_split
        model._validation_set = NGS.val_set_split
    model.fit()
    return model
