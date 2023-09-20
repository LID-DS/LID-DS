import json
import os
import os.path
import re

import pandas as pd
import torch
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
from torch import nn
from torch.optim import Optimizer


def save_to_json(result_dict: dict, path: str):
    """
        convert result dict to correct format
        cut known performance and put the rest into config dict
    """
    performance = {
        "true_positives": int,
        "false_positives": int,
        "true_negatives": int,
        "false_negatives": int,
        "correct_alarm_count": int,
        "exploit_count": int,
        "detection_rate": float,
        "consecutive_false_positives_normal": int,
        "consecutive_false_positives_exploits": int,
        "recall": float,
        "precision_with_cfa": float,
        "precision_with_syscalls": float,
        "f1_cfa": float
    }
    config = {}
    for key in result_dict.keys():
        if key in performance.keys():
            performance[key] = result_dict[key]
        else:
            config[key] = result_dict[key]
    complete_dict = result_dict
    if os.path.exists(path):
        with open(path, 'r') as file:
            result_list = json.load(file)
        result_list.append(complete_dict)
        with open(path, 'w') as file:
            json.dump(result_list, file, indent=2)
    else:
        print('No persistent data yet')
        result_list = [complete_dict]
        with open(path, 'w') as file:
            json.dump(result_list, file, indent=2)


def load_from_json(path: str):
    try:
        with open(path, 'r') as file:
            result_list = json.load(file)
    except IOError:
        print(f'No results at {path}')
        result_list = None
    return result_list


def print_as_table(results: list = None, path: str = None):
    """
    Pretty print a list of dictionaries (myDict) as a dynamically sized table.
    If column names (colList) aren't specified, they will show in random order.
    """
    if results is None and path is None:
        print('Please provide either result list or path to file')
    if results is None:
        results = load_from_json(path)
    config_list = []
    performance_list = []
    for result in results:
        config_list.append(result['config'])
        performance_list.append(result['performance'])
    config = pd.DataFrame(config_list)
    performance = pd.DataFrame(performance_list)
    result_list = pd.concat([performance, config], axis=1)
    print(result_list)


def save_to_mongo(result_dict: dict, db_name: str = 'experiments'):
    """
    opens connection to MongoDB Server and inserts current result document
    """
    try:
        mongo_ip = os.environ['LID_DS_MONGO_IP']
        mongo_user = os.environ['LID_DS_MONGO_USER']
        mongo_pw = os.environ['LID_DS_MONGO_PW']

        client = MongoClient(mongo_ip,
                             username=mongo_user,
                             password=mongo_pw)

        db = client[db_name]
        collection = db[db_name]

        collection.insert_one(result_dict)
        print("Persisted results in MongoDB")
    except ValueError:
        raise ValueError("Please make sure MongoDB Environment Variables are set")
    except ServerSelectionTimeoutError:
        print("Could not connect to Experiment DB")
    except OperationFailure:
        print("Could not persist Data, please check User Credentials. If Credentials are correct please check if your data contains the fields 'config', 'dataset' and 'scenario'")


class ModelCheckPoint:
    """ Helper class to save and load intermediary model states.

        Can be used to save :class:`torch.nn.Module` models with their optimizer :class:`torch.optim.Optimizer` for a given epoch. This is helpful if you intend to
        resume the training process starting from a previous epoch.
        It saves the model with `model_state_dict`, `optimizer_state_dict`, train and validation losses
        to a directory in the form::
            Models
            └── LID-DS-2019
                ├── CVE-2014-0160
                │    └── transformer
                │        └── ngram_length11_thread_awareTrue_anomaly_scoreMEAN_batch_size512
                │            ├── epochs1.model
                │            └── epochs2.model
                └── CVE-2017-7529
                     └── transformer
                         └── ngram_length11_thread_awareTrue_anomaly_scoreMEAN_batch_size512
                             ├── epochs2.model
                             └── epochs6.model

        Note:
            If run on a cluster, you might want to run all epochs on one node. Let's say node1 runs only until
            epoch 5 and node2 runs until epoch 10. Even thought it is possible to share the Models folder,
            node2 can not use the checkpoint at epoch 5 of node1 since node1 has not finished yet (if they are started
            at the same time).

    """

    def __init__(
            self,
            scenario_name: str,
            lid_ds_version_name: str,
            algorithm: str,
            algo_config: dict,
            models_dir: str = "Models",
    ):
        """
        Args:
            algo_config (dict): will be used to construct the model name. should be unique for each configuration.
            models_dir (str): base dir to save models.
        """
        self.model_path_base = os.path.join(models_dir, lid_ds_version_name, scenario_name, algorithm)
        self.model_name = '_'.join(''.join((key, str(val))) for (key, val) in algo_config.items())
        self.epochs_dir = os.path.join(self.model_path_base, self.model_name)

        os.makedirs(self.epochs_dir, exist_ok=True)

    def load(
            self,
            model: nn.Module,
            optimizer: Optimizer,
            epoch: int = -1
    ) -> tuple[int, dict[int, float], dict[int, float], dict]:
        """ Load the recent checkpoint states to the given model and optimizer from a checkpoint

        If there exists a checkpoint with specified epoch it will be loaded. Else, the checkpoint with the highest epoch
        will be loaded and the epoch number will be returned. If there are no previous checkpoints nothing will be
        loaded and the returned epoch number is 0.

        Args:
            model (nn.Module): pytorch model
            optimizer (Optimizer): model optimizer
            epoch (int): epoch to load

        Returns:
            tuple: (last_epoch, train_losses, val_losses)
            last_epoch: same as `epoch` if checkpoint found, else the highest available epoch number
            losses: dictionaries of form {epoch: loss}
        """
        train_losses = {}
        val_losses = {}
        checkpoint = None

        saved_epochs = [f for f in os.listdir(self.epochs_dir) if f.endswith(".model")]
        saved_epochs = [int(re.findall(r'\d+', saved_epoch)[0]) for saved_epoch in saved_epochs]
        last_epoch = max(saved_epochs, default=0)

        if saved_epochs and last_epoch > epoch:
            last_epoch = max(e for e in saved_epochs if e <= epoch)
        if last_epoch > 0:
            epoch_path = os.path.join(self.epochs_dir, f"epochs{last_epoch}.model")
            checkpoint = torch.load(
                epoch_path,
                map_location=torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            )
            train_losses = checkpoint["train_losses"]
            val_losses = checkpoint["val_losses"]
            model.load_state_dict(checkpoint["model_state_dict"])
            optimizer.load_state_dict(checkpoint["optimizer_state_dict"])

        return last_epoch, train_losses, val_losses, checkpoint

    def save(
            self,
            model: nn.Module,
            optimizer: Optimizer,
            epoch: int,
            train_losses: dict[int, float],
            val_losses: dict[int, float], **kwargs):
        """ Saves the model and optimizer states.

        Args:
            model (nn.Module): pytorch model
            optimizer (Optimizer): model optimizer
            epoch (int): epoch to load
            train_losses: list of train_losses up to this epoch
            val_losses: list of validation losses up to this epoch
        """
        epoch_path = os.path.join(self.epochs_dir, f"epochs{epoch}.model")

        torch.save(
            {
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "train_losses": train_losses,
                "val_losses": val_losses
            } | kwargs,
            epoch_path
        )
