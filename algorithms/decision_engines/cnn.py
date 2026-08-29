from functools import lru_cache
import math
import torch
import numpy as np
import torch.nn as nn

from tqdm import tqdm
from torch import optim
from torch.utils.data import Dataset
from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


class CNNDataset(Dataset):
    """Torch dataset for CNN: reshapes flat input vectors into 2D (channels x width)."""

    def __init__(self, data, input_channels):
        self.x_data = []
        self.y_data = []
        for datapoint in data:
            x = np.asarray(datapoint[0], dtype=np.float32)
            # Reshape flat vector into (channels, width_per_channel)
            x = x.reshape(input_channels, -1)
            self.x_data.append(torch.from_numpy(x).to(device=device))
            self.y_data.append(
                torch.from_numpy(np.asarray(datapoint[1], dtype=np.float32)).to(device=device))

    def __len__(self):
        return len(self.x_data)

    def __getitem__(self, index):
        return self.x_data[index], self.y_data[index]


class CNN(BuildingBlock):
    """
    1D-CNN Decision Engine for syscall-based IDS.

    Analogous to MLP: takes an input_vector (e.g. n OHE-encoded syscalls)
    and an output_label (OHE of the next syscall). Scores anomalies as
    1 - P(correct_label).

    The input is reshaped into (n_channels, ohe_size) where each channel
    is one position in the ngram. Conv1d operates over the OHE dimension.

    Args:
        input_vector: BuildingBlock providing the flattened input
        output_label: BuildingBlock providing the OHE label
        input_channels: number of ngram positions (= n in Ngram(n+1))
        num_filters: number of Conv1d filters per layer
        num_conv_layers: number of Conv1d layers
        kernel_size: Conv1d kernel size
        batch_size: training batch size
        learning_rate: Adam optimizer learning rate
        deduplicate_training: deduplicate training pairs
    """

    def __init__(self,
                 input_vector: BuildingBlock,
                 output_label: BuildingBlock,
                 input_channels: int,
                 num_filters: int = 64,
                 num_conv_layers: int = 2,
                 kernel_size: int = 3,
                 batch_size: int = 64,
                 learning_rate: float = 0.003,
                 deduplicate_training: bool = True):
        super().__init__()

        self.input_vector = input_vector
        self.output_label = output_label
        self.input_channels = input_channels
        self.num_filters = num_filters
        self.num_conv_layers = num_conv_layers
        self.kernel_size = kernel_size
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self._deduplicate = deduplicate_training

        self._dependency_list = [input_vector, output_label]

        self._input_size = 0
        self._output_size = 0

        self._training_set = set() if deduplicate_training else []
        self._validation_set = set() if deduplicate_training else []
        self._model = None

        self._early_stop_epochs = 50

    def train_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)
            if self._output_size == 0:
                self._output_size = len(output_label)

            pair = (input_vector, output_label)
            if self._deduplicate:
                self._training_set.add(pair)
            else:
                self._training_set.append(pair)

    def val_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            pair = (input_vector, output_label)
            if self._deduplicate:
                self._validation_set.add(pair)
            else:
                self._validation_set.append(pair)

    def fit(self):
        print(f"CNN.train_set: {len(self._training_set)}".rjust(27))

        # Derive width per channel from input_size / input_channels
        width = self._input_size // self.input_channels

        self._model = self._build_model(
            in_channels=self.input_channels,
            width=width,
            output_size=self._output_size
        ).to(device)
        self._model.train()

        criterion = nn.MSELoss()
        optimizer = optim.Adam(self._model.parameters(),
                               lr=self.learning_rate, weight_decay=1e-5)

        train_data_set = CNNDataset(self._training_set, self.input_channels)
        val_data_set = CNNDataset(self._validation_set, self.input_channels)
        del self._training_set, self._validation_set
        self._training_set = None
        self._validation_set = None

        epochs_since_last_best = 0
        best_avg_loss = math.inf
        best_weights = {}

        train_data_loader = torch.utils.data.DataLoader(
            train_data_set, batch_size=self.batch_size, shuffle=True)
        val_data_loader = torch.utils.data.DataLoader(
            val_data_set, batch_size=self.batch_size, shuffle=True)

        max_epochs = 10000
        bar = tqdm(range(0, max_epochs), 'training'.rjust(27), unit=" epochs")
        for e in bar:
            for i, data in enumerate(train_data_loader):
                inputs, labels = data
                optimizer.zero_grad()
                outputs = self._model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()

            val_loss = 0.0
            count = 0
            for i, data in enumerate(val_data_loader):
                inputs, labels = data
                outputs = self._model(inputs)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                count += 1
            avg_val_loss = val_loss / count if count > 0 else math.inf

            if avg_val_loss < best_avg_loss:
                best_avg_loss = avg_val_loss
                best_weights = self._model.state_dict()
                epochs_since_last_best = 1
            else:
                epochs_since_last_best += 1

            stop_early = epochs_since_last_best >= self._early_stop_epochs

            bar.set_description(
                f"fit CNN {epochs_since_last_best}|{best_avg_loss:.5f}".rjust(27),
                refresh=True)

            if stop_early:
                break

        print(f"stop at {bar.n} epochs".rjust(27))
        self._model.load_state_dict(best_weights)
        self._model.eval()

    def _build_model(self, in_channels, width, output_size):
        """Build 1D-CNN: Conv1d layers -> Flatten -> FC -> Softmax."""
        layers = []

        current_channels = in_channels
        current_width = width

        for i in range(self.num_conv_layers):
            # Use padding to preserve width
            pad = self.kernel_size // 2
            layers.append(nn.Conv1d(current_channels, self.num_filters,
                                     kernel_size=self.kernel_size, padding=pad))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(p=0.1))
            current_channels = self.num_filters

        layers.append(nn.Flatten())
        flat_size = current_channels * current_width
        layers.append(nn.Linear(flat_size, output_size))
        layers.append(nn.Softmax(dim=-1))

        return nn.Sequential(*layers)

    @lru_cache(maxsize=1000)
    def _cached_results(self, input_vector, output_label):
        if input_vector is None:
            return None

        try:
            label_index = output_label.index(1)
        except ValueError:
            return None

        x = np.asarray(input_vector, dtype=np.float32)
        x = x.reshape(self.input_channels, -1)
        in_tensor = torch.tensor(x, dtype=torch.float32, device=device).unsqueeze(0)
        with torch.no_grad():
            cnn_out = self._model(in_tensor)
        result = 1 - cnn_out[0][label_index].item()
        return result

    def _calculate(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        label = self.output_label.get_result(syscall)
        return self._cached_results(input_vector, label)

    def depends_on(self):
        return self._dependency_list
