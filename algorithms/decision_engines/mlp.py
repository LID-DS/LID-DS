import collections
import math

import numpy
import numpy as np
import torch
import torch.nn as nn
from torch import optim
from torch.utils.data import Dataset
from tqdm import tqdm

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class MLPDataset(Dataset):
    def __init__(self, data):
        self.x_data = []
        self.y_data = []
        for datapoint in data:
            self.x_data.append(torch.from_numpy(numpy.asarray(datapoint[0], dtype=np.float32)))
            self.y_data.append(torch.from_numpy(numpy.asarray(datapoint[1], dtype=np.float32)))

    def __len__(self):
        return len(self.x_data)

    def __getitem__(self, index):
        _x = self.x_data[index]
        _y = self.y_data[index]

        return _x, _y


class MLP(BuildingBlock):
    def __init__(self,
                 input_vector: BuildingBlock,
                 output_label: BuildingBlock,
                 hidden_size: int,
                 hidden_layers: int,
                 batch_size: int):

        super().__init__()
        self.input_vector = input_vector
        self.output_label = output_label

        self._dependency_list = [input_vector, output_label]

        self._input_size = 0
        self._output_size = 0
        self.hidden_size = hidden_size
        self.hidden_layers = hidden_layers
        self.batch_size = batch_size

        self._training_set = set()
        self._validation_set = set()

        self._model = None  # to be initialized in fit()

        self._early_stop_epochs = 200

        self._result_dict = {}

    def train_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        # building the training data set with input vector and labels
        # estimating the input size
        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            if self._output_size == 0:
                self._output_size = len(output_label)

            self._training_set.add((input_vector, output_label))

    def val_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            self._validation_set.add((input_vector, output_label))

    def fit(self):
        self._model = Feedforward(
            input_size=self._input_size,
            hidden_size=self.hidden_size,
            output_size=self._output_size,
            hidden_layers=self.hidden_layers
        ).model

        criterion = nn.MSELoss()
        optimizer = optim.SGD(self._model.parameters(), lr=0.003)
        train_data_set = MLPDataset(self._training_set)
        val_data_set = MLPDataset(self._validation_set)

        loss_dq = collections.deque(maxlen=self._early_stop_epochs)
        best_avg_loss = math.inf

        train_data_loader = torch.utils.data.DataLoader(train_data_set, batch_size=self.batch_size, shuffle=True)
        val_data_loader = torch.utils.data.DataLoader(val_data_set, batch_size=self.batch_size, shuffle=True)

        max_epochs = 100000
        bar = tqdm(range(0, max_epochs), 'training'.rjust(27), unit=" epochs")

        for e in bar:
            running_loss = 0

            # training
            for i, data in enumerate(train_data_loader):
                inputs, labels = data

                optimizer.zero_grad()  # prepare gradients

                outputs = self._model(inputs)  # compute output
                loss = criterion(outputs, labels)  # compute loss

                loss.backward()  # compute gradients
                optimizer.step()  # update weights

                running_loss += loss.item()

            # validation
            val_loss = 0.0
            count = 0
            for i, data in enumerate(val_data_loader):
                inputs, labels = data
                outputs = self._model(inputs)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                count += 1
            avg_val_loss = val_loss / count

            if avg_val_loss < best_avg_loss:
                best_avg_loss = avg_val_loss

            loss_dq.append(avg_val_loss)
            stop_early = True
            for l in loss_dq:
                if l == best_avg_loss:
                    stop_early = False
            if stop_early:
                break

            bar.set_description(f"fit MLP, loss: {avg_val_loss:.5f}, epoch: {e}".rjust(27), refresh=True)


    def _calculate(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        label = self.output_label.get_result(syscall)
        if input_vector is not None:
            if input_vector in self._result_dict:
                return self._result_dict[input_vector]
            else:
                in_tensor = torch.tensor(input_vector)
                mlp_out = self._model(in_tensor)

                label_index = label.index(1)
                anomaly_score = 1 - mlp_out[label_index]

                self._result_dict[input_vector] = anomaly_score
                return anomaly_score
        else:
            return None

    def depends_on(self):
        return self._dependency_list


class Feedforward(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, hidden_layers):
        super(Feedforward, self).__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size  # number of distinct input vectors
        self.output_size = output_size
        layer_list = self._get_mlp_sequence(hidden_layers)

        self.model = nn.Sequential(*layer_list)

    def _get_mlp_sequence(self, hidden_layers):
        hidden_layer_list = []
        for i in range(hidden_layers):
            hidden_layer_list.append(nn.Linear(self.hidden_size, self.hidden_size))
            hidden_layer_list.append(nn.ReLU())

        return [
                   nn.Linear(self.input_size, self.hidden_size),
                   nn.ReLU()
               ] + hidden_layer_list + [
                   nn.Linear(self.hidden_size, self.output_size),
                   nn.Softmax()
               ]
