import torch
import torch.nn as nn
from torch import optim
from torch.utils.data import Dataset

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class MLPDataset(Dataset):
    def __init__(self, data):
        self.x_data = []
        self.y_data = []
        for datapoint in data:
            self.x_data.append(datapoint[0])
            self.y_data.append(datapoint[1])

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

        self._input_size = 0
        self._output_size = None
        self.hidden_size = hidden_size
        self.hidden_layers = hidden_layers
        self.batch_size = batch_size

        self._training_set = set()
        self._validation_set = set()

        self._model = None  # to be initialized in fit()

    def train_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        # building the training data set with input vector and labels
        # estimating the input size
        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            self._training_set.add((input_vector, output_label))

    def val_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            self._validation_set.add((input_vector, output_label))

    def fit(self):
        self._output_size = len(self._training_set)
        self._model = Feedforward(
            input_size=self._input_size,
            hidden_size=self.hidden_size,
            output_size=self._output_size,
            hidden_layers=self.hidden_layers
        ).model

        criterion = nn.MSELoss()
        optimizer = optim.SGD(self._model.parameters(), lr=0.003)

        max_epochs = 100000
        for e in range(max_epochs):
            running_loss = 0

            for input_vector, output_label in self._training_set:
                optimizer.zero_grad()

                output = self._model(input_vector)
                loss = criterion(output, output_label)

                loss.backward()
                optimizer.step()

                running_loss += loss.item()
            else:
                print(f"Training loss: {running_loss / len(self._training_set)}")

    def _calculate(self, syscall: Syscall):
        pass


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
