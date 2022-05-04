import torch
import torch.nn as nn

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class MLP(BuildingBlock):
    def __init__(self,
                 input_vector: BuildingBlock,
                 output_label: BuildingBlock,
                 hidden_size: int,
                 hidden_layers: int):
        super().__init__()
        self.input_vector = input_vector
        self.output_label = output_label

        self._input_size = None
        self._output_size = None
        self.hidden_size = hidden_size
        self.hidden_layers = hidden_layers

        self._model = None # to be initialized in fit()

    def train_on(self, syscall: Syscall):
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        # todo: calculate output size
        pass

    def fit(self):
        self._model = Feedforward(
            input_size=self._input_size,
            hidden_size=self.hidden_size,
            output_size=self._output_size,
            hidden_layers=self.hidden_layers
        )

    def _calculate(self, syscall: Syscall):
        pass


class Feedforward(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, hidden_layers):
        super(Feedforward, self).__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size # number of distinct input vectors
        self.output_size = output_size

        # todo: number of hidden layers as parameter
        self.model = nn.Sequential(
            nn.Linear(self.input_size, self.hidden_size),
            nn.ReLU(),
            nn.Linear(self.hidden_size, self.hidden_size),
            nn.ReLU(),
            nn.Linear(self.hidden_size, self.output_size),
            nn.Softmax()
        )

