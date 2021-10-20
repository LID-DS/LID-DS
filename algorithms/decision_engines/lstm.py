import torch
import torch.nn as nn
from torch.autograd import Variable

import numpy as np
from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine


class PytorchLSTModel(BaseDecisionEngine):

    def __init__(self,
                 ngram_length,
                 embedding_size,
                 distinct_syscalls,
                 extra_param=0,
                 epochs=300,
                 streaming_window_size=1,
                 architecture=None,
                 predict_on_batch=False,
                 batch_size=1,
                 stateful=False):
        self._ngram_length = ngram_length
        self._embedding_size = embedding_size
        self._extra_param = extra_param
        self._stateful = stateful
        self._batch_size = batch_size
        self._predict_on_batch = predict_on_batch
        self._epochs = epochs
        self._distinct_syscalls = distinct_syscalls
        self._training_data = {
            'x': [],
            'y': []
        }
        self._architecture = architecture
        self._lstm_layer = None
        self._device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    def _set_model(self, distinct_syscalls: int, data_shape: int):
        input_dim = self._ngram_length * (self._extra_param + self._embedding_size)
        hidden_dim = 64
        n_layers = 1
        self._lstm = Net(distinct_syscalls,
                         input_dim,
                         hidden_dim,
                         n_layers,
                         data_shape)

    def train_on(self, feature_list: list):
        # TODO get distinct syscalls
        x = np.array(feature_list[1:])
        y = feature_list[0][0]
        self._training_data['x'].append(x)
        self._training_data['y'].append(y)

    def fit(self):
        x_tensors = Variable(torch.Tensor(self._training_data['x'])).to(self._device)
        y_tensors = Variable(torch.Tensor(self._training_data['y'])).to(self._device)
        y_tensors = y_tensors.long()

        x_tensors_final = torch.reshape(x_tensors, (x_tensors.shape[0], 1, x_tensors.shape[1]))
        print("Training Shape", x_tensors_final.shape, y_tensors.shape)

        self._set_model(self._distinct_syscalls, x_tensors_final.shape[1])
        self._lstm.to(self._device)
        learning_rate = 0.001
        criterion = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self._lstm.parameters(), lr=learning_rate)
        torch.manual_seed(1)
        for epoch in tqdm(range(self._epochs), 'training network:'.rjust(25), unit=" epochs"):
            outputs = self._lstm.forward(x_tensors_final)
            optimizer.zero_grad()  # caluclate the gradient, manually setting to 0

            # obtain the loss function
            # outputs = self._convert_to_class_indices(outputs)
            loss = criterion(outputs, y_tensors)

            loss.backward()  # calculates the loss of the loss function

            optimizer.step()  # improve from loss, i.e backprop
            if epoch % 10 == 0:
                self._accuracy(outputs, y_tensors)
                print("Epoch: %d, loss: %1.5f" % (epoch, loss.item()))

    def _accuracy(self, outputs, y_tensors):
        hit = 0
        miss = 0
        for i in range(len(outputs)):
            pred = torch.argmax(outputs[i])
            if pred == y_tensors[i]:
                hit += 1
            else:
                miss += 1
        print(f"accuracy {hit/(hit+miss)}")


class Net(nn.Module):

    def __init__(self, num_classes, input_size, hidden_size, num_layers, seq_length):
        super(Net, self).__init__()
        self.num_classes = num_classes
        self.num_layers = num_layers  # number of layers
        self.input_size = input_size  # input size
        self.hidden_size = hidden_size  # hidden state
        self.seq_length = seq_length  # sequence length

        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                            num_layers=num_layers, batch_first=True)
        self.fc_1 = nn.Linear(hidden_size, 128)  # fully connected 1
        self.output = nn.Linear(hidden_size, num_classes)  # fully connected 1
        self.fc = nn.Linear(128, num_classes)  # fully connected last layer
        self.relu = nn.ReLU()
        self.tanh = nn.Tanh()
        self._device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    def forward(self, x):
        # hidden state
        h_0 = Variable(torch.zeros(self.num_layers, x.size(0), self.hidden_size)).to(self._device)
        # internal state
        c_0 = Variable(torch.zeros(self.num_layers, x.size(0), self.hidden_size)).to(self._device)
        # Propagate input through LSTM
        output, (hn, cn) = self.lstm(x, (h_0, c_0))  # lstm with input, hidden, and internal state
        hn = hn.view(-1, self.hidden_size)  # reshaping the data for Dense layer next
        out = self.tanh(hn)
        out = self.output(out)
        return out
