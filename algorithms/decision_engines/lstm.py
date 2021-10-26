import os
import torch
import torch.nn as nn
from torch.autograd import Variable
from torch.utils.data import Dataset, DataLoader

import numpy as np
from tqdm import tqdm

from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine


class LSTM(BaseDecisionEngine):
    """

    LSTM decision engine

    Main idea:
        training:
            train prediction of next systemcall given a feature vector
        prediction:
            convert logits return value of model for every syscall to possibilties with softmax
            check predicted possibility of actual syscall and return 1-pred_pos as anomaly score


    """

    def __init__(self,
                 ngram_length: int,
                 embedding_size: int,
                 distinct_syscalls: int,
                 extra_param=0,
                 epochs=300,
                 architecture=None,
                 batch_size=1,
                 model_path='Models/',
                 force_train=False):
        """

        Args:
            ngram_length:       count of embedded syscalls
            embedding_size:     size of one embedded syscall
            distinct_syscalls:  amount of distinct syscalls in training data
            extra_param:        amount of used extra parameters
            epochs:             set training epochs of LSTM
            architecture:       type of LSTM architecture
            batch_size:         set maximum batch_size
            model_path:         path to save trained Net to
            force_train:        force training of Net

        """
        self._ngram_length = ngram_length
        self._embedding_size = embedding_size
        self._extra_param = extra_param
        self._batch_size = batch_size
        self._epochs = epochs
        self._distinct_syscalls = distinct_syscalls
        self._model_path = model_path \
            + f'n{self._ngram_length}-e{self._embedding_size}-p{self._extra_param}-ep{self._epochs}'
        self._training_data = {
            'x': [],
            'y': []
        }
        self._state = 'build_training_data'
        self._architecture = architecture
        self._lstm = None
        self._batch_indices = []
        self._current_batch = []
        self._batch_counter = 0
        self._hidden_state = None
        self._cell_state = None
        self._device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        self._device = torch.device("cpu")
        if not force_train:
            if os.path.exists(self._model_path):
                self._set_model(self._distinct_syscalls, self._device)
                self._lstm.load_state_dict(torch.load(self._model_path))
            else:
                print(f"Did not load Model {self._model_path}.")

    def _set_model(self, distinct_syscalls: int, device: str):
        """

        create LSTM Net with outputlayer of distinct_syscalls + 1 (one extra for unknown syscalls)

        """
        input_dim = self._ngram_length * (self._extra_param + self._embedding_size)
        hidden_dim = 64
        n_layers = 1
        # output layer is #distinct_syscall + 1 for unknown syscalls
        self._lstm = Net(distinct_syscalls + 1,
                         input_dim,
                         hidden_dim,
                         n_layers,
                         device=device,
                         batch_size=self._batch_size)

    def train_on(self, feature_list: list):
        """

        create training data and keep track of batch indices
        batch indices are later used for creation of batches

        Args:
            feature_list (int): list of prepared features for DE

        """
        if self._lstm is None:
            x = np.array(feature_list[1:])
            y = feature_list[0][0]
            self._training_data['x'].append(x)
            self._training_data['y'].append(y)
            self._current_batch.append(self._batch_counter)
            self._batch_counter += 1
            if len(self._current_batch) == self._batch_size:
                self._batch_indices.append(self._current_batch)
                self._current_batch = []
        else:
            pass

    def fit(self):
        """

        fit model only if it could not be loaded
        set model state.
        convert training data to tensors and feed into custom dataset
        call torch dataloader with prepared batch_indices
            needed because end of recording cuts a batch
        create actual net for fitting
        define hyperparameters, iterate through DataSet and train Net
        keep hidden and cell state over batches, only reset with new recording


        """
        if self._state == 'build_training_data':
            self._state = 'fitting'
        if self._lstm is None:
            x_tensors = Variable(torch.Tensor(self._training_data['x'])).to(self._device)
            y_tensors = Variable(torch.Tensor(self._training_data['y'])).to(self._device)
            y_tensors = y_tensors.long()
            x_tensors_final = torch.reshape(x_tensors, (x_tensors.shape[0], 1, x_tensors.shape[1]))
            dataset = SyscallFeatureDataSet(x_tensors_final, y_tensors)
            # for custom batches
            dataloader = DataLoader(dataset, batch_sampler=self._batch_indices)  # batch_size=self._batch_size)
            print(f"Training Shape x: {x_tensors_final.shape} y: {y_tensors.shape}")
            self._set_model(self._distinct_syscalls, self._device)
            self._lstm.to(self._device)
            preds = []
            # Net hyperparameters
            learning_rate = 0.001
            criterion = torch.nn.CrossEntropyLoss()
            optimizer = torch.optim.Adam(self._lstm.parameters(), lr=learning_rate)
            self._hidden_state = None
            self._cell_state = None
            torch.manual_seed(1)
            for epoch in tqdm(range(self._epochs), 'training network:'.rjust(25), unit=" epochs"):
                for i, data in enumerate(dataloader, 0):
                    inputs, labels = data
                    outputs, self._hidden_state, self_cell_state = self._lstm.forward(inputs,
                                                                                      self._hidden_state,
                                                                                      self._cell_state)
                    # caluclate the gradient, manually setting to 0
                    optimizer.zero_grad()
                    # obtain the loss function
                    loss = criterion(outputs, labels)
                    # calculates the loss of the loss function
                    loss.backward()
                    # improve from loss, i.e backprop
                    optimizer.step()
                    for i in range(len(outputs)):
                        preds.append(torch.argmax(outputs[i]))
                self._accuracy(preds, y_tensors)
                preds = []
                print("Epoch: %d, loss: %1.5f" % (epoch, loss.item()))
                # reset hidden state
                self.new_recording()
            torch.save(self._lstm.state_dict(), self._model_path)
        else:
            print(f"Net already trained. Using model {self._model_path}")
            pass

    def predict(self, feature_list: list) -> float:
        """

        remove label from feature_list and feed into model.
        calc possibility of prediction_probs[0][actual_call] and return
        1 - calculated possibility as anomaly score

        """
        x_tensor = Variable(torch.Tensor(np.array([feature_list[1:]])))
        x_tensor_final = torch.reshape(x_tensor, (x_tensor.shape[0], 1, x_tensor.shape[1]))
        actual_syscall = feature_list[0][0]
        prediction_logits, hidden_state, cell_state = self._lstm(x_tensor_final,
                                                                 self._hidden_state,
                                                                 self._cell_state)
        softmax = nn.Softmax()
        prediction_probs = softmax(prediction_logits)
        predicted_probability = prediction_probs[0][actual_syscall]
        anomaly_score = 1 - predicted_probability
        return anomaly_score

    def _accuracy(self, outputs, labels):
        """

        calculate accuracy of last epoch

        """
        hit = 0
        miss = 0
        for i in range(len(outputs) - 1):
            if outputs[i] == labels[i]:
                hit += 1
            else:
                miss += 1
        print(f"accuracy {hit/(hit+miss)}")

    def new_recording(self):
        """

        while creation of dataset:
            cut batch after recording end
        while fitting and detecting
            reset hidden state

        """
        if self._lstm is None and self._state == 'build_training_data':
            if len(self._current_batch) > 0:
                self._batch_indices.append(self._current_batch)
                self._current_batch = []
        elif self._state == 'fitting':
            self._hidden_state = None
            self._cell_state = None
        else:
            pass


class Net(nn.Module):

    def __init__(self,
                 num_classes: int,
                 input_size: int,
                 hidden_size: int,
                 num_layers: int,
                 device: str,
                 batch_size: int):
        super(Net, self).__init__()
        self.num_classes = num_classes
        self.num_layers = num_layers  # number of layers
        self.input_size = input_size  # input size
        self.hidden_size = hidden_size  # hidden state

        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size,
                            num_layers=num_layers, batch_first=True)
        self.fc_1 = nn.Linear(hidden_size, 128)  # fully connected 1
        self.output = nn.Linear(hidden_size, num_classes)  # fully connected 1
        self.fc = nn.Linear(128, num_classes)  # fully connected last layer
        self.relu = nn.ReLU()
        self.tanh = nn.Tanh()
        self._device = torch.device(device)
        self._hidden_state = None  # hidden_state
        self._cell_state = None  # cell_state
        self.init_states(batch_size)

    def forward(self, x, hidden_state, cell_state):
        # Propagate input through LSTM
        # lstm with input, hidden, and internal cell state
        if hidden_state is None:
            self.init_states(x.size(0))
        else:
            self._hidden_state = hidden_state
            self._cell_state = cell_state
        output, (new_hidden_state, new_cell_state) = self.lstm(x,
                                                               (self._hidden_state,
                                                                self._cell_state))
        # internal state
        # reshaping the data for Dense layer next
        new_hidden_state = new_hidden_state.view(-1, self.hidden_size)
        out = self.tanh(new_hidden_state)
        out = self.output(out)
        return out, hidden_state, cell_state

    def init_states(self, batch_size: int):
        # hidden state
        self._hidden_state = Variable(
            torch.zeros(self.num_layers, batch_size, self.hidden_size)).to(self._device)
        # internal state
        self._cell_state = Variable(
            torch.zeros(self.num_layers, batch_size, self.hidden_size)).to(self._device)


class SyscallFeatureDataSet(Dataset):

    def __init__(self, X, Y):
        self.X = X
        self.Y = Y
        if len(self.X) != len(self.Y):
            raise Exception("The length of X does not match length of Y")

    def __len__(self):
        return len(self.X)

    def __getitem__(self, index):
        _x = self.X[index]
        _y = self.Y[index]
        return _x, _y


class EndBatchWithRecording:
    """

    Custom Batch Sampler to end batch with 'new_recording' marker

    """

    def __init__(self, batch_sampler):
        pass
