import math
import torch
import collections

import numpy as np
import torch.nn as nn

from tqdm import tqdm
from torch import optim
from torch.utils.data import Dataset
from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class MLPDataset(Dataset):
    """
    torch dataloader that presents syscall data as tensors to neural network
    """

    def __init__(self, data):
        """
        adds all datapoints as tensors to dataset
        """
        self.x_data = []
        self.y_data = []
        for datapoint in data:
            self.x_data.append(torch.from_numpy(np.asarray(datapoint[0], dtype=np.float32)))
            self.y_data.append(torch.from_numpy(np.asarray(datapoint[1], dtype=np.float32)))

    def __len__(self):
        """
        returns the length of the dataset
        """
        return len(self.x_data)

    def __getitem__(self, index):
        """
        returns one item for a given index
        """
        _x = self.x_data[index]
        _y = self.y_data[index]

        return _x, _y


class MLP(BuildingBlock):
    """
        MLP Bulding Block built on pytorch
        initializes, trains and uses FeedForward Class from below

        Args:
            input_vector: the building block that is used for training
            output_label: the building block that is used for labeling the input vector
                            needs to be a vector with only one dimension != 0
            hidden_size: the number of neurons of the hidden layers
            hidden_layers: the number of hidden layers
            batch_size: number of input datapoints that are showed to the neural network
                            before adjusting the weights
    """

    def __init__(self,
                 input_vector: BuildingBlock,
                 output_label: BuildingBlock,
                 hidden_size: int,
                 hidden_layers: int,
                 batch_size: int,
                 learning_rate: float = 0.003):
        super().__init__()

        self.input_vector = input_vector
        self.output_label = output_label
        self.hidden_size = hidden_size
        self.hidden_layers = hidden_layers
        self.batch_size = batch_size
        self.learning_rate = learning_rate

        self._dependency_list = [input_vector, output_label]

        # estimated in train_on method
        self._input_size = 0
        self._output_size = 0

        self._training_set = set()
        self._validation_set = set()
        self._model = None  # to be initialized in fit()

        # number of epochs after which training is stopped if no improvement in loss has occurred
        self._early_stop_epochs = 100

        self._result_dict = {}

    def train_on(self, syscall: Syscall):
        """
            building the training data set with input vector and labels
            estimating the input size

            Args:
                syscall: the current system call object
        """

        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            if self._output_size == 0:
                self._output_size = len(output_label)

            self._training_set.add((input_vector, output_label))

    def val_on(self, syscall: Syscall):
        """
            building the validation dataset

            Args:
                syscall: the current system call object
        """
        input_vector = self.input_vector.get_result(syscall)
        output_label = self.output_label.get_result(syscall)

        if input_vector is not None and output_label is not None:
            self._validation_set.add((input_vector, output_label))

    def fit(self):
        """
            trains the neural network
            initializes the FeedForward Model
            trains the model in batches using pytorch logic

            calculates loss on validation data and stops when no optimization occurs
        """
        print(f"MLP.train_set: {len(self._training_set)}".rjust(27))
        
        self._model = Feedforward(
            input_size=self._input_size,
            hidden_size=self.hidden_size,
            output_size=self._output_size,
            hidden_layers=self.hidden_layers
        ).model
        self._model.train()

        criterion = nn.MSELoss()  # using mean squared error for loss calculation
        optimizer = optim.Adam(self._model.parameters(), lr=self.learning_rate)  # using Adam optimizer

        # building the datasets
        train_data_set = MLPDataset(self._training_set)
        val_data_set = MLPDataset(self._validation_set)

        # loss preparation for early stop of training        
        epochs_since_last_best = 0
        best_avg_loss = math.inf
        best_weights = {}

        # initializing the torch dataloaders for training and validation
        train_data_loader = torch.utils.data.DataLoader(train_data_set, batch_size=self.batch_size, shuffle=True)
        val_data_loader = torch.utils.data.DataLoader(val_data_set, batch_size=self.batch_size, shuffle=True)

        max_epochs = 10000
        # iterate through max epochs
        bar = tqdm(range(0, max_epochs), 'training'.rjust(27), unit=" epochs")  # fancy print for training        
        for e in bar:
            # running_loss = 0

            # training
            for i, data in enumerate(train_data_loader):
                inputs, labels = data

                optimizer.zero_grad()  # prepare gradients

                outputs = self._model(inputs)  # compute output
                loss = criterion(outputs, labels)  # compute loss

                loss.backward()  # compute gradients
                optimizer.step()  # update weights

                # running_loss += loss.item()

            # validation
            val_loss = 0.0
            count = 0
            # calculate validation loss
            for i, data in enumerate(val_data_loader):
                inputs, labels = data
                outputs = self._model(inputs)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                count += 1
            avg_val_loss = val_loss / count

            if avg_val_loss < best_avg_loss:
                best_avg_loss = avg_val_loss
                best_weights = self._model.state_dict()
                epochs_since_last_best = 1
            else:
                epochs_since_last_best += 1

            # determine if loss optimization occurred in last x epochs, if not stop training
            #loss_dq.append(avg_val_loss)
            stop_early = False
            if epochs_since_last_best >= self._early_stop_epochs:
                stop_early = True

            # refreshs the fancy printing
            bar.set_description(f"fit MLP {epochs_since_last_best}|{best_avg_loss:.5f}".rjust(27), refresh=True)

            if stop_early:
                break
        
        print(f"stop at {bar.n} epochs".rjust(27))        
        self._result_dict = {}
        self._model.load_state_dict(best_weights)
        self._model.eval()


    def _calculate(self, syscall: Syscall):
        """
            calculates the anomaly score for one syscall
            idea: output of the neural network is a softmax layer containing the
                    estimated probability p for every possible output
                    1-p for the actual next syscall is then used as anomaly score

            Args:
                syscall: the current System Call Object

            returns: anomaly score
        """
        input_vector = self.input_vector.get_result(syscall)
        label = self.output_label.get_result(syscall)
        if input_vector is not None:
            if input_vector in self._result_dict:
                return self._result_dict[input_vector]
            else:
                in_tensor = torch.tensor(input_vector, dtype=torch.float32)
                mlp_out = self._model(in_tensor)

                try: 
                    label_index = label.index(1)  # getting the index of the actual next datapoint
                    anomaly_score = 1 - mlp_out[label_index]
                except:
                    anomaly_score = 1

                self._result_dict[input_vector] = anomaly_score
                return anomaly_score
        else:
            return None

    def depends_on(self):
        self.list = self._dependency_list
        return self.list

    def get_net_weights(self):
        """
            returns information about weights and biases of the neural network
        """

        # iterating over layers, if layer has weights it will be added with its index to the results
        weight_dict = {}
        for i in range(len(self._model)):
            if hasattr(self._model[i], 'weight'):
                weight_dict[str(i)] = {
                    'type': type(self._model[i]).__name__,
                    'in_features': self._model[i].in_features,
                    'out_features': self._model[i].out_features,
                    'weights': self._model[i].weight,
                    'bias': self._model[i].bias
                }
        return weight_dict



class Feedforward:
    """
        handles the torch neural net by using the Sequential Class for mlp initialization
        implements adjustable hidden layers

        Args:
            input_size: the size of the input vector
            hidden_size: the number of neurons of the hidden layers
            output_size: the size of the output vector
            hidden_layers: the number of hidden layers
    """

    def __init__(self, input_size, hidden_size, output_size, hidden_layers):
        super(Feedforward, self).__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        layer_list = self._get_mlp_sequence(hidden_layers)

        self.model = nn.Sequential(*layer_list)  # giving sequential the layers as list

    def _get_mlp_sequence(self, hidden_layers):
        """
            initializes the mlp layers as list
            number of hidden layers is adjustable

            input and hidden layers are Linear
            activation function is ReLU
            output layer is Softmax

            Args:
                number of hidden layers

        """
        hidden_layer_list = []
        for i in range(hidden_layers):
            hidden_layer_list.append(nn.Linear(self.hidden_size, self.hidden_size))
            hidden_layer_list.append(nn.Dropout(p=0.5))
            hidden_layer_list.append(nn.ReLU())


        return [
                   nn.Linear(self.input_size, self.hidden_size),
                   nn.Dropout(p=0.5),
                   nn.ReLU()
               ] + hidden_layer_list + [
                   nn.Linear(self.hidden_size, self.output_size),
                   nn.Dropout(p=0.5),
                   nn.Softmax()
               ]
