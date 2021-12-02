from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
import torch
import torch.nn as nn
import numpy as np
from tqdm import tqdm

# https://www.geeksforgeeks.org/implementing-an-autoencoder-in-pytorch/

class AENetwork(nn.Module):
    def __init__(self, input_size, hidden_size):
        super().__init__()
        self._input_size = input_size
        self._hidden_size = hidden_size
        
        # Building an linear encoder with Linear
        # layer followed by Relu activation function
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(self._input_size, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, self._hidden_size)
        )
          
        # Building an linear decoder with Linear
        # layer followed by Relu activation function
        # The Sigmoid activation function
        # outputs the value between 0 and 1
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(self._hidden_size, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, self._input_size),
            torch.nn.Sigmoid()
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AE(BaseDecisionEngine):
    def __init__(self, input_size, hidden_size):
        super().__init__()
        self._nn = AENetwork(input_size,hidden_size)
        self._loss_function = torch.nn.MSELoss()
        self._epochs = 10
        self._training_data = []
        self._val_data = []
        self._optimizer = torch.optim.Adam(            
            self._nn.parameters(),
            lr = 1e-1,
            weight_decay=1e-8
        )

    def train_on(self, input_array: list):
        x = np.array(input_array)        
        self._training_data.append(x)
        
    def val_on(self, input_array: list):
        x = np.array(input_array)
        self._val_data.append(x)

    def fit(self):
        # tqdm(range(self._epochs), 'training network:'.rjust(25), unit=" epochs"):
        for epoch in tqdm(range(self._epochs), 'training network:'.rjust(25), unit=" epochs"):
            for input_vector in self._training_data:
                # Output of Autoencoder
                in_t = torch.from_numpy(input_vector)
                ae_output_t = self._nn(in_t)
                # Calculating the loss function
                loss = self._loss_function(ae_output_t,  in_t)
                    
                # The gradients are set to zero,
                # the the gradient is computed and stored.
                # .step() performs parameter update
                self._optimizer.zero_grad()
                loss.backward()
                self._optimizer.step()

    def predict(self, input_array: list) -> float:
        # Output of Autoencoder
        in_t = torch.from_numpy(input_array)
        ae_output_t = self._nn(in_t)
        # Calculating the loss function
        loss = self._loss_function(ae_output_t, in_t)
        return loss

    def new_recording(self):
        pass