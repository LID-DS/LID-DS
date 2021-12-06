import collections
from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
import torch
import torch.utils.data.dataset as td
import torch.nn as nn
import numpy as np
from tqdm import tqdm
import math

device = torch.device("cpu") 

class AEDataset(td.Dataset):
    """
    helper class used to present the data to torch
    """
    def __init__(self, data: set) -> None:
        super().__init__()
        data_array = []
        for line in data:
            data_array.append(line)
        self.xy_data = torch.tensor(data_array, dtype=torch.float32).to(device) 

    def __len__(self):
        return len(self.xy_data)

    def __getitem__(self, idx):
        xy = self.xy_data[idx]
        return xy

class AENetwork(nn.Module):
    """
    the actual autoencoder as torch module
    """
    def __init__(self, input_size, hidden_size):
        super().__init__()
        self._input_size = input_size
        
        # Building an linear encoder with Linear
        # layer followed by SELU activation function
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(self._input_size, 100),
            torch.nn.SELU(),
            torch.nn.Linear(100, 70),
            torch.nn.SELU(),
            torch.nn.Linear(70, 50),
            torch.nn.SELU(),
            torch.nn.Linear(50, 35),
            torch.nn.SELU(),
            torch.nn.Linear(35, hidden_size),
            torch.nn.SELU(),
        )
          
        # Building an linear decoder with Linear
        # layer followed by SELU activation function
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(hidden_size, 35),
            torch.nn.SELU(),                   
            torch.nn.Linear(35, 50),
            torch.nn.SELU(),       
            torch.nn.Linear(50, 70),
            torch.nn.SELU(),       
            torch.nn.Linear(70, 100),
            torch.nn.SELU(),
            torch.nn.Linear(100, self._input_size),
            torch.nn.SELU()
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AE(BaseDecisionEngine):
    """
    the decision engine
    """
    def __init__(self, input_size, hidden_size):
        super().__init__()
        self._autoencoder = AENetwork(input_size,hidden_size)
        self._autoencoder.train()
        self._loss_function = torch.nn.MSELoss()
        self._epochs = 10000
        self._batch_size = 128
        self._training_set = set() # we use distinct training data
        self._result_dict = {}
        self._optimizer = torch.optim.Adam(            
            self._autoencoder.parameters(),
            lr = 0.001,
            weight_decay=0.01
        )
        self._early_stopping_num_epochs = 100

    def train_on(self, input_array: list):        
        self._training_set.add(tuple(input_array))
        
    def val_on(self, input_array: list):
        pass
        
    def fit(self):
        print(f"size of distinct training data: {len(self._training_set)}")
        loss_dq = collections.deque(maxlen=self._early_stopping_num_epochs)
        best_avg_loss = math.inf
        best_ae_model = None
        ae_ds = AEDataset(self._training_set)
        torch.manual_seed(1)
        data_loader = torch.utils.data.DataLoader(ae_ds, batch_size=self._batch_size, shuffle=True)
        bar = tqdm(range(0, self._epochs), 'training'.rjust(27), unit=" epochs")
        for epoch in bar:            
            epoch_loss = 0.0
            max_loss = 0.0
            count = 0
            for (batch_index, batch) in enumerate(data_loader):
                count += 1
                X = batch  # inputs
                Y = batch  # targets (same as inputs)
                self._optimizer.zero_grad()                # prepare gradients
                oupt = self._autoencoder(X)                # compute output/target
                loss_value = self._loss_function(oupt, Y)  # a tensor
                if loss_value.item() > max_loss:
                    max_loss = loss_value.item()
                epoch_loss += loss_value.item()            # accumulate for display
                loss_value.backward()                      # compute gradients
                self._optimizer.step()                     # update weights
            avg_loss = epoch_loss /count
            bar.set_description(f"fit AE: avg|best loss={avg_loss:.3f}|{best_avg_loss:.3f}".rjust(27), refresh=True)            
            if avg_loss < best_avg_loss:
                best_avg_loss = avg_loss
                best_ae_model = self._autoencoder.parameters()

            loss_dq.append(avg_loss)            
            stop_early = True
            for l in loss_dq:
                if l == best_avg_loss:
                    stop_early = False
            if stop_early:                
                break

        print(f"stopped after {bar.n} epochs")
        self._result_dict = {}
        self._autoencoder.eval()
        
    def predict(self, input_array: list) -> float:
        input_tuple = tuple(input_array)
        if input_tuple in self._result_dict:
            return self._result_dict[input_tuple]
        else:
            # Output of Autoencoder        
            in_t = torch.tensor(input_array, dtype=torch.float32).to(device) 
            ae_output_t = self._autoencoder(in_t)
            # Calculating the loss function
            loss = self._loss_function(ae_output_t, in_t).item()
            self._result_dict[input_tuple] = loss
            return loss

    def new_recording(self):
        pass