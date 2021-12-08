import collections
from algorithms.decision_engines.base_decision_engine import BaseDecisionEngine
import torch
import torch.utils.data.dataset as td
import torch.nn as nn
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
        self._factor = 0.7
        # Building an linear encoder with Linear
        # layer followed by SELU activation function
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(
                self._input_size, 
                int(self._input_size * self._factor)),
            torch.nn.SELU(),                    
            torch.nn.Linear(
                int(self._input_size * self._factor), 
                int(self._input_size * self._factor * self._factor)),
            torch.nn.SELU(),            
            torch.nn.Linear(
                int(self._input_size * self._factor * self._factor), 
                hidden_size),
            torch.nn.SELU()           
        )
          
        # Building an linear decoder with Linear
        # layer followed by SELU activation function
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(
                hidden_size, 
                int(self._input_size*self._factor*self._factor)),
            torch.nn.SELU(),                             
            torch.nn.Linear(
                int(self._input_size*self._factor*self._factor), 
                int(self._input_size*self._factor)),            
            torch.nn.SELU(),       
            torch.nn.Linear(
                int(self._input_size*self._factor), 
                self._input_size),
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
        print(self._autoencoder)
        self._autoencoder.train()
        self._loss_function = torch.nn.MSELoss()
        self._epochs = 100000
        self._batch_size = 128
        #self._batch_size = 64
        self._training_set = set() # we use distinct training data
        self._validation_set = set()
        self._result_dict = {}
        self._optimizer = torch.optim.Adam(            
            self._autoencoder.parameters(),
            lr = 0.001,# lr = 0.001,
            weight_decay=0.01
        )
        self._early_stopping_num_epochs = 200

    def train_on(self, input_array: list):        
        self._training_set.add(tuple(input_array))
        
    def val_on(self, input_array: list):
        self._validation_set.add(tuple(input_array))
        
    def fit(self):
        print(f"size of distinct training data: {len(self._training_set)}")
        loss_dq = collections.deque(maxlen=self._early_stopping_num_epochs)
        best_avg_loss = math.inf
        ae_ds = AEDataset(self._training_set)
        ae_ds_val = AEDataset(self._validation_set)
        data_loader = torch.utils.data.DataLoader(ae_ds, batch_size=self._batch_size, shuffle=True)
        val_data_loader = torch.utils.data.DataLoader(ae_ds_val, batch_size=self._batch_size, shuffle=True)
        bar = tqdm(range(0, self._epochs), 'training'.rjust(27), unit=" epochs")        
        for epoch in bar:            
            epoch_loss = 0.0            
            count = 0            
            for (batch_index, batch) in enumerate(data_loader):
                count += 1
                X = batch  # inputs
                Y = batch  # targets (same as inputs)
                # forward
                oupt = self._autoencoder(X)                # compute output
                loss_value = self._loss_function(oupt, Y)  # compute loss (a tensor)
                epoch_loss += loss_value.item()            # accumulate for display
                # backward                
                self._optimizer.zero_grad()                # prepare gradients
                loss_value.backward()                      # compute gradients
                self._optimizer.step()                     # update weights
            avg_loss = epoch_loss /count

            # validation
            val_loss = 0.0
            count = 0
            for (batch_index, batch) in enumerate(val_data_loader):
                X = batch
                outputs = self._autoencoder(X)
                loss_value = self._loss_function(outputs, X)
                val_loss += loss_value.item()
                count += 1
            avg_val_loss = val_loss / count

            # print epoch results
            bar.set_description(f"fit AE: train|val loss={avg_loss:.3f}|{avg_val_loss:.3f}".rjust(27), refresh=True)            
            if avg_loss < best_avg_loss:
                best_avg_loss = avg_loss

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