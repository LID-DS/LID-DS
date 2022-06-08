import collections
from enum import Enum
import torch
import torch.utils.data.dataset as td
import torch.nn as nn
from tqdm import tqdm
import math

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


device = torch.device("cpu") 


class AEMode(Enum):
    LOSS = 1
    HIDDEN = 2
    LOSS_AND_HIDDEN = 3


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


class AE(BuildingBlock):
    """
    the decision engine
    """
    def __init__(self, input_vector: BuildingBlock, hidden_size, mode: AEMode = AEMode.LOSS, batch_size=256):
        super().__init__()                
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._mode = mode 
        self._hidden_size = hidden_size
        self._input_size = 0
        self._autoencoder = None # AENetwork(input_size,hidden_size)               
        #self._autoencoder.train()
        self._loss_function = torch.nn.MSELoss()
        self._epochs = 100000
        self._batch_size = batch_size
        self._training_set = set() # we use distinct training data
        self._validation_set = set()
        self._result_dict = {}

        self._early_stopping_num_epochs = 50

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)
            self._training_set.add(tuple(input_vector))
        
    def val_on(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            self._validation_set.add(tuple(input_vector))
        
    def fit(self):
        print(f"ae.train_set: {len(self._training_set)}".rjust(27))
        self._autoencoder = AENetwork(self._input_size ,self._hidden_size)               
        self._autoencoder.train()
        self._optimizer = torch.optim.Adam(            
            self._autoencoder.parameters(),
            lr = 0.001,# lr = 0.001,
            weight_decay=0.01
        )
        loss_dq = collections.deque(maxlen=self._early_stopping_num_epochs)
        best_avg_val_loss = math.inf
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
            bar.set_description(f"fit AE: {avg_loss:.5f}|{avg_val_loss:.5f}".rjust(27), refresh=True)            
            if avg_val_loss < best_avg_val_loss:
                best_avg_val_loss = avg_val_loss

            loss_dq.append(avg_val_loss)
            stop_early = True
            for l in loss_dq:
                if l == best_avg_val_loss:
                    stop_early = False
            if stop_early:                
                break

        print(f"stop at {bar.n} epochs".rjust(27))
        self._result_dict = {}
        self._autoencoder.eval()
        
    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:            
            if input_vector in self._result_dict:
                return self._result_dict[input_vector]
            else:
                # Output of Autoencoder        
                result = 0
                in_t = torch.tensor(input_vector, dtype=torch.float32).to(device) 
                if self._mode == AEMode.LOSS:
                    # calculating the autoencoder:
                    ae_output_t = self._autoencoder(in_t)
                    # Calculating the loss function
                    result = self._loss_function(ae_output_t, in_t).item()
                if self._mode == AEMode.HIDDEN:
                    # calculating only the encoder part of the autoencoder:
                    ae_encoder_t = self._autoencoder.encoder(in_t)
                    result = tuple(ae_encoder_t.tolist())
                if self._mode == AEMode.LOSS_AND_HIDDEN:
                    # encoder
                    ae_encoder_t = self._autoencoder.encoder(in_t)
                    # decoder
                    ae_decoder_t = self._autoencoder.decoder(ae_encoder_t)
                    # loss:
                    loss = self._loss_function(ae_decoder_t, in_t).item()
                    # hidden:
                    hidden = ae_encoder_t.tolist()
                    # result
                    rl = [loss]
                    rl.extend(hidden)
                    result = tuple(rl)

                self._result_dict[input_vector] = result
                return result    
        else:
            return None            

    def new_recording(self):
        pass