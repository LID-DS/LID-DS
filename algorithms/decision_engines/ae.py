from enum import Enum
from functools import lru_cache
import time
import torch
import torch.utils.data.dataset as td
import torch.nn as nn
from tqdm import tqdm
import math

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') 


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
        self.xy_data = torch.tensor(data_array, dtype=torch.float32, device=device)

    def __len__(self):
        return len(self.xy_data)

    def __getitem__(self, idx):
        xy = self.xy_data[idx]
        return xy

class AENetwork(nn.Module):
    """
    the actual autoencoder as torch module
    """

    def __init__(self, input_size):
        super().__init__()        
        self._input_size = input_size
        self._factor = 0.7
        first_hidden_layer_size = self._input_size #int(self._input_size * 1.333)
        # Building an encoder
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(self._input_size, first_hidden_layer_size),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),
            
            torch.nn.Linear(first_hidden_layer_size, int(first_hidden_layer_size * pow(self._factor,2))),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),

            torch.nn.Linear(int(first_hidden_layer_size * pow(self._factor,2)), int(first_hidden_layer_size * pow(self._factor,3))),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),

            torch.nn.Linear(int(first_hidden_layer_size * pow(self._factor,3)), int(first_hidden_layer_size * pow(self._factor,4))),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU()
        )
          
        # Building an decoder
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(int(first_hidden_layer_size * pow(self._factor,4)), int(first_hidden_layer_size * pow(self._factor,3))),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),

            torch.nn.Linear(int(first_hidden_layer_size * pow(self._factor,3)), int(first_hidden_layer_size * pow(self._factor,2))),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),

            torch.nn.Linear(int(first_hidden_layer_size * pow(self._factor,2)), first_hidden_layer_size),
            torch.nn.Dropout(p=0.5),
            torch.nn.SELU(),

            torch.nn.Linear(first_hidden_layer_size, self._input_size),
            torch.nn.Dropout(p=0.5),
            #torch.nn.Sigmoid()
        )

        for m in self.encoder:
            if isinstance(m, nn.Linear):
                fan_in = m.in_features
                nn.init.normal(m.weight, 0, math.sqrt(1. / fan_in))
        for m in self.decoder:
            if isinstance(m, nn.Linear):
                fan_in = m.in_features                
                nn.init.normal(m.weight, 0, math.sqrt(1. / fan_in))                

    def max_norm(self, max_val=2, eps=1e-8):
        for name, param in self.named_parameters():
            if 'bias' not in name:
                norm = param.norm(2, dim=0, keepdim=True)
                desired = torch.clamp(norm, 0, max_val)
                param = param * (desired / (eps + norm))

    def forward(self, x):        
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        self.max_norm()
        return decoded


class AE(BuildingBlock):
    """
    the decision engine
    """
    def __init__(self, input_vector: BuildingBlock, mode: AEMode = AEMode.LOSS, batch_size=256, max_training_time=600, early_stopping_epochs=50):
        super().__init__()                
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._mode = mode 
        self._input_size = 0
        self._autoencoder = None 
        self._loss_function = torch.nn.MSELoss()        
        self._batch_size = batch_size
        self._training_set = set() 
        self._validation_set = set()
        self._max_training_time = max_training_time # time in seconds
        self._early_stopping_num_epochs = early_stopping_epochs

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
        print(f"AE.train_set: {len(self._training_set)}".rjust(27))
        self._autoencoder = AENetwork(self._input_size).to(device)         
        self._autoencoder.train()
        self._optimizer = torch.optim.Adam(            
            self._autoencoder.parameters(),
            lr = 0.001,
            betas=(0.9,0.999),
            eps=1e-07,
            amsgrad=False
        )
        # loss preparation for early stop of training        
        best_avg_val_loss = math.inf
        epochs_since_last_best = 0
        best_weights = {}
        training_start_time = time.time()

        ae_ds = AEDataset(self._training_set)
        ae_ds_val = AEDataset(self._validation_set)
        data_loader = torch.utils.data.DataLoader(ae_ds, batch_size=self._batch_size, shuffle=True)
        val_data_loader = torch.utils.data.DataLoader(ae_ds_val, batch_size=self._batch_size, shuffle=True)
        
        with tqdm(total=self._max_training_time, unit=" epoch", bar_format="{l_bar}{bar}| {n:0.1f}/{total}s") as bar:              
            last_ts = time.time()            
            epoch_counter = 0
            bar.set_description(f"fit AE: {epoch_counter}|{0}/{self._early_stopping_num_epochs}|None".rjust(27), refresh=True)
            while True:
                epoch_counter += 1                
                for (batch_index, batch) in enumerate(data_loader):                    
                    X = batch  # inputs
                    Y = batch  # targets (same as inputs)
                    # forward
                    oupt = self._autoencoder(X)                # compute output
                    loss_value = self._loss_function(oupt, Y)  # compute loss (a tensor)
                    # backward                
                    self._optimizer.zero_grad()                # prepare gradients
                    loss_value.backward()                      # compute gradients
                    self._optimizer.step()                     # update weights

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

                if avg_val_loss < best_avg_val_loss:
                    best_avg_val_loss = avg_val_loss
                    best_weights = self._autoencoder.state_dict()
                    epochs_since_last_best = 1
                else:
                    epochs_since_last_best += 1
                
                stop_early = False

                # early stopping by epochs
                if epochs_since_last_best >= self._early_stopping_num_epochs:
                    stop_early = True

                # early stopping by time
                duration = time.time() - training_start_time
                if duration > self._max_training_time:
                    stop_early = True

                # print epoch results
                # {self._max_training_time - duration:.1f}|
                bar.set_description(f"fit AE: {epoch_counter}|{epochs_since_last_best}/{self._early_stopping_num_epochs}|{best_avg_val_loss:.5f}".rjust(27), refresh=True)
                
                dts = time.time() - last_ts 
                bar.update(dts)
                last_ts = time.time()
                
                if stop_early:
                    break

        print(f"stop at {bar.n:2f} seconds and {epoch_counter} epochs".rjust(27))        
        self._autoencoder.load_state_dict(best_weights)
        self._autoencoder.eval()
        self._training_set = set() 
        self._validation_set = set()


    @lru_cache(maxsize=1000)
    def _cached_results(self, input_vector):
        if input_vector is None:            
            return None            
        else:            
            # Output of Autoencoder        
            result = 0
            in_t = torch.tensor(input_vector, dtype=torch.float32).to(device) 
            if self._mode == AEMode.LOSS:
                # calculating the autoencoder:
                with torch.no_grad():
                    ae_output_t = self._autoencoder(in_t)
                # Calculating the loss function
                result = self._loss_function(ae_output_t, in_t).item()
            if self._mode == AEMode.HIDDEN:
                # calculating only the encoder part of the autoencoder:
                with torch.no_grad():
                    ae_encoder_t = self._autoencoder.encoder(in_t)
                result = tuple(ae_encoder_t.tolist())
            if self._mode == AEMode.LOSS_AND_HIDDEN:
                with torch.no_grad():
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

            return result    


    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        return self._cached_results(input_vector)

    def new_recording(self):
        pass