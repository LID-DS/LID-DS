from enum import Enum
from functools import lru_cache
import sys
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

    def __init__(self, input_size, bottleneck_size=64):
        super().__init__()
        self._input_size = input_size
        hidden = max(bottleneck_size * 4, 256)

        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(self._input_size, hidden),
            torch.nn.Dropout(p=0.1),
            torch.nn.ReLU(),

            torch.nn.Linear(hidden, bottleneck_size),
            torch.nn.Dropout(p=0.1),
            torch.nn.ReLU(),
        )

        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(bottleneck_size, hidden),
            torch.nn.Dropout(p=0.1),
            torch.nn.ReLU(),

            torch.nn.Linear(hidden, self._input_size),
            torch.nn.Sigmoid(),
        )

        for m in list(self.encoder) + list(self.decoder):
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity='relu')

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AE(BuildingBlock):
    """
    the decision engine
    """
    def __init__(self, input_vector: BuildingBlock, mode: AEMode = AEMode.LOSS,
                 batch_size=256, max_training_time=600, early_stopping_epochs=50,
                 bottleneck_size=64, deduplicate_training=True):
        super().__init__()
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._mode = mode
        self._input_size = 0
        self._autoencoder = None
        self._loss_function = torch.nn.MSELoss()
        self._batch_size = batch_size
        self._deduplicate = deduplicate_training
        self._training_set = set() if deduplicate_training else []
        self._validation_set = set() if deduplicate_training else []
        self._max_training_time = max_training_time
        self._early_stopping_num_epochs = early_stopping_epochs
        self._bottleneck_size = bottleneck_size

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)
            t = tuple(input_vector)
            if self._deduplicate:
                self._training_set.add(t)
            else:
                self._training_set.append(t)

    def val_on(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        if input_vector is not None:
            t = tuple(input_vector)
            if self._deduplicate:
                self._validation_set.add(t)
            else:
                self._validation_set.append(t)
        
    def fit(self):
        _quiet = not sys.stderr.isatty()
        if not _quiet:
            print(f"AE.train_set: {len(self._training_set)}".rjust(27))
        self._autoencoder = AENetwork(self._input_size, self._bottleneck_size).to(device)
        self._autoencoder.train()
        self._optimizer = torch.optim.Adam(
            self._autoencoder.parameters(),
            lr=0.001,
            betas=(0.9, 0.999),
            eps=1e-07,
            weight_decay=1e-5,
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
        
        with tqdm(total=self._max_training_time, unit=" epoch", bar_format="{l_bar}{bar}| {n:0.1f}/{total}s", disable=_quiet) as bar:              
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

        if not _quiet:
            print(f"stop at {bar.n:2f} seconds and {epoch_counter} epochs".rjust(27))        
        self._autoencoder.load_state_dict(best_weights)
        self._autoencoder.eval()
        self._training_set = set() if self._deduplicate else []
        self._validation_set = set() if self._deduplicate else []


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