from enum import Enum
from functools import lru_cache
import time
from tqdm import tqdm
import math
import numpy
from tensorflow import keras
from keras.constraints import max_norm

from dataloader.syscall import Syscall
from algorithms.building_block import BuildingBlock


class AE_TF(BuildingBlock):    
    """
    a simple implementation of the ae using keras/tf
    does not support AEMode.Hidden or AEMode.LOSS_AND_HIDDEN
    I used this to check our AE results - its seems booth have similar results
    """
    def __init__(self, input_vector: BuildingBlock, batch_size=256, epochs=1000):
        super().__init__()                
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._input_size = 0
        self._autoencoder = None              
        self._batch_size = batch_size
        self._training_set = set() 
        self._validation_set = set()
        self._epochs = epochs

        # model state
        self._model_state = "Training"


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
        

    def _build_model(self, input_vector_size):
        self._first_hidden_layer_size = 100
        self._factor = 0.7
        self._dropout = 0.5
        self._max_norm_value = 2.0
        # number of encoding and decoding layers
        self._num_layers = 5 
        self._loss = keras.losses.MeanSquaredError()
        self._optimizer=keras.optimizers.Adam()
        self._activation_function = "selu"

        # input
        input_layer = keras.Input(shape=(input_vector_size,), dtype="float32", name="input_layer")
        x = input_layer
        # encoding
        for i in range(0, self._num_layers-1):
            x = keras.layers.Dense(
                self._first_hidden_layer_size * pow(self._factor, i), 
                activation=self._activation_function, 
                name="encoder_hidden_{}".format(i), 
                kernel_constraint=max_norm(self._max_norm_value)
            )(x)
            x = keras.layers.Dropout(self._dropout)(x)
        
        # decoding
        for i in range(self._num_layers-1, -1, -1):
            x = keras.layers.Dense(
                self._first_hidden_layer_size * pow(self._factor, i), 
                activation=self._activation_function, 
                name="decoder_hidden_{}".format(i), 
                kernel_constraint=max_norm(self._max_norm_value)
            )(x)
            x = keras.layers.Dropout(self._dropout)(x)

        # output
        output_layer = keras.layers.Dense(
            input_vector_size, 
            activation=self._activation_function, 
            name="output_layer", 
            kernel_constraint=max_norm(self._max_norm_value)
        )(x)
        model = keras.Model(inputs=input_layer, outputs=output_layer, name="simple_autoencoder")
        # model.summary()        
        model.compile(loss=self._loss, optimizer=self._optimizer)
        return model


    def fit(self):
        print(f"AE.train_set: {len(self._training_set)}".rjust(27))

        # prepare the training matrix        
        self._number_of_cols = self._input_size
        self._number_of_rows = len(self._training_set)
        training_matrix = numpy.zeros((self._number_of_rows, self._number_of_cols), dtype="single")
        
        # build the model:
        self._autoencoder = self._build_model(self._input_size)

        # prepare the row buffer for use in detection mode
        self._np_buffer = numpy.zeros((1, self._input_size), dtype="single")

        # build the training matrix
        row = 0        
        for input_value in self._training_set:            
            training_matrix[row] = input_value
            row += 1
        
        # finally fit the autoencoder
        print(f"matrix.shape = {training_matrix.shape} --> {training_matrix.size}")
        #callback_early_stopping = tf.keras.callbacks.EarlyStopping(monitor='loss', patience=10, restore_best_weights=True)        
        #callback_timed_stopping = TimedStopping(seconds=5*60*60,verbose=1) # stop after 5h = 5 * 60 * 60 seconds        
        # self._autoencoder.fit(training_matrix, training_matrix, batch_size=128, epochs=1000, validation_split=0.0, callbacks=[callback_early_stopping, callback_timed_stopping], verbose=2)
        self._autoencoder.fit(training_matrix, training_matrix, batch_size=self._batch_size, epochs=self._epochs, validation_split=0.0, verbose=0)

        print("switching to detection mode")
        # set state to detection
        self._model_state = "detection"       

        self._training_set = set() 
        self._validation_set = set()
        
        
    @lru_cache(maxsize=1000)
    def _cached_results(self, input_vector):
        if input_vector is None:            
            return None            
        else:            
            # Output of Autoencoder
            self._np_buffer[0] = input_vector
            result = self._autoencoder.test_on_batch(x=self._np_buffer, y=self._np_buffer)            
            return result    


    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        return self._cached_results(input_vector)

    def new_recording(self):
        pass