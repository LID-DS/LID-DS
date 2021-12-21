from typing import Union

from tqdm import tqdm
from algorithms.building_block import BuildingBlock

from algorithms.building_block_manager import BuildingBlockManager
from dataloader.base_data_loader import BaseDataLoader
from dataloader.syscall import Syscall


class DataPreprocessor:
    """
        Receives DataLoader object, and a list of BuildingBlocks
        Training data, validation data and test data can than be returned as feature lists.

    """

    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block: BuildingBlock
                 ):
        self._data_loader = data_loader
        self._building_block_manager = BuildingBlockManager(resulting_building_block)
        print("feature dependency graph: ")
        print(self._building_block_manager.to_dot())
        self._prepare_and_fit_building_blocks()

    def _prepare_and_fit_building_blocks(self):
        """
        preprocessing for building blocks
        - calls train on, val on and fit for each building block on the training data in the order given by the building block manager
        """
        num_generations = len(self._building_block_manager.building_block_generations)
        for current_generation in range(0, num_generations):
            # infos
            print(f"at generation: {current_generation + 1} of {num_generations}: {self._building_block_manager.building_block_generations[current_generation]}")
            for previous_generation in range(0, current_generation):
                print(f" | depending on: {self._building_block_manager.building_block_generations[previous_generation]}")

            # training
            for recording in tqdm(self._data_loader.training_data(),
                                  f"train bb {current_generation + 1}/{num_generations}".rjust(27),
                                  unit=" recording"):
                for syscall in recording.syscalls():
                    dependencies = {}
                    # calculate already fitted bbs
                    for previous_generation in range(0, current_generation):
                        for previous_bb in self._building_block_manager.building_block_generations[previous_generation]:                            
                            previous_bb.calculate(syscall, dependencies)
                    # call train_on for current iteration bbs
                    for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                        current_bb.train_on(syscall, dependencies)
                self.new_recording()

            # validation
            for recording in tqdm(self._data_loader.validation_data(),
                                  f"val bb {current_generation + 1}/{num_generations}".rjust(27),
                                  unit=" recording"):
                for syscall in recording.syscalls():
                    dependencies = {}
                    # calculate already fitted bbs
                    for previous_generation in range(0, current_generation):
                        for previous_bb in self._building_block_manager.building_block_generations[previous_generation]:                            
                            previous_bb.calculate(syscall, dependencies)
                    # call val_on for current iteration bbs
                    for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                        current_bb.val_on(syscall, dependencies)
                self.new_recording()            

            # fit current generation bbs
            for current_bb in tqdm(self._building_block_manager.building_block_generations[current_generation],
                                        f"fitting bbs {current_generation + 1}/{num_generations}".rjust(27),
                                        unit=" bbs"):
                current_bb.fit()

    def calculate_building_blocks_for_syscall(self, syscall: Syscall):
        """
        calculates all building blocks for the given system call        
        Returns: a dictionary with all calculated building block results
        """
        # first calculate all bbs in the correct order
        dependencies = {}
        for current_generation in range(0, len(self._building_block_manager.building_block_generations)):
            for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                current_bb.calculate(syscall, dependencies)
        return dependencies

    def new_recording(self):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all features and calls new_recording on them
        """
        for generation in self._building_block_manager.building_block_generations:
            for bb in generation:
                bb.new_recording()
