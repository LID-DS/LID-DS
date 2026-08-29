from typing import Union
import urllib
from tqdm import tqdm
from algorithms.building_block import BuildingBlock

from algorithms.building_block_manager import BuildingBlockManager
from dataloader.base_data_loader import BaseDataLoader
from dataloader.syscall import Syscall

def dot_to_str(dot):
    dot_str = dot.to_string()
    lines = dot_str.splitlines()
    result = ""
    for line in lines:
        if '" -> "' in line or "strict digraph  {" in line or line == "}":
            result += line + "\n"
    return result

class DataPreprocessor:
    """
        Receives DataLoader object, and a list of BuildingBlocks
        Training data, validation data and test data can than be returned as feature lists.

    """

    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block: BuildingBlock,
                 quiet: bool = False,
                 skip_training: bool = False
                 ):
        self._data_loader = data_loader
        self._building_block_manager = BuildingBlockManager(resulting_building_block)
        self._baseBB = BuildingBlock()
        self._graph_dot = dot_to_str(self._building_block_manager.to_dot())
        if not quiet and not skip_training:
            graph_url_encode = urllib.parse.quote(self._graph_dot)
            url = f"https://dreampuf.github.io/GraphvizOnline/#{graph_url_encode}"
            print("-------------------------------")
            print("Dependency Graph Visualisation:")
            print(url)
            #print(self._graph_dot)
            print("-------------------------------")

        if not skip_training:
            self._prepare_and_fit_building_blocks()

    def prepare_and_fit(self):
        """Public entry point for deferred training."""
        self._prepare_and_fit_building_blocks()

    def get_building_block_manager(self):
        return self._building_block_manager

    def get_graph_dot(self):
        return self._graph_dot

    def _train_on_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.train_on.__func__ != self._baseBB.train_on.__func__:
                return True
        return False

    def _val_on_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.val_on.__func__ != self._baseBB.val_on.__func__:
                return True
        return False

    def _fit_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.fit.__func__ != self._baseBB.fit.__func__:
                return True
        return False

    def _can_single_pass_train(self):
        """Check if all BBs support single-pass training (no fit barriers)."""
        bb_gens = self._building_block_manager.building_block_generations
        trainable = [i for i in range(len(bb_gens)) if self._train_on_needed(bb_gens[i])]
        if len(trainable) <= 1:
            return False  # Nothing to collapse
        # All BBs in gens 0..last_trainable must be online_trainable
        last_trainable = trainable[-1]
        for gen_idx in range(last_trainable + 1):
            for bb in bb_gens[gen_idx]:
                if not bb.online_trainable:
                    return False
        return True

    def _prepare_and_fit_building_blocks(self):
        """
        preprocessing for building blocks
        - calls train on, val on and fit for each building block on the training data in the order given by the building block manager
        """
        if self._can_single_pass_train():
            self._prepare_single_pass()
        else:
            self._prepare_multi_pass()

    def _prepare_single_pass(self):
        bb_gens = self._building_block_manager.building_block_generations
        num_gens = len(bb_gens)

        # Print generation info
        for i in range(num_gens):
            print(f"at generation: {i + 1} of {num_gens}: {bb_gens[i]}")

        trainable = [i for i in range(num_gens) if self._train_on_needed(bb_gens[i])]
        validatable = [i for i in range(num_gens) if self._val_on_needed(bb_gens[i])]

        # Phase 1: Single training pass (all trainable gens in one recording iteration)
        if trainable:
            for recording in tqdm(self._data_loader.training_data(),
                                  "single-pass train".rjust(27), unit=" recording"):
                for syscall in recording.syscalls():
                    for gen_idx in trainable:
                        for bb in bb_gens[gen_idx]:
                            bb.train_on(syscall)
                self.new_recording()

        # Phase 2: Fit all (in generation order)
        for i in range(num_gens):
            if self._fit_needed(bb_gens[i]):
                for bb in tqdm(bb_gens[i],
                               f"fitting bbs {i + 1}/{num_gens}".rjust(27), unit=" bbs"):
                    bb.fit()

        # Phase 3: Single validation pass
        if validatable:
            for recording in tqdm(self._data_loader.validation_data(),
                                  "single-pass val".rjust(27), unit=" recording"):
                for syscall in recording.syscalls():
                    for gen_idx in validatable:
                        for bb in bb_gens[gen_idx]:
                            bb.val_on(syscall)
                self.new_recording()

    def _prepare_multi_pass(self):
        num_generations = len(self._building_block_manager.building_block_generations)
        for current_generation in range(0, num_generations):
            # infos
            print(f"at generation: {current_generation + 1} of {num_generations}: {self._building_block_manager.building_block_generations[current_generation]}")

            # training
            if not self._train_on_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.training_data(),
                                    f"train bb {current_generation + 1}/{num_generations}".rjust(27),
                                    unit=" recording"):
                    for syscall in recording.syscalls():
                        for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                            current_bb.train_on(syscall)
                    self.new_recording()

            # validation
            if not self._val_on_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.validation_data(),
                                    f"val bb {current_generation + 1}/{num_generations}".rjust(27),
                                    unit=" recording"):
                    for syscall in recording.syscalls():
                        for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                            current_bb.val_on(syscall)
                    self.new_recording()

            # fit current generation bbs
            if not self._fit_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:
                for current_bb in tqdm(self._building_block_manager.building_block_generations[current_generation],
                                            f"fitting bbs {current_generation + 1}/{num_generations}".rjust(27),
                                            unit=" bbs"):
                    current_bb.fit()

    def new_recording(self):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all bbs and calls new_recording on them
        """
        for generation in self._building_block_manager.building_block_generations:
            for bb in generation:
                bb.new_recording()
