import os
import pickle
import typing

from treelib import Tree
from treelib.exceptions import DuplicatedNodeIdError

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class PathEvilness(BuildingBlock):
    def __init__(self, scenario_path, path='Models', force_retrain=False, ):
        """
        Feature calculateor that builds a tree for all existing paths in the 
        training data while training.
        
        In the calculateion step the calculateor returns 0 for syscalls without 
        filepath in args and for known paths.
        
        If a path is not present in the tree the calculateor checks the height 
        of the anomaly in the tree and returns 1/height resulting in a return
        value that is always 0 < return_value < 1
        """
        super().__init__()
        scenario_name = os.path.basename(os.path.normpath(scenario_path))
        self._file_tree = Tree()
        self._file_tree.create_node('root', 'root')
        self._path = os.path.join(path, f'{scenario_name}-files.tree')
        self._cache = []
        self._tree_was_loaded = False
        if not force_retrain:
            self._load()

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        return []

    def train_on(self, syscall: Syscall, features: dict):
        """
        takes one systemcall and builds the training buffer
        """
        if not self._tree_was_loaded:
            fd = self._get_valid_fd_or_none(syscall.params())

            if fd is not None:
                path_list = self._fd_preprocessing(fd)
                if path_list is not None:
                    if path_list not in self._cache:
                        self._cache.append(path_list)
                        self._build_file_tree(path_list)

    def _get_valid_fd_or_none(self, params) -> typing.Union[str, None]:
        """
        checks syscall params for file descriptor tags and calculates its value if present, if not it returns None
        Returns:
            value of file descriptor param or None
        """
        param_names = ['fd', 'in_fd', 'out_fd']  # params to investigate
        for param in param_names:
            if param in params:
                fd = params[param]
                if '<f>' in fd:
                    return fd
        return None

    def _fd_preprocessing(self, fd) -> typing.Union[list, None]:
        """
        preprocesses file descriptor by cutting front and back of the string and splitting it on '/'
        Returns:
            path as list if / in path
            None if no valid filepath
        """
        if '<f>' in fd:
            index = fd.find('<f>')  # <f> occurs at the beginning of all real file paths in file descriptors
            clean_path = fd[index + 3:-1]
            if '/' in clean_path:
                return ['root'] + clean_path.split('/')[1:]
            else:
                return None

    def _build_file_tree(self, path_list):
        """
        builds the file tree on given path
        """
        i = 1
        while i < len(path_list):
            child = path_list[i]
            child_id = os.path.join(*path_list[:i + 1])
            parent_id = os.path.join(*path_list[:i])
            try:
                self._file_tree.create_node(child, child_id, parent_id)
            except DuplicatedNodeIdError:
                pass  # Todo if this is the correct behaviour it should be explained in a comment here
            i += 1

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        calculates evilness by checking if path exists in cache
        if not it calculates evilness by looking for the height of the first
        deviating path part
        Returns:
            evilness between 0 and 1
        """
        evilness = 0

        fd = self._get_valid_fd_or_none(syscall.params())
        if fd is not None:
            path_list = self._fd_preprocessing(fd)
            if path_list not in self._cache and path_list is not None:
                i = 1
                while i < len(path_list):
                    node_id = os.path.join(*path_list[:i + 1])
                    parent_id = os.path.join(*path_list[:i])
                    node = self._file_tree.get_node(node_id)
                    i += 1
                    if node is None:
                        parent_node = self._file_tree.get_node(parent_id)
                        evilness = 1 / (self._file_tree.depth(parent_node) + 1)
                        break
        dependencies[self.get_id()] = evilness

    def fit(self):
        """
        persists tree and finalizes training
        """
        file_handler = open(self._path, 'wb')
        pickle.dump(self._file_tree, file_handler)

    def _load(self):
        """
        loads tree from models folder if it already exists
        """
        try:
            file_handler = open(self._path, 'rb')
            self._file_tree = pickle.load(file_handler)
            self._tree_was_loaded = True
        except FileNotFoundError:
            pass
