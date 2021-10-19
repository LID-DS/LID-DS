import os
import typing

from algorithms.features.base_syscall_feature_extractor import BaseSyscallFeatureExtractor
from dataloader.syscall import Syscall

from treelib import Tree
from treelib.exceptions import DuplicatedNodeIdError


class PathEvilness(BaseSyscallFeatureExtractor):

    def __init__(self):
        super().__init__()
        self._file_tree = Tree()
        self._file_tree.create_node('root', 'root')
        self._cache = []

    def train_on(self, syscall: Syscall):
        fd = self._get_valid_fd_or_none(syscall.params())

        if fd is not None:
            path_list = self._fd_preprocessing(fd)
            if path_list not in self._cache:
                self._cache.append(path_list)
                self._build_file_tree(path_list)

    def _get_valid_fd_or_none(self, params):
        if 'fd' in params:
            fd = params['fd']
            if '<f>' in fd:
                return fd
            else:
                return None

    def _fd_preprocessing(self, fd):
        if '<f>' in fd:
            index = fd.find('<f>')
            clean_path = fd[index + 3:-1]
            return ['root'] + clean_path.split('/')[1:]

    def _build_file_tree(self, path_list):
        i = 1
        while i < len(path_list):
            child = path_list[i]
            child_id = os.path.join(*path_list[:i + 1])
            parent_id = os.path.join(*path_list[:i])
            try:
                self._file_tree.create_node(child, child_id, parent_id)
            except DuplicatedNodeIdError:
                pass
            i += 1

    def extract(self, syscall: Syscall) -> typing.Tuple[int, object]:
        evilness = 0

        fd = self._get_valid_fd_or_none(syscall.params())
        if fd is not None:
            path_list = self._fd_preprocessing(fd)
            if path_list not in self._cache:
                for i in range(len(path_list)):
                    node_id = os.path.join(*path_list[:i+1])
                    node = self._file_tree.get_node(node_id)
                    if node is None:
                        evilness = 1 / (self._file_tree.depth(node) - 1)
                        print(evilness)
                        break



        return PathEvilness.get_id(), evilness
