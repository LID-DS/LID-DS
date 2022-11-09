import os
import shutil
import pytest

from dataloader.direction import Direction
from dataloader.data_loader_ctf import DataLoaderCTF

def test_real_world_dataloader():
    scenario_path = 'dataloader/test/ctf_dummy_scenario'
    dataloader = DataLoaderCTF(scenario_path=scenario_path,
                                     direction=Direction.BOTH)

    # check if recording types are detected correctly
    for recording in dataloader.training_data():
        assert recording.metadata()['exploit'] == False
    for recording in dataloader.validation_data():
        assert recording.metadata()['exploit'] == False

    # check if count of syscalls, last syscall name and last thread id is correct
    syscall_counter = 0
    last_syscall_name = ''
    last_syscall_tid = 0
    for recording in dataloader.training_data():
        for syscall in recording.syscalls():
            syscall_counter += 1
            last_syscall_name = syscall.name()
            last_syscall_tid = syscall.thread_id()

    assert syscall_counter == 2680
    assert last_syscall_name == "epoll_wait"
    assert last_syscall_tid == 32240

    syscall_counter = 0
    for recording in dataloader.validation_data():
        for syscall in recording.syscalls():
            syscall_counter += 1
            last_syscall_name = syscall.name()
            last_syscall_tid = syscall.thread_id()

    assert syscall_counter == 2196
    assert last_syscall_name == "epoll_wait"
    assert last_syscall_tid == 88707

    syscall_counter = 0
    for recording in dataloader.test_data():
        for syscall in recording.syscalls():
            syscall_counter += 1
            last_syscall_name = syscall.name()
            last_syscall_tid = syscall.thread_id()

    assert last_syscall_name == "epoll_wait"
    assert syscall_counter == 11652
    assert last_syscall_tid == 38947
