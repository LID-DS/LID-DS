import pytest
import os

from dataloader.dataloader_factory import dataloader_factory

from dataloader.dataloader_real_world import DataLoaderRealWorld
from dataloader.data_loader_2019 import DataLoader2019
from dataloader.data_loader_2021 import DataLoader2021

from shutil import rmtree


def test_dataloader_factory():
    path_2019 = create_2019_dummy()
    path_2021 = create_2021_dummy()
    path_real_world = create_real_world_dummy()
    invalid_path = create_invalid_dummy()

    dataloader_object_2019 = dataloader_factory(path_2019)
    assert isinstance(dataloader_object_2019, DataLoader2019)

    dataloader_object_2021 = dataloader_factory(path_2021)
    assert isinstance(dataloader_object_2021, DataLoader2021)

    dataloader_object_real_world = dataloader_factory(path_real_world)
    assert isinstance(dataloader_object_real_world, DataLoaderRealWorld)

    with pytest.raises(ValueError):
        invalid_dataloader = dataloader_factory(invalid_path)

    clean_up()


def create_2019_dummy():
    path = '/tmp/dummy19/dummyscenario'
    os.makedirs(path, exist_ok=True)

    os.system(f'touch {path}/runs.csv')

    with open(os.path.join(path, 'runs.csv'), 'w+') as runs_file:
        runs_file.writelines(
            ['image_name, scenario_name, is_executing_exploit, warmup_time, recording_time, exploit_start_time',
             'lid-ds/cve-2017-7529:latest, dummy.txt, False, 10, 40, -1'])

    with open(os.path.join(path, 'runs.csv'), 'w+') as recording_file:
        recording_file.writelines(
            ['6 10:19:40.823572081 6 101 nginx 23804 < epoll_wait res=1 '])

    return path


def create_2021_dummy():
    base_path = '/tmp/dummy21/dummyscenario'
    path = os.path.join(base_path, 'test', 'normal')
    os.makedirs(path, exist_ok=True)

    os.system(f'touch {path}/dummy.zip')

    return base_path


def create_real_world_dummy():
    base_path = '/tmp/dummyrw/dummyscenario'
    path = os.path.join(base_path, 'test')
    os.makedirs(path, exist_ok=True)

    os.system(f'touch {path}/dummy.zip')

    return base_path


def create_invalid_dummy():
    path = '/tmp/dumb_dummy/dummydumb'
    os.makedirs(path, exist_ok=True)
    os.system(f'touch {path}/superdumbdummy.exe')

    return path


def clean_up():
    rmtree('/tmp/dummy19')
    rmtree('/tmp/dummy21')
    rmtree('/tmp/dumb_dummy')
