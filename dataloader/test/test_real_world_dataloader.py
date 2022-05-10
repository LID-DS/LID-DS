import pytest

from dataloader.dataloader_factory import dataloader_factory


def create_real_world_dummy():
    base_path = '/tmp/dummy21/dummyscenario'
    path = os.path.join(base_path, 'test', 'normal')
    os.makedirs(path, exist_ok=True)

    os.system(f'touch {path}/dummy.zip')

    return base_path
