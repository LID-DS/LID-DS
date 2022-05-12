import pytest
import os

from dataloader.direction import Direction
from dataloader.dataloader_real_world import DataLoaderRealWorld

def test_real_world_dataloader():
    dataloader = DataLoaderRealWorld(scenario_path='dataloader/test/real_world_dummy/',
                                     direction=Direction.BOTH)
    for recording in dataloader.test_data():
        assert recording.metadata()['exploit']==True
    for recording in dataloader.training_data():
        assert recording.metadata()['exploit']==False
