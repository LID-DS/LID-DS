import os
import shutil
import pytest

from dataloader.direction import Direction
from dataloader.dataloader_real_world import DataLoaderRealWorld

def test_real_world_dataloader():
    scenario_path='dataloader/test/real_world_dummy/'
    dataloader = DataLoaderRealWorld(scenario_path=scenario_path,
                                     direction=Direction.BOTH)
    source_training = scenario_path + '/training/20220303_donnerstag_vormittag_99.zip'
    source_test = scenario_path + '/test/20220307_montag_malicious_1.zip'
    dest_training = '/tmp/20220303_donnerstag_vormittag_99.zip'
    dest_test = '/tmp/20220307_montag_malicious_1.zip'
    shutil.copyfile(source_training, dest_training)
    shutil.copyfile(source_test, dest_test)
    for recording in dataloader.test_data():
        assert recording.metadata()['exploit']==True
    for recording in dataloader.training_data():
        assert recording.metadata()['exploit']==False
    os.remove(source_training)
    os.remove(source_test)
    shutil.copyfile(dest_training, source_training)
    shutil.copyfile(dest_test, source_test)
