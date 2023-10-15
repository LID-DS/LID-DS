from os import listdir, path

from dataloader.dataloader_adfa_ld_2 import DataLoaderFixedADFALD
from dataloader.direction import Direction
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_loader_2019 import DataLoader2019
from dataloader.data_loader_2021 import DataLoader2021
from dataloader.dataloader_adfa_ld import DataLoaderADFALD
from dataloader.dataloader_real_world import DataLoaderRealWorld


def dataloader_factory(scenario_path: str, direction: Direction = Direction.OPEN, **kwargs) -> BaseDataLoader:
    """
    creates DataLoader 2019 or 2021 by detecting the dataset specific file structure
    """
    file_list = listdir(scenario_path)
    file_list.sort()

    _, base_file_extension = path.splitext(file_list[0])

    """
    LID-DS 2019 Dataset has txt files or one csv file in root folder which lead to return of
    DataLoader 2019 Object
    
    LID-DS 2021 has three subdirs that lead to empty file extension
    if subdirs are detected the dataset subdir with normal test data is opened
    if it contains zip files a DataLoader 2021 Object is returned

    Real World Data also has three subdirs, but no extra subdirs (normal, idle, normal_and_attack)
    """
    # if base_file_extension == '.txt' or base_file_extension == '.csv':
    if "runs.csv" in file_list:
        print('LID-DS 2019 detected, initializing Dataloader')
        return DataLoader2019(scenario_path, direction)
    elif base_file_extension == '':
        try:
            normal_path = path.join(scenario_path, 'test', 'normal')
            adfa_path = path.join(scenario_path, 'Attack_Data_Master')
            if path.isdir(normal_path):
                example_file = listdir(normal_path)[0]
                _, sub_file_extension = path.splitext(example_file)
                if sub_file_extension == '.zip':
                    print('LID-DS 2021 detected, initializing Dataloader')
                    return DataLoader2021(scenario_path, direction)
                else:
                    raise_value_error()
            elif path.isdir(adfa_path):
                if kwargs:
                    return DataLoaderFixedADFALD(
                        scenario_path,
                        kwargs['attack'],
                        kwargs['val_count'],
                        kwargs['val_train_add'],
                        kwargs['test_normal_count'])
                else:
                    return DataLoaderFixedADFALD(scenario_path)
            else:
                zip_path = path.join(scenario_path, 'test')
                example_file = listdir(zip_path)[0]
                _, sub_file_extension = path.splitext(example_file)
                if sub_file_extension == '.zip' or sub_file_extension == '.scap':
                    print('Real world data detected, initializing Dataloader')
                    return DataLoaderRealWorld(scenario_path, direction)
                else:
                    raise_value_error()
        except Exception:
            raise_value_error()
    else:
        raise_value_error()


def raise_value_error():
    raise ValueError('invalid dataset structure, please use LID-DS 2019, LID-DS 2021  or real world dataset scenarios')
