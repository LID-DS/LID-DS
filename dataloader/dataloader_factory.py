from os import listdir, path
from dataloader.base_data_loader import BaseDataLoader
from dataloader.data_loader_2019 import DataLoader2019
from dataloader.data_loader_2021 import DataLoader2021
from dataloader.direction import Direction


def dataloader_factory(scenario_path: str, direction: Direction = Direction.OPEN) -> BaseDataLoader:
    """
    creates DataLoader 2019 or 2021 by detecting the dataset specific file structure
    """
    file_list = listdir(scenario_path)
    file_list.sort()

    _, base_file_extension = path.splitext(file_list[0])
    # print(base_file_extension)

    """
    LID-DS 2019 Dataset has txt files or one csv file in root folder which lead to return of
    DataLoader 2019 Object
    
    LID-DS 2021 has three subdirs that lead to empty file extension
    if subdirs are detected the dataset subdir with normal test data is opened
    if it contains zip files a DataLoader 2021 Object is returned
    """
    # if base_file_extension == '.txt' or base_file_extension == '.csv':
    if "runs.csv" in file_list:
        print('LID-DS 2019 detected, initializing Dataloader')
        return DataLoader2019(scenario_path, direction)
    elif base_file_extension == '':
        try:
            normal_path = path.join(scenario_path, 'test', 'normal')
            example_file = listdir(normal_path)[0]
            _, sub_file_extension = path.splitext(example_file)
            if sub_file_extension == '.zip':
                print('LID-DS 2021 detected, initializing Dataloader')
                return DataLoader2021(scenario_path, direction)
            else:
                raise_value_error()
        except:
            raise_value_error()
    else:
        raise_value_error()


def raise_value_error():
    raise ValueError('invalid dataset structure, please use LID-DS 2019 or LID-DS 2021 dataset scenarios')
