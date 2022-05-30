from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

if __name__ == '__main__':
    """
    this is a script to gather recording information
    """
    ngram_length = 5
    embedding_size = 4
    thread_aware = True
    window_length = 100

    # path = '/media/tk/SSD/ganzmann_data/'
    path='../Data/real_world'
    # data loader for scenario
    dataloader = dataloader_factory(path, direction=Direction.CLOSE)

    train_data = dataloader.training_data()
    val_data = dataloader.training_data()
    test_data = dataloader.training_data()

    for data in val_data:
        print(data.metadata())
