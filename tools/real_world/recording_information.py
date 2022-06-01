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
    path='/home/tk-whk/Documents/WHK/Data/real_world'
    # data loader for scenario
    dataloader = dataloader_factory(path, direction=Direction.CLOSE)

    train_data = dataloader.training_data()
    val_data = dataloader.validation_data()
    test_data = dataloader.test_data()
    
    val_time = 0
    for data in val_data:
        val_time += data.metadata()['recording_time']
    print(f'Validation recording_time: {(val_time/60)/60} h')
    training_time = 0
    for data in train_data:
        training_time += data.metadata()['recording_time']
    print(f'Training recording_time: {(training_time/60)/60} h')
    test_time = 0
    for data in test_data:
        test_time += data.metadata()['recording_time']
    print(f'Test recording_time: {(test_time/60)/60} h')
    full_recording_time = training_time + val_time + test_time
    print(f'Full recording time: {(full_recording_time/60)/60}')
