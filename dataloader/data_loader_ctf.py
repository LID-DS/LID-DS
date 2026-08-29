import errno
import os
from dataloader.base_data_loader import BaseDataLoader
from dataloader.direction import Direction
from dataloader.recording_ctf import RecordingCTF

class DataLoaderCTF(BaseDataLoader):
    """

        Receives path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self, scenario_path, direction: Direction = Direction.BOTH):
        """

            Save path of scenario and create metadata_list.

            Parameter:
            scenario_path (str): path of associated folder
            direction (str): filter on syscall direction

        """
        super().__init__(scenario_path)
        if os.path.isdir(scenario_path):
            self.scenario_path = scenario_path
            self._direction = direction
        else:
            print(f'Could not find {scenario_path}!!!!')
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENONET),
                scenario_path
            )

    def data(self) -> list:
        """

            Create list of recordings contained in training data.

            Returns:
            list: list of recordings

        """
        recordings = self.extract_recordings()
        return recordings

    def extract_recordings(self) -> list:
        """

            Go through list of all files.
            Instantiate new Recording object and append to recordings list.
            If all files have been seen return list of Recordings.

            Returns:
            list: list of data recordings


        """
        recordings = []
        file_list = None
        for file in file_list:
            recordings.append(RecordingCTF(name=file,path=path,direction=self._direction))
        return recordings