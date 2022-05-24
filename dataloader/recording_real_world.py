import os

from zipfile import ZipFile

from dataloader.direction import Direction
from dataloader.syscall_2021 import Syscall2021
from dataloader.base_recording import BaseRecording


class RecordingRealWorld(BaseRecording):
    """
        Single recording captured in 1 way
        class provides functions to handle every type of recording
            --> syscall text file
        Args:
        path (str): path of recording
        name (str): name of file without extension
    """

    def __init__(self, name: str, path: str, direction: Direction):
        """
            Save name and path of recording.
            Parameter:
            path (str): path of associated sc files
            name (str): name without path and extension
        """
        self.name = name
        self.path = path
        self._direction = direction
        self.check_recording()

    def syscalls(self) -> str:
        """
            Prepare stream of syscalls,
            yield single lines
            Returns:
            str: syscall text line
        """
        try:
            with ZipFile(self.path, 'r') as zipped:
                with zipped.open(self.name + '.sc') as unzipped:
                    for line_id, syscall in enumerate(unzipped, start=1):
                        syscall = syscall.decode('UTF-8')
                        syscall_object = Syscall2021(self.path,
                                                     syscall.rstrip(),
                                                     line_id=line_id)
                        if self._direction != Direction.BOTH:
                            if syscall_object.direction() == self._direction:
                                yield syscall_object
                        else:
                            yield syscall_object
        except Exception:
            raise Exception(
                f'Error while working with file: {self.name} at {self.path}')

    def metadata(self) -> dict:
        """
            Calculate recording time with delta between first and last syscall
            Returns:
            dict: metadata dictionary
        """
        with open(self.path, 'r') as f:
            first_line = f.readline()
            for line in f:
                pass
            last_line = line

        print('done')
        start_time = str(first_line).split(' ')[0]
        end_time = str(last_line).split(' ')[0]
        recording_time = int(end_time) - int(start_time)
        print(recording_time)
        if 'malicious' in self.name:
            return {"exploit": True,
                    "time": {
                        "exploit": [
                            {
                                "absolute": 0.0
                            }
                        ]
                    }}
        else:
            return {"exploit": False}

    def check_recording(self) -> bool:
        """
            only 2021
            check if all necessary files are present
        """
        if not os.path.isfile(self.path):
            raise FileNotFoundError(
                f'Missing .sc file for recording: {self.path}')
