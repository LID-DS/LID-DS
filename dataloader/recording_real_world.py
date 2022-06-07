import os
import json

from zipfile import ZipFile, ZIP_DEFLATED
from datetime import datetime

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
            Calculate recording time with delta between first and last syscall in sc file.
            Persist file inside zip as json.
            Returns:
            dict: metadata dictionary
        """
        base_path = os.path.dirname(self.path)
        sc_path = base_path + '/' + os.path.basename(self.path)[:-3] + 'sc'
        json_path = base_path + '/' + os.path.basename(self.path)[:-3] + 'json'
        json_file_name = os.path.basename(self.path)[:-3] + 'json'
        json_exists = False
        with ZipFile(self.path, 'r') as zip_ref:
            # check if json file already exists 
            if json_file_name in zip_ref.namelist():
                json_exists = True
            if not json_exists:
                zip_ref.extractall(os.path.dirname(self.path))
            else:
                with zip_ref.open(json_file_name) as unzipped:
                    unzipped_byte_json = unzipped.read()
                    unzipped_json = json.loads(unzipped_byte_json.decode('utf-8').replace("'", '"'))
                return unzipped_json
        # get first and last line of sc file
        head = os.popen(f'head {sc_path}').read()
        tail = os.popen(f'tail {sc_path}').read()
        first_line = head.split('\n')[0]
        tail_split = tail.split('\n')
        last_line = tail_split[len(tail_split) - 2]  # -2 because of empty line at the end

        # calc time delta of first and last system call
        start_time = str(first_line).split(' ')[0]
        end_time = str(last_line).split(' ')[0]
        recording_time = (int(end_time) - int(start_time)) * 10 ** -9
        # convert timestamp to float
        if 'malicious' in self.name:
            result_dict = {
                "exploit": True,
                "recording_time": recording_time,
                "time": {
                    "exploit": [
                        {
                            "absolute": 0.0
                        }
                    ]
                }}
        else:
            result_dict= {
                "exploit": False,
                "recording_time": recording_time
            }
        # write metadata as json to zip 
        with open(json_path, 'w+') as file:
            json.dump(result_dict, file)
        with ZipFile(self.path, 'w', compresslevel=8, compression=ZIP_DEFLATED) as zip_ref:
            zip_ref.write(json_path,
                          os.path.basename(json_path))
            zip_ref.write(sc_path,
                          os.path.basename(sc_path))

        # delete sc file and json file
        os.remove(json_path)
        os.remove(sc_path)
        return result_dict

    def check_recording(self) -> bool:
        """
            only 2021
            check if all necessary files are present
        """
        if not os.path.isfile(self.path):
            raise FileNotFoundError(
                f'Missing .sc file for recording: {self.path}')
