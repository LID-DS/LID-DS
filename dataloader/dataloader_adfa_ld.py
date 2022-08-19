from enum import Enum

from base_data_loader import BaseDataLoader

class Attacks(Enum):
    Adduser = 1
    Hydra_FTP = 2
    Hydra_SSH = 3
    Java_Meterpreter = 4
    Meterpreter = 5
    Web_Shell = 6


class DataLoaderADFALD(BaseDataLoader):
    def __init__(self, scenario_path: str, attack: Attacks, validation_count: int):
        super().__init__(scenario_path)
        self._normal_recordings = None
        self._exploit_recordings = None
        self._distinct_syscalls = None
        self._attack = attack
        self._validation_count = validation_count

        self.extract_recordings()

    def training_data(self) -> list:
        pass

    def validation_data(self) -> list:
        pass

    def test_data(self) -> list:
        pass

    def extract_recordings(self) -> list:
        pass

    def distinct_syscalls_training_data(self): -> int:
        pass