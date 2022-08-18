from base_data_loader import BaseDataLoader


class DataLoaderADFALD(BaseDataLoader):
    def __init__(self, scenario_path: str):
        super().__init__(scenario_path)
        self._normal_recordings = None
        self._exploit_recordings = None
        self._distinct_syscalls = None
        self._direction = direction

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