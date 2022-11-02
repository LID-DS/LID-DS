from dataloader.base_data_loader import BaseDataLoader


class DataloaderCTF(BaseDataLoader):
    def __init__(self, scenario_path: str):
        super().__init__(scenario_path)
        self.scenario_path = scenario_path

    def training_data(self) -> list:
        pass

    def validation_data(self) -> list:
        pass

    def test_data(self) -> list:
        pass

    def extract_recordings(self, category: str) -> list:
        pass

