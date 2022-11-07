from dataloader.direction import Direction


class BaseDataLoader:
    """

        Recieves path of scenario.

        Args:
        scenario_path (str): path of scenario folder

        Attributes:
        scenario_path (str): stored Arg
        metadata_list (list): list of metadata for each recording

    """

    def __init__(self, scenario_path: str):
        """

            Save path of scenario and create metadata_list.

            Parameter:
            scenario_path (str): path of assosiated folder

        """
        self.scenario_path = scenario_path
        print(f"loading {scenario_path}")
        
    def training_data(self) -> list:
        """

            Create list of recordings contained in training data.
            Specify recordings with recording_type.

            Returns:
            list: list of training data recordings

        """
        pass

    def validation_data(self) -> list:
        """

            Create list of recordings contained in validation data.
            Specify recordings with recording_type.

            Returns:
            list: list of validation data recordings

        """
        pass

    def test_data(self) -> list:
        """

            Create list of recordings contained in test data.
            Specify recordings with recording_type.

            Returns:
            list: list of test data recordings

        """
        pass

    def extract_recordings(self, category: str) -> list:
        """

            Go through list of all files in specified category.
            Instanciate new Recording object and append to recordings list.
            If all files have been seen return list of Recordings.

            Parameter:
            category (str): filter for category (training, validation, test)

            Returns:
            list: list of data recordings for specified category


        """
        pass

    def collect_metadata(self) -> dict:
        """

            Create dictionary which contains following information about recording:
                first key: Category of recording : training, validataion, test
                second key: Name of recording
                value : {recording type: str, path: str}

            Returns:
            dict: metadata_dict containing type of recording for every recorded file

        """
        pass

    def get_direction_string(self):
        """
            parses Direction of system calls to string if attribute is present
        @return: direction string
        """
        if hasattr(self, '_direction'):
            return str(self._direction).split('.')[1].lower()
        else:
            return "None"
