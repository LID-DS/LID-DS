from dataloader.syscall import Syscall
from typing import Generator

class BaseRecording:
    """
        Base class for a single recordings
    """

    def __init__(self):
        pass

    def syscalls(self) -> Generator[Syscall, None, None]:
        """
            yields single lines of syscalls
        """
        raise NotImplementedError()

    def packets(self):
        """
            only for 2021
            should return pypcap Extractor object
            see: https://pypcapkit.jarryshaw.me/en/latest/foundation/extraction.html#pcapkit.foundation.extraction.Extractor
        """
        raise NotImplementedError()

    def resource_stats(self) -> list:
        """
            only for 2021
            Read .res file of recording.
            Returns:
            List of used resources

        """
        raise NotImplementedError()

    def metadata(self) -> dict:
        """
            Returns:
            dict: metadata dictionary
        """
        raise NotImplementedError()

    def check_recording(self) -> bool:
        """
            only 2021
            check if all necessary files are present
        """
        raise NotImplementedError()
