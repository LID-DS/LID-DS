from enum import IntEnum
from datetime import datetime


class ParseResource(IntEnum):
    TIMESTAMP = 0
    CPU_USAGE = 1
    MEMORY_USAGE = 2
    NETWORK_RECEIVED = 3
    NETWORK_SEND = 4
    STORAGE_READ = 5
    STORAGE_WRITTEN = 6


class ResourceStatistic:

    """

        Class to organize resource statistics.
        Initialization with list of multiple resource entries for specific timestamps.

    """

    def __init__(self, line: list):
        self._raw_line = line
        self._timestamp = None
        self._cpu_usage = None
        self._memory_usage = None
        self._network_send = None
        self._storage_read = None
        self._storage_written = None
        self._network_received = None

    def timestamp_unix_in_s(self) -> float:
        """

            Convert timestamp string to float

            Returns:
                float: timestamp of resource usage in unix format (seconds since 1970)

        """
        if self._timestamp is None:
            self._timestamp = float(self._raw_line[ParseResource.TIMESTAMP])
        return self._timestamp

    def timestamp_datetime(self) -> datetime:
        """

            Convert timestamp string to datetime object

            Returns:
                datetime: timestamp in python datetime format

        """
        if self._timestamp is None:
            self._timestamp = datetime.fromtimestamp(float(self._raw_line[ParseResource.TIMESTAMP]))
        return self._timestamp

    def cpu_usage(self) -> float:
        """

            Convert cpu_usage string to float

            Returns:
                float: cpu_usage for specific timestamp

        """
        if self._cpu_usage is None:
            self._cpu_usage = float(self._raw_line[ParseResource.CPU_USAGE])
        return self._cpu_usage

    def memory_usage(self) -> int:
        """

            Convert memory_usage string to int

            Returns:
                int: memory_usage for specific timestamp

        """
        if self._memory_usage is None:
            self._memory_usage = int(self._raw_line[ParseResource.MEMORY_USAGE])
        return self._memory_usage

    def network_received(self) -> int:
        """

            Convert network_received string to int

            Returns:
                int: network_received for specific timestamp

        """
        if self._network_received is None:
            self._network_received = int(self._raw_line[ParseResource.NETWORK_RECEIVED])
        return self._network_received

    def network_send(self) -> int:
        """

            Convert network_send string to int

            Returns:
                int: network_send for specific timestamp

        """
        if self._network_send is None:
            self._network_send = int(self._raw_line[ParseResource.NETWORK_SEND])
        return self._network_send

    def storage_read(self) -> int:
        """

            Convert storage_read string to int

            Returns:
                int: storage_read for specific timestamp

        """
        raw_string = self._raw_line[ParseResource.STORAGE_READ]
        if self._storage_read is None:
            if raw_string != 'NULL':
                self._storage_read = int(self._raw_line[ParseResource.STORAGE_READ])
            else:
                self._storage_read = 0
        return self._storage_read

    def storage_written(self) -> int:
        """

            Convert storage_written string to int

            Returns:
                int: storage_written for specific timestamp

        """
        raw_string = self._raw_line[ParseResource.STORAGE_WRITTEN]
        if self._storage_written is None:
            if raw_string != 'NULL':
                self._storage_written = int(self._raw_line[ParseResource.STORAGE_WRITTEN])
            else:
                self._storage_written = 0
        return self._storage_written
