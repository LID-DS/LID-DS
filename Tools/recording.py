import os
import csv
import json
import pcapkit
import zipfile


class Recording:
    """

        Single recording captured in 4 ways
        class provides functions to handle every type of recording
            --> syscall text file
            --> pcap packets
            --> json describing recording
            --> statistics of resources

        Args:
        path (str): path of recording
        name (str): name of file without extension

    """

    def __init__(self, path: str, name: str):
        """

            Save name and path of recording.

            Parameter:
            path (str): path of associated files
            name (str): name without path and extension

        """
        self.path = path
        self.name = name
        pass

    def syscalls(self) -> str:
        """

            Prepare stream of syscalls,
            yield single lines

            Returns:
            str: syscall text line

        """
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.sc') as unzipped:
                for syscall in unzipped:
                    yield Syscall(syscall.decode('utf-8').rstrip())

    def packets(self):
        """

            Unzip and extract pcap objects,

            Returns:
            pcap obj: return pypcap Extractor object
            src:
                https://pypcapkit.jarryshaw.me/en/latest/foundation/extraction.html#pcapkit.foundation.extraction.Extractor

        """
        try:
            with zipfile.ZipFile(self.path, 'r') as zipped:
                file_list = zipped.namelist()
                for file in file_list:
                    if file.endswith('.pcap'):
                        zipped.extract(file, 'tmp')
            obj = pcapkit.extract(fin=f'tmp/{self.name}.pcap',
                                  engine='scapy',
                                  store=True,
                                  nofile=True,
                                  tcp=True,
                                  strict=True)
        except Exception:
            print(f'Error extracting pcap file {self.name}')
            return None
        finally:
            os.remove(f'tmp/{self.name}.pcap')

        return obj

    def resource_stats(self) -> list:
        """

            Read .res file of recording.
            Includes usage of following resources for a point in time:
                timestamp,
                cpu_usage,
                memory_usage,
                network_received,
                network_send,
                storage_read,
                storage_written

            Returns:
            List of used resources

        """
        statistics = []
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.res') as unzipped:
                string = unzipped.read().decode('utf-8')
                reader = csv.reader(string.split('\n'), delimiter=',')
                # remove header
                next(reader)
                for row in reader:
                    if len(row) > 0:
                        statistics.append(ResourceStatistic(row))
        return statistics

    def metadata(self) -> dict:
        """

            Read json file and extract metadata as dict
            with following format:
            {"container": [
                    "ip": str,
                    "name": str,
                    "role": str
             "exploit": bool,
             "exploit_name": str,
             "image": str,
             "recording_time": int,
             "time":{
                    "container_ready": {
                        "absolute": float,
                        "relative": float,
                        "source": str
                    },
                    "exploit": [
                        {
                            "absolute": float,
                            "name": str,
                            "relative": float,
                            "source": str
                        }
                    ]
                    "warmup_end": {
                        "absolute": float,
                        "relative": float,
                        "source": str
                    }
                }
            }

            Returns:
            dict: metadata dictionary

        """
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.json') as unzipped:
                unzipped_byte_json = unzipped.read()
                unzipped_json = json.loads(unzipped_byte_json.decode('utf-8').replace("'", '"'))
        return unzipped_json
