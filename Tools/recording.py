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

    """

    def __init__(self, path: str, name: str):
        self.path = path
        self.name = name
        pass

    def syscalls(self):
        """

            Prepare stream of syscalls
            Parse line in sc file
            yield parsed line

            :return parsed_syscall

        """
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.sc') as unzipped:
                for syscall in unzipped:
                    yield syscall.decode('utf-8').rstrip()

    def packets(self):
        with zipfile.ZipFile(self.path, 'r') as zipped:
            for zip_archive in zipped.namelist():
                try:
                    capture = pcapkit.extract(fin=zip_archive)
                    print(capture)
                except Exception:
                    print('no pcap')
            # with zipped.open(self.name + '.pcap') as unzipped:
            # extracted = pcapkit.extract(fin=unzipped.name)
        pass

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

            :return list of used resources

        """
        statistics = []
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.res') as unzipped:
                string = unzipped.read().decode('utf-8')
                reader = csv.reader(string.split('\n'), delimiter=',')
                # remove header
                next(reader)
                for row in reader:
                    statistics.append(row)
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

            :return dict of metadata
        """
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.json') as unzipped:
                unzipped_byte_json = unzipped.read()
                unzipped_json = json.loads(unzipped_byte_json.decode('utf-8').replace("'", '"'))
        return unzipped_json
