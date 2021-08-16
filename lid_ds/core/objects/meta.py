from typing import Union

from lid_ds.core.objects.environment import ScenarioEnvironment


class ScenarioMeta:
    def __init__(self, exploit_time: Union[int, float], warmup_time: Union[int, float],
                 recording_time: Union[int, float], exploit_name: str):
        if not isinstance(warmup_time, (int, float)):
            raise TypeError("Warmup time needs to be an integer or float")
        if not isinstance(recording_time, (int, float)):
            raise TypeError("Recording time needs to be an integer or float")
        if not isinstance(exploit_time, (int, float)):
            raise TypeError(
                "Exploit start time needs to be an integer or float")
        if exploit_time > recording_time != -1:
            raise ValueError(
                "The start time of the exploit must be before the end of the recording!"
            )
        self.name = ScenarioEnvironment().recording_name
        self.exploit_time = exploit_time
        self.is_exploit = exploit_time != 0
        self.warmup_time = warmup_time
        self.recording_time = recording_time
        self.exploit_name = exploit_name
