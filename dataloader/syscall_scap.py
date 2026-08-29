import base64
import re
from datetime import datetime
from enum import IntEnum
from typing import Tuple, Union

from dataloader.direction import Direction
from dataloader.syscall import Syscall

class SyscallSplitPart(IntEnum):
    EVT_NUM = 0
    EVT_TIME = 1
    EVT_CPU = 2
    PROC_NAME = 3
    THREAD_TID = 4
    DIRECTION = 5
    SYSCALL_NAME = 6
    PARAMS_BEGIN = 7  # Ab Index 7 beginnen die Parameter

class Param(IntEnum):
    NAME = 0
    VALUE = 1

class SyscallSCAP(Syscall):
    """
    Repräsentiert einen Systemaufruf als Objekt, erstellt aus einer Zeilenzeichenkette aus einer SCAP-Aufzeichnung.
    """

    def __init__(self, recording_path: str, syscall_line: str, recording_date: str = None):
        """
        :param recording_path: Pfad zur Aufzeichnung
        :param syscall_line: Die Zeile der Systemaufruf-Aufzeichnung
        :param recording_date: Optionales Datum im Format 'DD/Mon/YYYY', um den Zeitstempel zu vervollständigen
        """
        self.syscall_line = syscall_line
        self._line_list = syscall_line.split(' ')
        self._evt_num = None
        self._timestamp_datetime = None
        self._cpu = None
        self._proc_name = None
        self._thread_id = None
        self._name = None
        self._direction = None
        self._params = None
        self.recording_path = recording_path
        self.recording_date = recording_date  # Optional, falls das Datum benötigt wird

    def evt_num(self) -> int:
        if self._evt_num is None:
            self._evt_num = int(self._line_list[SyscallSplitPart.EVT_NUM])
        return self._evt_num

    def timestamp_datetime(self) -> datetime:
        """
        Parst den Zeitstempel und gibt ein datetime-Objekt zurück.
        Wenn ein Datum angegeben ist, wird es verwendet, ansonsten wird nur die Zeit verwendet.
        """
        if self._timestamp_datetime is None:
            time_str = self._line_list[SyscallSplitPart.EVT_TIME]
            if self.recording_date:
                datetime_str = f"{self.recording_date} {time_str}"
                self._timestamp_datetime = datetime.strptime(datetime_str, "%d/%b/%Y %H:%M:%S.%f")
            else:
                # Ohne Datum setzen wir ein Standarddatum oder nur die Zeit
                time_obj = datetime.strptime(time_str, "%H:%M:%S.%f")
                self._timestamp_datetime = time_obj
        return self._timestamp_datetime

    def cpu(self) -> int:
        if self._cpu is None:
            self._cpu = int(self._line_list[SyscallSplitPart.EVT_CPU])
        return self._cpu

    def process_name(self) -> str:
        if self._proc_name is None:
            self._proc_name = self._line_list[SyscallSplitPart.PROC_NAME]
        return self._proc_name

    def thread_id(self) -> int:
        """
        Extrahiert die Thread-ID aus dem String '(9239)'.
        """
        if self._thread_id is None:
            thread_str = self._line_list[SyscallSplitPart.THREAD_TID]
            match = re.match(r'\((\d+)\)', thread_str)  # Korrektur: Extra ")" entfernt
            if match:
                tid = int(match.group(1))  # Thread-ID als Integer extrahieren
                self._thread_id = tid
            else:
                self._thread_id = None
        return self._thread_id

    def name(self) -> str:
        if self._name is None:
            self._name = self._line_list[SyscallSplitPart.SYSCALL_NAME]
        return self._name

    def direction(self) -> Direction:
        """
        Bestimmt die Richtung basierend auf den Zeichen '<' und '>'.
        """
        if self._direction is None:
            dir_char = self._line_list[SyscallSplitPart.DIRECTION]
            if dir_char == '>':
                self._direction = Direction.OPEN
            elif dir_char == '<':
                self._direction = Direction.CLOSE
            else:
                self._direction = None
        return self._direction

    def params(self) -> dict:
        """
        Extrahiert Parameter aus der Parameterliste und speichert deren Namen und Werte als Dictionary.
        Verbessert das Parsing, um Werte mit Leerzeichen korrekt zu behandeln.
        """
        if self._params is None:
            self._params = {}
            if len(self._line_list) > SyscallSplitPart.PARAMS_BEGIN:
                params_str = ' '.join(self._line_list[SyscallSplitPart.PARAMS_BEGIN:])
                # Regex, um key=value Paare zu finden, wobei value auch Leerzeichen enthalten kann
                pattern = re.compile(r'(\w+)=("[^"]+"|[^" ]+)')
                for match in pattern.finditer(params_str):
                    key = match.group(1)
                    value = match.group(2).strip('"')  # Entfernt Anführungszeichen, falls vorhanden
                    self._params[key] = value
        return self._params

    def param(self, param_name: str, b64decode: bool = False) -> Union[str, bytes, None]:
        """
        Ruft den angeforderten Parameter ab und decodiert ihn bei Bedarf von Base64.

        :param param_name: Name des Parameters
        :param b64decode: Wenn True, wird der Wert von Base64 decodiert
        :return: Der Wert des Parameters als String oder Bytes, oder None, wenn nicht gefunden
        """
        params = self.params()
        try:
            param_value = params[param_name]
            if b64decode:
                return base64.b64decode(param_value)
            else:
                return param_value
        except KeyError:
            return None
