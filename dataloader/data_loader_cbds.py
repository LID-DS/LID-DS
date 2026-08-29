import errno
import os
from typing import Generator, List
from tqdm import tqdm

from dataloader.direction import Direction
from dataloader.recording_scap import RecordingSCAP
from dataloader.base_data_loader import BaseDataLoader


class DataLoaderCBDS(BaseDataLoader):
    """
    Lädt Daten aus einem Szenario-Ordner, der SCAP-Dateien enthält.

    Args:
        scenario_path (str): Pfad zum Szenario-Ordner.
        direction (Direction, optional): Filter für die Richtung der Syscalls. Standard ist Direction.BOTH.
    """

    def __init__(self, scenario_path: str, direction: Direction = Direction.BOTH):
        """
        Initialisiert die DataLoaderCBDS-Klasse.

        Args:
            scenario_path (str): Pfad zum Szenario-Ordner.
            direction (Direction, optional): Filter für die Richtung der Syscalls. Standard ist Direction.BOTH.

        Raises:
            FileNotFoundError: Wenn der angegebene Szenario-Pfad nicht existiert oder kein Verzeichnis ist.
        """
        super().__init__(scenario_path)
        if os.path.isdir(scenario_path):
            self.scenario_path = scenario_path
            self._direction = direction
        else:
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                scenario_path
            )

    def data(self) -> List[RecordingSCAP]:
        """
        Gibt die Liste der RecordingSCAP-Objekte zurück.

        Returns:
            List[RecordingSCAP]: Liste der aufgezeichneten SCAP-Dateien.
        """
        return self.extract_recordings()

    def training_data(self) -> List[RecordingSCAP]:
        """
        Gibt die Trainingsdaten zurück.

        Returns:
            List[RecordingSCAP]: Liste der Trainingsaufzeichnungen.
        """
        # Hier können spezifische Logiken zur Aufteilung der Daten implementiert werden
        return self.extract_recordings()

    def validation_data(self) -> List[RecordingSCAP]:
        """
        Gibt die Validierungsdaten zurück.

        Returns:
            List[RecordingSCAP]: Liste der Validierungsaufzeichnungen.
        """
        # Hier können spezifische Logiken zur Aufteilung der Daten implementiert werden
        return self.extract_recordings()

    def test_data(self) -> List[RecordingSCAP]:
        """
        Gibt die Testdaten zurück.

        Returns:
            List[RecordingSCAP]: Liste der Testaufzeichnungen.
        """
        # Hier können spezifische Logiken zur Aufteilung der Daten implementiert werden
        return self.extract_recordings()

    def extract_recordings(self) -> List[RecordingSCAP]:
        """
        Extrahiert alle SCAP-Dateien im Szenario-Ordner und erstellt RecordingSCAP-Objekte.

        Returns:
            List[RecordingSCAP]: Liste der aufgezeichneten SCAP-Dateien.
        """
        recordings = []
        # Liste aller Dateien im Szenario-Ordner
        try:
            file_list = os.listdir(self.scenario_path)
        except Exception as e:
            raise RuntimeError(f"Fehler beim Auflisten des Szenario-Ordners: {e}")

        # Filter für SCAP-Dateien (angenommen, sie enden mit .scap)
        scap_files = [f for f in file_list if f.lower().endswith('.scap')]

        if not scap_files:
            print(f"Keine SCAP-Dateien im Ordner {self.scenario_path} gefunden.")
            return recordings

        # Fortschrittsanzeige mit tqdm
        for file in tqdm(scap_files, desc="Lade SCAP-Dateien", unit="datei"):
            file_path = os.path.join(self.scenario_path, file)
            try:
                recording = RecordingSCAP(
                    name=os.path.splitext(file)[0],
                    path=file_path,
                    direction=self._direction
                )
                recordings.append(recording)
            except Exception as e:
                print(f"Fehler beim Laden der Datei {file_path}: {e}")

        return recordings
