import subprocess
import shlex
from typing import Generator, Optional

from dataloader.base_recording import BaseRecording
from dataloader.direction import Direction
from dataloader.syscall import Syscall
from dataloader.syscall_scap import SyscallSCAP


class RecordingSCAP(BaseRecording):
    """
    Repräsentiert eine Aufzeichnung einer SCAP-Datei.

    Parameter:
        name (str): Der Name der Aufzeichnung.
        path (str): Der Pfad zur SCAP-Datei.
        direction (Direction, optional): Filter auf die Richtung der Syscalls. Standard ist Direction.BOTH.
    """

    def __init__(self, name: str, path: str, direction: Direction = Direction.BOTH):
        super().__init__()
        self.name = name
        self.path = path
        self._direction = direction

    def syscalls(self) -> Generator[SyscallSCAP, None, None]:
        """
        Generator, der SyscallSCAP-Objekte aus der SCAP-Datei liest und einzeln zurückgibt.

        Yields:
            SyscallSCAP: Ein Systemaufruf-Objekt.
        """
        # Befehl vorbereiten
        cmd = f"sysdig -r {shlex.quote(self.path)}"
        
        try:
            # Subprozess starten, um den sysdig-Befehl auszuführen
            with subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Direkt als Text lesen
                bufsize=1,  # Line-buffered
                universal_newlines=True
            ) as process:
                # Über die Standardausgabe des Prozesses iterieren
                for line in process.stdout:
                    line = line.strip()
                    if not line:
                        continue  # Leere Zeilen überspringen

                    # Erstellen eines SyscallSCAP-Objekts
                    syscall = SyscallSCAP(recording_path=self.path, syscall_line=line)

                    # Filter anwenden, falls eine spezifische Richtung gefordert ist
                    if self._direction == Direction.BOTH:
                        yield syscall
                    elif self._direction == Direction.OPEN and syscall.direction() == Direction.OPEN:
                        yield syscall
                    elif self._direction == Direction.CLOSE and syscall.direction() == Direction.CLOSE:
                        yield syscall

                # Warten, bis der Subprozess beendet ist
                process.wait()

                # Überprüfen, ob der Subprozess erfolgreich war
                if process.returncode != 0:
                    stderr = process.stderr.read()
                    raise RuntimeError(f"sysdig-Befehl fehlgeschlagen mit Rückgabecode {process.returncode}: {stderr}")

        except FileNotFoundError:
            raise RuntimeError("Der sysdig-Befehl wurde nicht gefunden. Stellen Sie sicher, dass sysdig installiert ist.")
        except Exception as e:
            raise RuntimeError(f"Ein Fehler ist beim Lesen der SCAP-Datei aufgetreten: {e}")
