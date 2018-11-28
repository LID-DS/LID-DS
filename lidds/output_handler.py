"""
Leipzig Intrusion Detection Dataset (LID-DS) 
Copyright (C) 2018 Martin Grimmer, Martin Max Röhling, Dennis Kreußel and Simon Ganz

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


The output_handler module provides functions related to the writing of sysdig reports and config files.
The main task here is the correct path management.
"""
# Global imports
import os
import yaml
import uuid

# Relative imports
from .argparser import LIDArgparser


class OutputHandler:
    """
    The simulator object is used to control chronologically order of actions done in the simulation.
    """

    def __init__(self, config):
        """
        Save a copy of the config parameter because call-by-reference is a bitch.
        """
        self.simulatorConfig = config.copy()
        args = LIDArgparser().parse_args()
        if (args.run_id):
            self.id = args.run_id
        else:
            self.id = uuid.uuid4()
        self.directoryPath = os.path.join(args.output_directory, str(self.id))
        if not os.path.exists(self.directoryPath):
            os.makedirs(self.directoryPath)
        # TODO: Handle uuid collisions (like this is ever gonna happen)

        os.chmod(self.directoryPath, 0o755)

    def getScapPath(self):
        return os.path.join(self.directoryPath, '{id}.scap'.format(id=self.id))

    def writeConfig(self):
        with open(os.path.join(self.directoryPath, 'config.yml'), 'w') as outfile:
            yaml.dump(self.simulatorConfig, outfile, default_flow_style=False)
