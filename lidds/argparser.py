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


The argparse module provides a preconfigured argument parser named LIDArgparser.
Onto this argparser object the user can add more arguments to consider before parsing system arguments with it.
Also it provides utility functions for the correct usage of readable and writeable directories in custom arguments.
"""
# Global imports
import os
import sys
import argparse
import tempfile


class readable_dir(argparse.Action):
    """
    Checks if the path of a given directory is readable and stores the Path object
    """
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir=values
        if not os.path.isdir(prospective_dir):
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
        if os.access(prospective_dir, os.R_OK):
            setattr(namespace,self.dest,prospective_dir)
        else:
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


class writeable_dir(argparse.Action):
    """
    Checks if the path of a given directory is writeable and stores the Path object
    """
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir=values
        if not os.path.isdir(prospective_dir):
            raise argparse.ArgumentTypeError("writeable_dir:{0} is not a valid path".format(prospective_dir))
        if os.access(prospective_dir, os.W_OK):
            setattr(namespace,self.dest,prospective_dir)
        else:
            raise argparse.ArgumentTypeError("writeable_dir:{0} is not a writeable dir".format(prospective_dir))


"""
Default output directory is system-tmp directory
"""
defaultOutputDir = tempfile.gettempdir()


class LIDArgparser():
    """
    A singleton which represents a argparse-parser with default arguments that are essential to the simulation workflow.
    """
    class __LIDArgparser(argparse.ArgumentParser):
        """
        SINGLETON-PATTERN
        the instance of the LIDArgparser is an __LIDArgparser
        """
        def __init__(self):
            """
            Initialize arguments that are parsed by argparse.
            required:
            --recording-time
            --warmup-time

            optional:
            --exploit
            --run-id
            --container-name
            --output-directory

            if exploit if present:
            --wait-time
            is required.

            """
            # basically a super() call
            argparse.ArgumentParser.__init__(self)
            self.add_argument('-rt', '--recording-time', dest='recording_time', action='store', type=int, required=True, help='The total time (in ms) of recording the simulation.')
            self.add_argument('-wt', '--warmup-time', dest='warmup_time', action='store', type=int, required=True, help='The total time (in ms) of waiting before any recording takes place.')

            self.add_argument('-ior', '--io-buffer', dest='io_buffer_length', action='store', type=int, default=80, required=False, help='The maximum byte count that gets recorded on IO-Buffers!')

            self.add_argument('--exploit', dest='execute_exploit', action='store_true', default=True, help='Execute the exploit during simulation.')
            self.add_argument('-t', '--wait-time', dest='wait_before_exploit', action='store', type=int, required='--exploit' in sys.argv, help='The total time (in ms) of waiting before the exploit is executed. (Only relevant when executeExploit flag is set!)')

            self.add_argument('-id', '--run-id', dest='run_id', action='store', type=str, required=False, help='Give your run an id - otherwise we generate one!')
            self.add_argument('-c', '--container-name', dest='container_name', action='store', type=str, required=False, help='The name of the created victim container!')
            self.add_argument('-o', '--output-directory', dest='output_directory', action=writeable_dir, required=False, default=defaultOutputDir, help='Path to !')

    instance = None

    def __init__(self):
        """
        SINGLETON-PATTERN
        Initialize the instance.
        If it was already defined - do nothing.
        """
        if not LIDArgparser.instance:
            LIDArgparser.instance = LIDArgparser.__LIDArgparser()

    def __getattr__(self, name):
        """
        SINGLETON-PATTERN
        pipe all get-attr-calls to the instance
        """
        return getattr(self.instance, name)
