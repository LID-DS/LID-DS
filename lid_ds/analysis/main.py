"""LID-DS system call trace analysis tool

Usage:
  lid_ds_analysis scap <input_file>
  lid_ds_analysis (-h | --help)
  lid_ds_analysis --version

Options:
  -h --help     Show this screen.
  --version     Show version.

"""
import os
from docopt import docopt
from lid_ds.analysis.parse_scap import parse_scap
from lid_ds.vis.syscall_vis import duration_vis

def main():
    arguments = docopt(__doc__, version='0.2.2')
    if arguments['scap']:
        if os.path.isfile(arguments['<input_file>']) and arguments['<input_file>'].endswith('.scap'):
            syscalls = parse_scap(arguments['<input_file>'])
            duration_vis(syscalls)
            print(arguments)
