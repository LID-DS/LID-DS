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
"""
"""
The recorder module provides the recorder class that describes a way to record system calls from docker containers
"""

# Global imports
import pexpect
import signal
from .argparser import LIDArgparser

class Recorder:
  '''
  The recorder handles starting and stopping of recording system calls via sysdig
  '''
  def __init__(self, container, outputHandler):
    self.container = container
    self.outputHandler = outputHandler

  def start_recording(self):
    print('recording:' + self.container.name)
    print('executing: sysdig -w {outputPath} container.name={containername}'.format(containername=self.container.name, outputPath=self.outputHandler.getScapPath()))
    args = LIDArgparser().parse_args() 
    io_buffer_length = args.io_buffer_length
    self.child = pexpect.spawn('sysdig -w {outputPath} -s {ioBufferLength} container.name={containername}'.format(containername=self.container.name, outputPath=self.outputHandler.getScapPath(), ioBufferLength=io_buffer_length))


  def stop_recording(self):
    while self.child.isalive():
      self.child.sendcontrol('c')
    #terminated = self.child.kill(signal.SIGINT)
    print('terminated!')
