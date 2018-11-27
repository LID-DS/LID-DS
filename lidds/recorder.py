
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
