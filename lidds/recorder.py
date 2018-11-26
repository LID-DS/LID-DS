
"""
The recorder module provides the recorder class that describes a way to record system calls from docker containers
"""

# Global imports
import pexpect
import signal

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
    self.child = pexpect.spawn('sysdig -w {outputPath} container.name={containername}'.format(containername=self.container.name, outputPath=self.outputHandler.getScapPath()))


  def stop_recording(self):
    while self.child.isalive():
      self.child.sendcontrol('c')
    #terminated = self.child.kill(signal.SIGINT)
    print('terminated!')
