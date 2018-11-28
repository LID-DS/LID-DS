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


The simulator module provides a Simulator which is used to manage the simulation workflow.
It assures that the timing of the steps done in the simulation is correct and provides ways
for users to define their own simulation by registering initial-, normalBehaviour- and exploit hooks.
It also manages the recording of the victim container.
"""
# Future imports
from __future__ import print_function

# Global imports
import time
import sys
import os

# Relative imports

from .output_handler import OutputHandler
from promise import Promise
from threading import Timer
from .container_manager import startContainer, stopContainer
from .recorder import Recorder


class Simulator:
    """
    The simulator object is used to control chronologically order of actions done in the simulation.
    """

    def __init__(self, config):
        """
        Save a copy of the config parameter because call-by-reference is a bitch.
        """
        self.runtimeConfig = config.copy()
        self.outputHandler = OutputHandler(self.runtimeConfig)
        print('saving output to' + self.outputHandler.directoryPath)

    def registerInitHook(self, initHook):
        """
        register the initial-hook to execute later
        """
        self.initHook = initHook

    def registerTerminateHook(self, terminateHook):
        """
        register the initial-hook to execute later
        """
        self.terminateHook = terminateHook

    def registerNormalBehaviour(self, normalBehavior):
        """
        register the normal-behaviour-hook to execute later
        """
        self.normalBehaviourHook = normalBehavior

    def registerExploit(self, exploit):
        """
        register the exploit-hook to execute later
        """
        self.exploitHook = exploit

    def startSimulation(self):
        """
        1. create Containers
        2. initialize-hook
        3. start normal behaviour
        4. in <warmup-time> milliseconds do start recording
        5. if exploit: in <warmup-time + wait-before-exploit> milliseconds do start exploit
        6. in <warmup_time + recording_time> milliseconds stop recording
        7. in <warmup_time + recording_time> milliseconds kill process
        """
        self.__startVirtualization().then(
            lambda container:
            self.__executeInitHook().then(
                lambda res:
                self.__startNormalBehaviour().then(
                    lambda res:
                    self.__startTimers()
                ).catch(
                    lambda reas:
                    print(reas)
                )
            ).catch(
                lambda reas:
                print(reas)
            )
        ).catch(
            lambda reas:
            print(reas)
        )

    def __startTimers(self):
        """
        Starts the recording, and exploit timers
        """
        startRecordingTimer = Timer(self.runtimeConfig["warmup_time"] / 1000, self.__startRecording)
        startRecordingTimer.start()

        if self.runtimeConfig["execute_exploit"] and self.runtimeConfig["wait_before_exploit"]:
            exploitTimer = Timer((self.runtimeConfig["warmup_time"] + self.runtimeConfig["wait_before_exploit"]) / 1000,
                                 self.__startExploit)
            exploitTimer.start()

    def __executeInitHook(self):
        """
        Execute init hook and inject resolve and reject parameters
        """
        return Promise(
            lambda resolve, reject:
            self.initHook(self.container, resolve, reject)
        )

    def __executeTerminateHook(self):
        """
        Execute terminate hook and inject resolve and reject parameters
        """
        return Promise(
            lambda resolve, reject:
            self.terminateHook(resolve, reject)
        )

    def __startNormalBehaviour(self):
        """
        Execute normal behaviour hook
        """
        return Promise(
            lambda resolve, reject:
            resolve(self.normalBehaviourHook(self.container))
        )

    def __startVirtualization(self):
        """
        Start the victim container and save it as field
        """
        return Promise(
            lambda resolve, reject:
            startContainer(self.runtimeConfig['imagename'], self.runtimeConfig['portMapping']).then(
                lambda container:
                self.__setAndResolveContainer(container, resolve)
            ).catch(
                lambda reas:
                reject(reas)
            )
        )

    def __startRecording(self):
        """
        Start recording syscalls on victim
        """
        stopRecordingTimer = Timer(int(self.runtimeConfig["recording_time"]) / 1000, self.__stopRecording)
        stopRecordingTimer.start()
        # TODO: sysdig start live recording
        print('started recording' + str(time.time()))
        self.recorder.start_recording()

    def __stopRecording(self):
        """
        Stop recording syscalls on victim
        write logs and config
        execute terminate hook
        kill process
        """
        print('stopped recording' + str(time.time()))
        # TODO: sysdig stop live recording
        self.recorder.stop_recording()
        self.outputHandler.writeConfig()
        stopContainer(self.container).then(
            lambda res:
            self.__executeTerminateHook().then(
                lambda res:
                # sys.exit()
                # quit()
                os._exit(os.EX_OK)
            ).catch(
                lambda reas:
                # sys.exit()
                os._exit(os.EX_OSERR)
            )
        ).catch(
            lambda reas:
            reject(reas)
        )

    def __startExploit(self):
        """
        Execute exploit hook
        """
        print('started exploiting' + str(time.time()))
        if (self.exploitHook):
            self.exploitHook(self.container)

    def __setAndResolveContainer(self, container, resolve):
        """
        save container as field
        and resolve the container
        """
        self.container = container
        self.recorder = Recorder(self.container, self.outputHandler)
        resolve(container)
