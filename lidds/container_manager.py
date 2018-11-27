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
The container_manager module provides functions to starting and stopping victim containers.
"""
# Global imports
import docker

# Relative imports
from promise import Promise

def startContainer(imagename, portMapping):
  return Promise(
    lambda resolve, reject:
      __startContainer(resolve, reject, imagename, portMapping)
  )

def stopContainer(container):
  return Promise(
    lambda resolve, reject:
      __stopContainer(resolve, reject, container)
  )

def __startContainer(resolve, reject, imagename, portMapping):
  try:
    client = docker.from_env()
    resolve(client.containers.run(imagename, detach=True, stdin_open=True, tty=True, ports=portMapping))
  except Exception as error:
    reject(error)


def __stopContainer(resolve, reject, container):
  try:
    container.remove(force=True)
    resolve(0)
  except Exception as error:
    reject(error)