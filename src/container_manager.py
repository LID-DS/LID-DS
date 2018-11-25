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