"""
container run aims to provide a context manager for sanely
starting and stopping of containers
"""
from contextlib import contextmanager
from docker import from_env
from lid_ds.helpers import wait_until


@contextmanager
def container_run(config, check_if_available=lambda container: True, init_normal=None):
    """
    A contextmanager for container ressource management
    handles starting, stopping and removing of containers
    """
    try:
        docker_client = from_env()
        if ('image_name' in config and
                isinstance(config['image_name'], str) and
                'port_mapping' in config and
                isinstance(config['port_mapping'], dict)):
            container = docker_client.containers.run(
                config['image_name'],
                name="victim",
                network=config['network'],
                detach=True,
                stdin_open=True,
                tty=True,
                remove=True,
                ports=config['port_mapping']
            )
            wait_until(check_if_available, 60, 1, container=container)
            if init_normal is not None:
                init_normal()
        yield container
    finally:
        try:
            container.remove(force=True)
            print("Victim container removed")
        except:
            pass
