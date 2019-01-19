"""
test the container run context manager functionality
"""
from time import sleep
from docker.errors import ImageNotFound
from lid_ds.core import container_run, record_container

def test_container_recording():
    """
    test if the container_run contextmanager creates
    the correct container
    """
    def wait_available_fake(container):
        print(container)
        #print(kwargs.get('container'))
        #import time
        #time.sleep(20)
        return True
    with container_run({
            'image_name': 'nginx',
            'port_mapping': {
                '80/tcp': 80
            }
        }, wait_available_fake) as container:
        with record_container(container) as recorder:
            sleep(40)
