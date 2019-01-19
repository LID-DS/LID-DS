"""
test the container run context manager functionality
"""
from docker.errors import ImageNotFound
from lid_ds.core import container_run

def test_container_run_context_manager():
    """
    test if the container_run contextmanager creates
    the correct container
    """
    with container_run({
            'image_name': 'hello-world',
            'port_mapping': {
                '9200/tcp': 9200
            }
        }) as container:
        pass

def test_container_run_context_manager():
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
            'image_name': 'hello-world',
            'port_mapping': {
                '9200/tcp': 9200
            }
        }, wait_available_fake) as container:
        pass

def test_container_run_context_manager_exception():
    """
    test if exceptions during the container runtime are catchable
    """
    try:
        with container_run({
                'image_name': 'thisisnotavalidimage13',
                'port_mapping': {
                    '9200/tcp': 9200
                }
            }) as container:
            pass
    except ImageNotFound as notFoundE:
        pass
    except HTTPError as httpE:
        pass
