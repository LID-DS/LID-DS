"""
The wait_until module provides a helper method to wait
for a predicate to become True.
"""
import time

#pylint: disable=W1113
def wait_until(somepredicate, timeout, period=1, *args, **kwargs):
    """
    Wait until the predicate becomes True.
    If timeout is reached while the predicate is False
    it returns False.
    If the predicate has become True
    it returns True.
    """
    mustend = time.time() + timeout
    while time.time() < mustend:
        if somepredicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False
