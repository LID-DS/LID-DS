import sys
sys.path.append('../lidds')
from lidds.scheduler import scheduler_sync
"""
this tests runs endlessly
"""


def function_to_call(arg):
    return

scheduler_sync(function_to_call)