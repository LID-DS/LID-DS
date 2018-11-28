from lidds import scheduler

"""
this tests runs endlessly
"""


def function_to_call(arg):
    print(arg)

scheduler(function_to_call)