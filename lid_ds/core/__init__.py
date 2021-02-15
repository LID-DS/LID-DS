"""
the core module provides all functionality used to create,
run and record security scenarios
"""
try:
    from .scenario import Scenario
    from .image import ChainImage, Command, StdinCommand, ExecCommand, Image, TCPPacketMatcher
except Exception as e:
    print(e)
    raise ImportError("Not all dependencies could be imported.")
