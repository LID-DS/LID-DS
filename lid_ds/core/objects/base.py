from abc import ABC

from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.core.image import StdinCommand, Image


class ScenarioContainerBase(ABC):
    def __init__(self, image: Image):
        self.queue = ScenarioEnvironment().logging_queue
        self.network = ScenarioEnvironment().network
        self.image = image

    @property
    def to_stdin(self):
        return isinstance(self.image.command, StdinCommand)