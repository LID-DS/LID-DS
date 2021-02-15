from abc import ABC

from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.core.image import ChainImage


class ScenarioContainerBase(ABC):
    def __init__(self, image: ChainImage):
        self.queue = ScenarioEnvironment().logging_queue
        self.network = ScenarioEnvironment().network
        self.image = image

    @property
    def to_stdin(self):
        return any(map(lambda x: x.stdin, self.image.commands))
