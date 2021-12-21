from algorithms.building_block_id_manager import BuildingBlockIDManager
from dataloader.syscall import Syscall


class BuildingBlock:
    """
    base class for a features and other algorithms
    """

    def __init__(self):
        self._instance_id = None
        self.custom_fields = {}

    def train_on(self, syscall: Syscall, dependencies: dict):
        """
        takes one system call instance and the given features to train this extraction
        """        

    def val_on(self, syscall: Syscall, dependencies: dict):
        """
        takes one feature instance to validate on
        """

    def fit(self):
        """
        finalizes training
        """

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
        calculates building block on the given syscall and other already calculated building blocks given in dependencies
        writes its result into the given dependencies dict with key = get_id()
        """
        raise NotImplementedError("each building block has to implement calculate")

    def new_recording(self):
        """
        empties buffer and prepares for next recording
        """

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this building block
        """
        raise NotImplementedError("each building block has to implement depends_on to indicate its dependencies")

    def __str__(self) -> str:
        """
        gives a more or less human readable str representation of this object
        returns: "Name_of_class(memory_address)"
        """
        return f"{self.__class__.__name__}({hex(id(self))})"

    def __repr__(self):
        """
        same for __repr__
        """
        return self.__str__()

    def get_id(self):
        """
        returns the id of this feature instance - used to differ between different building blocks
        """
        if self._instance_id is None:
            self._instance_id = BuildingBlockIDManager().get_id(self)
        return self._instance_id
