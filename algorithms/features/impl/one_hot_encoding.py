from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall


class OneHotEncoding(BuildingBlock):
    """
        convert input to One Hot Encoding tuple
    """

    def __init__(self, input: BuildingBlock):
        super().__init__()
        self._input_to_int_dict = {}
        self._int_to_ohe_dict = {}
        self._input_id = input.get_id()
        self._dependency_list = [input]        

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall, dependencies: dict):
        """
            takes one input and assigns integer
            integer is current length of forward_dict
            keep 0 free for unknown input
        """
        if self._input_id in dependencies:
            input = dependencies[self._input_id]
            if input not in self._input_to_int_dict:
                self._input_to_int_dict[input] = len(self._input_to_int_dict) + 1

    def fit(self):
        """
        calculates the ohe for each seen input in training
        """
        length = len(self._input_to_int_dict)
        ohe_array = [0] * length
        self._int_to_ohe_dict[0] = tuple(ohe_array) # for unknown inputs
        for i in range(1, length + 1):
            ohe_array = [0] * length
            ohe_array[i-1] = 1
            self._int_to_ohe_dict[i] = tuple(ohe_array)
        print(f"OHE.size = {self.get_embedding_size()}".rjust(27))
        #print(self._int_to_ohe_dict)

    def calculate(self, syscall: Syscall, dependencies: dict):
        """
            transforms given input to an OHE tuple
            if input is not present: dont write a result
        """
        if self._input_id in dependencies:
            try:
                input = dependencies[self._input_id]
                input_to_int = self._input_to_int_dict[input]
            except KeyError:
                input_to_int = 0
            #print(f"ohe:{input_to_int}")
            dependencies[self.get_id()] = self._int_to_ohe_dict[input_to_int]
    
    def get_embedding_size(self):
        return len(self._input_to_int_dict)
