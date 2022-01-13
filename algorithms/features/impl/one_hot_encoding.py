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
        self._input_bb = input
        self._dependency_list = [input]        

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
            takes one input and assigns integer
            integer is current length of forward_dict
            keep 0 free for unknown input
        """
        input = self._input_bb.get_result(syscall)
        if input is not None:
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

    def _calculate(self, syscall: Syscall):
        """
            transforms given input to an OHE tuple
            if input is not present: dont write a result
        """
        input = self._input_bb.get_result(syscall)
        if input is not None:
            try:
                input_to_int = self._input_to_int_dict[input]
            except KeyError:
                input_to_int = 0
            return self._int_to_ohe_dict[input_to_int]
        else:
            return None
    
    def get_embedding_size(self):
        return len(self._input_to_int_dict)
