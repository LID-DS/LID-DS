from algorithms.building_block_id_manager import BuildingBlockIDManager
from dataloader.syscall import Syscall
from collections.abc import Iterable


class BuildingBlock:
    """
    base class for a features and other algorithms
    """

    def __init__(self):
        self._config = BuildingBlock.arguments()
        #print(self._config)
        self._instance_id = None        

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
        result = ""
        if len(self._config) > 0:
            config = str(self._config)
            #config = config.replace("{","").replace("}","")
            result = f"{self.__class__.__name__}({hex(id(self))}, {config})"
        else:
            result = f"{self.__class__.__name__}({hex(id(self))})"
        #print(result)
        return result

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

    def arguments():
            """Returns tuple containing dictionary of calling function's
            named arguments and a list of calling function's unnamed
            positional arguments.
            from: http://kbyanc.blogspot.com/2007/07/python-aggregating-function-arguments.html
            """
            from inspect import getargvalues, stack
            try:
                test = stack()
                #_, kwname, args = getargvalues(stack()[1][0])[-3:]
                _ , kwname, args = getargvalues(stack()[2][0])[-3:]
                args.update(args.pop(kwname, []))
                del args['self']
                del args['__class__']
                final_args = {}
                for k,v in args.items():
                    #print(f"at {k}")
                    if not isinstance(v, BuildingBlock) and (isinstance(v, str) or not isinstance(v, Iterable)):
                        #print(f"  add {k} -> {v}")
                        final_args[k] = v                    
                    if isinstance(v, Iterable) and not isinstance(v, str):
                        final_iter = []
                        for item in v:
                            if not isinstance(item, BuildingBlock):
                                final_iter.append(item)
                        if len(final_iter) > 0:
                            final_args[k] = final_iter
                            #print(f"  add {k} -> {final_iter}")
                return final_args
            except KeyError:
                return {}