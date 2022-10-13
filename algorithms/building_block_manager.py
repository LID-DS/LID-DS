import networkx as nx

from algorithms.building_block import BuildingBlock


class BuildingBlockManager:
    def __init__(self, final_bb: BuildingBlock):
        self._dependency_graph = nx.DiGraph()
        self._final_bb = final_bb

        #self._dependency_graph.add_node(final_bb)
        todo_bb = [final_bb]#.depends_on()
        todo_temp = []        
        
        while len(todo_bb) > 0:
            for source_bb_instance in todo_bb:
                for destination_bb_instance in source_bb_instance.depends_on():
                    self._dependency_graph.add_edge(source_bb_instance, destination_bb_instance)
                    todo_temp.append(destination_bb_instance)
            todo_bb = todo_temp
            todo_temp = []

        # determine order of calculation by topological sorting the underlying DAG
        # save the order as list of generations
        self.building_block_generations = []
        for generation in nx.topological_generations(self._dependency_graph):
            self.building_block_generations.append(generation)
        self.building_block_generations.reverse()

    def get_final_bb(self):
        """
        returns the "final" building block
        """
        return self._final_bb

    def to_dot(self):
        # print graph in dot format for graphviz visualization
        dot = nx.drawing.nx_pydot.to_pydot(self._dependency_graph)
        return dot

    def get_dependency_graph(self):
        return self._dependency_graph
