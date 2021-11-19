import networkx as nx


class FeatureManager:
    def __init__(self, list_of_features):
        self._dependency_graph = nx.DiGraph()
        self._final_features = list_of_features

        todo_features = []
        todo_temp = []
        for feature_instance in list_of_features:
            todo_features.append(feature_instance)
            self._dependency_graph.add_node(feature_instance)

        while len(todo_features) > 0:
            for source_feature_instance in todo_features:
                for destination_feature_instance in source_feature_instance.depends_on():
                    self._dependency_graph.add_edge(source_feature_instance, destination_feature_instance)
                    todo_temp.append(destination_feature_instance)
            todo_features = todo_temp
            todo_temp = []

        # determine order of calculation by topological sorting the underlying DAG
        # save the order as list of generations
        self.feature_generations = []
        for generation in nx.topological_generations(self._dependency_graph):
            self.feature_generations.append(generation)
        self.feature_generations.reverse()

    def get_features(self):
        """
        returns the "final" features -> the features used to build the resulting feature vector
        """
        return self._final_features

    def to_dot(self):
        # print graph in dot format for graphviz visualization
        dot = nx.drawing.nx_pydot.to_pydot(self._dependency_graph)
        return dot
