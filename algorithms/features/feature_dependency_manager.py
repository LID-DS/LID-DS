import networkx as nx


class FeatureDependencyManager:
    def __init__(self, list_of_features):
        self._dependency_graph = nx.DiGraph()

        todo_features = []
        todo_temp = []
        for feature_instance in list_of_features:
            print(f"adding: {feature_instance}")
            todo_features.append(feature_instance)

        while len(todo_features) > 0:
            for source_feature_instance in todo_features:
                print(f"at {source_feature_instance}")
                for destination_feature_instance in source_feature_instance.depends_on():
                    print(f"adding: {source_feature_instance} -> {destination_feature_instance}")
                    self._dependency_graph.add_edge(source_feature_instance, destination_feature_instance)
                    todo_temp.append(destination_feature_instance)
            todo_features = todo_temp
            todo_temp = []

        # print graph in dot format for graphviz visualization
        dot = nx.drawing.nx_pydot.to_pydot(self._dependency_graph)
        print(dot)

        # determine order of calculation by topological sorting the underlying DAG
        # save the order as list of generations
        self.feature_generations = []
        for generation in nx.topological_generations(self._dependency_graph):
            self.feature_generations.append(generation)
        self.feature_generations.reverse()
