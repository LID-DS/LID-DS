from collections import deque

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall
from algorithms.features.impl.ngram import Ngram
import networkx as nx

class SystemCallGraph(BuildingBlock):

    def __init__(self, input: BuildingBlock, thread_aware=True, thread_wise_graphs=False):
        super().__init__()
        # parameter        
        self._input = input
        self._input_id = input.get_id()
        self._thread_aware = thread_aware
        self._thread_wise_graphs = thread_wise_graphs

        # internal data
        self._graphs = {}
        self._last_added_nodes = {}
        self._result_dict = {}

        # dependency list
        self._dependency_list = []
        self._dependency_list.append(self._input)

    def depends_on(self):
        return self._dependency_list

    def train_on(self, syscall: Syscall):
        """
        adds the current input to the grpah
        """
        
        new_node = self._input.get_result(syscall)
        if new_node is not None:
            # check for threads
            tid = 0
            if self._thread_aware:
                tid = syscall.thread_id()
            # graph id
            gid = 0
            if self._thread_wise_graphs:
                gid = syscall.thread_id()

            # check for graph
            if gid not in self._graphs:
                self._graphs[gid] = nx.DiGraph()
            
            # check for last added node
            if tid not in self._last_added_nodes:
                self._last_added_nodes[tid] = None

            # finally add the input
            if self._last_added_nodes[tid] is None:
                self._graphs[gid].add_node(new_node)
            else:
                count = 0
                # edge already in graph? then update its freq.
                if self._graphs[gid].has_edge(self._last_added_nodes[tid], new_node):
                    count = self._graphs[gid].edges[self._last_added_nodes[tid], new_node]["f"]
                    # print(count)
                count += 1
                self._graphs[gid].add_edge(self._last_added_nodes[tid], new_node, f=count)
            self._last_added_nodes[tid] = new_node
    
    def fit(self):
        print(f"got {len(self._graphs)} graphs")
        s_n = 0
        s_e = 0
        for g in self._graphs.values():
            s_n += g.number_of_nodes()
            s_e += g.number_of_edges()
        print(f"with in sum: {s_n} nodes and {s_e} edges")        
        for g in self._graphs.values():
            for source_node in g.nodes:                
                sum_out = 0
                for s,t,data in g.out_edges(nbunch=source_node,data=True):
                    f=data["f"]
                    sum_out += f
                for s,t,data in g.out_edges(nbunch=source_node,data=True):
                    f=data["f"]
                    g.add_edge(s,t,f=f,p=f/sum_out)

    def _calculate(self, syscall: Syscall):
        """
        calculates transition probability 
        """
        # the new node
        new_node = self._input.get_result(syscall)
        if new_node is not None:
            # the thread id
            tid = 0
            if self._thread_aware:
                tid = syscall.thread_id()

            if tid in self._last_added_nodes:
                # is the result already calculated?
                s = self._last_added_nodes[tid]
                t = new_node
                edge = tuple([s,t])                
                if edge in self._result_dict:
                    self._last_added_nodes[tid] = new_node
                    return self._result_dict[edge]
                else:
                    # was not the first node for this tid
                    transition_probability = 0
                    for g in self._graphs.values():
                        if g.has_edge(s, t):
                            transition_probability += g[s][t]["p"]
                    transition_probability /= len(self._graphs)                                        
                    anomaly_score = 1.0 - transition_probability
                    self._result_dict[edge] = anomaly_score
                    self._last_added_nodes[tid] = new_node
                    return anomaly_score
            else:
                self._last_added_nodes[tid] = new_node
                return None
        else:
            return None
            

    def new_recording(self):
        self._last_added_nodes = {}