import math
from collections import deque

from algorithms.building_block import BuildingBlock
from dataloader.syscall import Syscall
from algorithms.features.impl.ngram import Ngram
import networkx as nx

VALID_SCORING_MODES = ('probability', 'frequency', 'confidence', '2-tuple', '3-tuple')

class SystemCallGraph(BuildingBlock):

    def __init__(self, input: BuildingBlock, thread_aware=True, thread_wise_graphs=False,
                 scoring_mode='probability', confidence_tau=10.0):
        super().__init__()
        if scoring_mode not in VALID_SCORING_MODES:
            raise ValueError(f"scoring_mode must be one of {VALID_SCORING_MODES}, got '{scoring_mode}'")
        # parameter
        self._input = input
        self._input_id = input.get_id()
        self._thread_aware = thread_aware
        self._thread_wise_graphs = thread_wise_graphs
        self._scoring_mode = scoring_mode
        self._confidence_tau = confidence_tau

        # internal data
        self._graphs = {}
        self._last_added_nodes = {}
        self._result_dict = {}
        self._max_f = 1

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
        max_f = 0
        for g in self._graphs.values():
            s_n += g.number_of_nodes()
            s_e += g.number_of_edges()
            for s, t, data in g.edges(data=True):
                if data["f"] > max_f:
                    max_f = data["f"]
        self._max_f = max_f if max_f > 0 else 1
        print(f"with in sum: {s_n} nodes and {s_e} edges (max_f={self._max_f})")
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
        calculates anomaly score based on scoring_mode
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
                edge = (s, t)
                if edge in self._result_dict:
                    self._last_added_nodes[tid] = new_node
                    return self._result_dict[edge]
                else:
                    # aggregate probability and frequency across graphs
                    transition_probability = 0.0
                    frequency_norm = 0.0
                    for g in self._graphs.values():
                        if g.has_edge(s, t):
                            transition_probability += g[s][t]["p"]
                            frequency_norm += g[s][t]["f"] / self._max_f
                    num_graphs = len(self._graphs)
                    transition_probability /= num_graphs
                    frequency_norm /= num_graphs

                    result = self._compute_score(transition_probability, frequency_norm)
                    self._result_dict[edge] = result
                    self._last_added_nodes[tid] = new_node
                    return result
            else:
                self._last_added_nodes[tid] = new_node
                return None
        else:
            return None

    def _compute_score(self, p, f_norm):
        prob_score = 1.0 - p
        freq_score = 1.0 - f_norm
        if self._scoring_mode == 'probability':
            return prob_score
        elif self._scoring_mode == 'frequency':
            return freq_score
        elif self._scoring_mode == 'confidence':
            confidence = 1.0 - math.exp(-f_norm * self._max_f / self._confidence_tau)
            return 1.0 - confidence * p
        elif self._scoring_mode == '2-tuple':
            return (prob_score, freq_score)
        else:  # 3-tuple
            confidence = 1.0 - math.exp(-f_norm * self._max_f / self._confidence_tau)
            return (prob_score, freq_score, 1.0 - confidence * p)
            

    def new_recording(self):
        self._last_added_nodes = {}