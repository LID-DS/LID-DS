"""
Utility functions for converting an ids dependency graph to a json format

"""
import json
from enum import Enum

from networkx import DiGraph
from networkx.readwrite import json_graph

from algorithms.building_block import BuildingBlock


def dependency_graph_to_config_tree(dependency_graph: DiGraph) -> dict:
    """
        gives the dependency graph as list of links between ids of building blocks
        each building block contains its config in another list called node

        returns: dictionary with nodes and links of the config graph
    """

    # getting the dependency tree
    graph_dict = json_graph.node_link_data(dependency_graph)
    json_string = json_encode(graph_dict)
    json_loaded = json.loads(json_string)

    """
        reforming dictionary to fit:
        {
            nodes: [
                {node1},
                {node2},
                ....
            ]
            links: [
                {
                    'source': node1['id'],
                    'target': node2['id]
            ]
        }
    """

    short_links = []
    for link in json_loaded['links']:
        short_links.append(
            {
                'source': link['source']['id'],
                'target': link['target']['id'],
            }
        )

    nodes = []
    for node in json_loaded['nodes']:
        nodes.append(node['id'])

    result = {
        'nodes': nodes,
        'links': short_links
    }
    return result


class BBJsonEncoder(json.JSONEncoder):
    """
    Custom JSONEncoder that recognizes BuildingBlocks
    """

    def default(self, obj):
        """ handle json encoding of non-primitive BuildingBlock class members"""
        if isinstance(obj, BuildingBlock):
            return obj.to_dict_repr()
        if isinstance(obj, Enum):
            return str(obj.name)
        return json.JSONEncoder.default(self, obj)


def json_encode(data):
    """alias for `BBJsonEncoder().encode(data)`"""
    return BBJsonEncoder().encode(data)
