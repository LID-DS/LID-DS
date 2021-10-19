from treelib import Tree

if __name__ == '__main__':
    tree = Tree()

    tree.create_node(tag='scads')
    tree.create_node(tag='martin', parent='scads')
    tree.create_node(tag='felix', parent='martin')
    tree.create_node(tag='eric', parent='scads')
    tree.create_node(tag='felix', parent='eric')

    print(tree)
