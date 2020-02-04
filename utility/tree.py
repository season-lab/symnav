class Node(object):
    def __init__(self, id, data, father_id=None):
        self.id        = id
        self.data      = data
        self.father_id = father_id
        self.children  = list()
    
    def copy(self):
        n = Node(self.id, self.data, self.father_id)
        n.children = self.children[:]
        return n

    def __hash__(self):
        return self.id
    
    def __eq__(self, other):
        return isinstance(other, Node) and self.id == other.id
    
    def __str__(self):
        return "<Node %s. data=%s>" % (str(self.id), str(self.data))
    
    def __repr__(self):
        return self.__str__()
    
    def serialize(self):
        children_serialize = [el.serialize() for el in self.children]
        val = 0
        for _, k, _ in children_serialize:
            val += k
        if val == 0:
            val = 1
        
        if isinstance(self.data, list):
            data = self.data[0]
        else:
            data = self.data
        label = str(data) if data else ""
        return (label, val, children_serialize)

class Tree(object):
    def __init__(self):
        self.root      = Node(0, None)
        self.root_id   = 0
        self.lookup    = dict()
        self.lookup[0] = self.root
    
    def is_empty(self):
        return len(self.root.children) == 0
    
    def is_leaf(self, node_id):
        return len(self.lookup[node_id].children) == 0

    def contains(self, node_id):
        return node_id in self.lookup
    
    def get_by_id(self, id):
        return self.lookup[id]
    
    def add_child(self, child_id, child_data, father_id=None):
        if father_id is None:
            father_id = self.root_id
        assert father_id in self.lookup
        assert child_id != 0
        self.lookup[child_id] = Node(child_id, child_data, father_id)
        self.lookup[father_id].children.append(self.lookup[child_id])
    
    def add_node(self, node):
        assert node.id != 0
        if node.father_id == 0:
            self.root.children = [node]
        self.lookup[node.id] = node
    
    def paths(self):
        path  = []
        stack = [
            (self.root_id, [])
        ]

        while stack:
            node_id, path = stack.pop()
            node          = self.lookup[node_id]

            if not node.children:
                yield path
            else:
                for child in node.children:
                    stack.append(
                        (child.id, path + [child])
                    )
    
    def leaves(self):
        for node_id in self.lookup:
            node = self.lookup[node_id]
            if len(node.children) == 0:
                yield node

    def DFS(self):
        stack = [self.root_id]

        while stack:
            node_id = stack.pop()
            if node_id != 0:
                yield self.lookup[node_id]
            stack.extend([el.id for el in self.lookup[node_id].children])
    
    def edges(self):
        stack = [self.root_id]

        while stack:
            node_id = stack.pop()
            if node_id == 0:
                continue
            
            for child in self.lookup[node_id].children:
                yield (self.lookup[node_id], child)
            stack.extend([el.id for el in self.lookup[node_id].children])
    
    def serialize(self):
        return [self.root.serialize()]
    
    def simplify(self):
        new_tree = Tree()

        fringe = self.root.children[:]
        for el in fringe:
            new_tree.add_child(el.id, [el.data])

        while fringe:
            el = fringe.pop()
            node = new_tree.get_by_id(el.id)

            while len(el.children) == 1:
                child = el.children[0]
                node.data.append(child.data)
                el = child
            
            for child in el.children:
                new_tree.add_child(child.id, [child.data], node.id)
                fringe.append(child)
        
        return new_tree
    
    def to_graphviz(self):
        fout = open("/home/luca/symb_tree.dot", "w")
        fout.write("digraph {\n")
        for key in self.lookup:
            node = self.lookup[key]
            fout.write("\t%s [label=\"\"]\n" % str(node.id))
            for child in node.children:
                fout.write("\t%s -> %s\n" % (str(node.id), str(child.id)))
        fout.write("}\n")
    
    def __eq__(self, other):
        if not isinstance(other, Tree):
            return False
        if len(other.lookup) != len(self.lookup):
            return False
        
        for key in self.lookup:
            if key not in other.lookup:
                return False
            if self.lookup[key] != other.lookup[key]:
                return False
        
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Tree with %d nodes>" % len(self.lookup)
    
    def __repr__(self):
        return self.__str__()

if __name__ == "__main__":
    t = Tree()
    t.add_child(1, "1")
    t.add_child(2, "2", father_id=1)
    t.add_child(7, "7", father_id=1)
    t.add_child(9, "9", father_id=7)
    t.add_child(3, "3")
    t.add_child(4, "4", father_id=3)
    t.add_child(5, "5", father_id=3)

    for path in t.paths():
        print(path)
