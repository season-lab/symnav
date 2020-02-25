from utility.tree import Tree
from analyses.constrained_inputs import extract_indirect_inputs
from angr.state_plugins.sim_action import SimActionConstraint
import json
import weakref

class LightweightState(object):
    def __init__(self, state):
        self.id              = LightweightState.hash_from_state(state)
        self.address         = state.addr                       # current ip value
        self.constraints     = state.solver.constraints[:]      # list of constraints
        self.block_addresses = state.block().instruction_addrs  # addresses of the block
        self.callstack       = list()                           # complete callstack
        self.last_constr     = None                             # last constraint added (if any!)
        self.mapped_pages    = len(state.memory.mem._pages)
        self.state_weakref   = weakref.proxy(state)
        for el in state.callstack:
            if el.ret_addr == 0:
                continue
            self.callstack.append(el.ret_addr)
        if list(state.history.actions):
            sac = list(state.history.actions)[-1]
            if isinstance(sac, SimActionConstraint):
                self.last_constr = sac
    
    def __str__(self):
        res = "<LightweightState %d at 0x%x>" % (self.id, self.address)
        return res
    
    def __repr__(self):
        return self.__str__()
    
    @staticmethod
    def hash_from_state(state):
        return id(state.history)
    
    @staticmethod
    def hash_from_history(state_history):
        return id(state_history)

class SymbtreeBuilder(object):
    def __init__(self, path_addr_to_block, tree=None):
        self.tree          = Tree() if tree is None else tree
        self.first_state   = None if (tree is None or tree.root.children == []) else tree.root.children[0].data
        self.addr_to_block = None
        with open(path_addr_to_block, "r") as fin:
            self.addr_to_block = json.load(fin)
    
    def update(self, state):
        if self.first_state is None:
            self.first_state = LightweightState(state)
            self.tree.add_child(self.first_state.id, self.first_state)
            return

        father = state.history.parent
        if father is None:
            father_id = self.first_state.id
        else:
            father_id = LightweightState.hash_from_history(father)
        assert self.tree.contains(father_id)
        
        lwState = LightweightState(state)
        assert not self.tree.contains(lwState.id)
        self.tree.add_child(lwState.id, lwState, father_id)
    
    def simplify_symbtree(self):
        simplified = self.tree.simplify()

        node_id_to_merged_id = dict()
        for node in simplified.DFS():
            for lwState in node.data:
                assert lwState.id not in node_id_to_merged_id
                node_id_to_merged_id[lwState.id] = node.id
        
        return simplified, node_id_to_merged_id

    def serialize(self):
        return self.tree.serialize()
