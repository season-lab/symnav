from IPython import embed
from utility.tree import Node, Tree
import claripy
import json

SKIP      = 1
SKIP_PATH = 2
ADD       = 3

class Filter(object):
    def __init__(self, blocks_white, edges_white, blocks_black, edges_black, max_fork, fork_choices, range_symbols):
        self.blocks_white  = blocks_white
        self.edges_white   = edges_white
        self.blocks_black  = blocks_black
        self.edges_black   = edges_black
        self.max_fork      = max_fork
        self.fork_choices  = fork_choices
        self.range_symbols = range_symbols

class TreePruner(object):
    def __init__(self, symb_tree, address_to_block, symbols):
        self.symb_tree = symb_tree
        self.symbols   = symbols
        if isinstance(address_to_block, dict):
            self.address_to_block = address_to_block
        else:
            with open(address_to_block, "r") as fin:
                self.address_to_block = json.load(fin)
    
    def parse_options(self, filter_opts):
        res = Filter(
            dict(), dict(), dict(), dict(), dict(), dict(), dict()
        )
        
        for opt in filter_opts:
            if opt["type"] == "filter_block" and opt["mode"] == "black":
                count = 0
                if "count" in opt:
                    count = int(opt["count"])
                res.blocks_black[opt["block_id"]] = count
            elif opt["type"] == "filter_block" and opt["mode"] == "white":
                count = 1
                if "count" in opt:
                    count = int(opt["count"])
                res.blocks_white[opt["block_id"]] = count
            elif opt["type"] == "filter_edge" and opt["mode"] == "black":
                count = 0
                if "count" in opt:
                    count = int(opt["count"])
                res.edges_black[
                    opt["src_id"], opt["dst_id"]
                ] = count
            elif opt["type"] == "filter_edge" and opt["mode"] == "white":
                count = 1
                if "count" in opt:
                    count = int(opt["count"])
                res.edges_white[(
                    opt["src_id"], opt["dst_id"]
                )] = count
            elif opt["type"] == "limit_fork":
                assert opt["block_id"] not in res.max_fork
                res.max_fork[opt["block_id"]] = [int(opt["num_fork"]), True]
                if "fork_choice" in opt:
                    res.fork_choices[opt["block_id"]] = opt["fork_choice"]
                if "inverted" in opt:
                    assert opt["inverted"] in {True, False}
                    if opt["inverted"]:
                        res.max_fork[opt["block_id"]] = [int(opt["num_fork"]), False]
            elif opt["type"] == "limit_symbol":
                assert opt["symbol_id"] not in res.range_symbols
                assert opt["symbol_id"] in self.symbols
                symb_obj = self.symbols[opt["symbol_id"]].claripy_obj
                res.range_symbols[opt["symbol_id"]] = (
                    symb_obj, int(opt["min"]), int(opt["max"])
                )
        return res
    
    @staticmethod
    def check_blacklisted_blocks(path, blocks_black):
        """ check whether all black-list blocks do not exceed max count """
        tmp_blocks_black = dict(blocks_black)
        for b in path:
            if b in tmp_blocks_black:
                tmp_blocks_black[b] -= 1
                if tmp_blocks_black[b] < 0:
                    return False
        return True
    
    @staticmethod
    def check_blacklisted_edges(path, edges_black):
        """ check whether all black-list edges do not exceed max count """
        edges = list()
        for b1, b2 in zip(path, path[1:]):
            edges.append((b1, b2))

        tmp_edges_black = dict(edges_black)
        for b1, b2 in edges:
            if (b1, b2) in tmp_edges_black:
                tmp_edges_black[(b1, b2)] -= 1
                if tmp_edges_black[(b1, b2)] < 0:
                    return False
        return True

    @staticmethod
    def check_whitelisted_blocks(path, blocks_white):
        """ check whether all white-list blocks are in path """
        tmp_blocks_white = dict(blocks_white)
        for b in path:
            if b in tmp_blocks_white:
                tmp_blocks_white[b] -= 1
        
        for b in tmp_blocks_white:
            if tmp_blocks_white[b] > 0:
                return False
        return True
    
    @staticmethod
    def check_whitelisted_edges(path, edges_white):
        """ check whether all white-list edges are in path """

        edges = list()
        for b1, b2 in zip(path, path[1:]):
            edges.append((b1, b2))

        tmp_edges_white = dict(edges_white)
        for e in edges:
            if e in tmp_edges_white:
                tmp_edges_white[e] -= 1
        
        for e in tmp_edges_white:
            if tmp_edges_white[e] > 0:
                return False
        return True
    
    @staticmethod
    def check_symbol_range(state, range_symbols):
        for sid in range_symbols:
            symbol, rmin, rmax = range_symbols[sid]
            if not state.solver.satisfiable(extra_constraints=[
                claripy.And(
                    claripy.SGE(symbol, rmin),
                    claripy.SLE(symbol, rmax)
                )
            ]):
                return False
        return True
    
    def get_blocks_state(self, state):
        blocks = []
        for addr in state.block_addresses:
            if str(addr) in self.address_to_block:
                block_id = self.address_to_block[str(addr)]
                if block_id not in blocks:
                    blocks.append(block_id)
        return blocks
    
    def choose_next(self, block_id, children, fork_choices):
        assert children
        if block_id not in fork_choices:
            return children[0]

        for child in children:
            lwState = child.data
            blocks = self.get_blocks_state(lwState)
            if set(blocks).intersection(set([fork_choices[block_id]])):
                return child
        return children[0]

    def __filter_tree(self, node, prec_id, path, filter_data, tree):
        lwState  = node.data
        blocks_id = self.get_blocks_state(lwState)
        path = path + blocks_id
        
        # block black check
        if not TreePruner.check_blacklisted_blocks(path, filter_data.blocks_black):
            return SKIP_PATH, None
        # edge black check
        if not TreePruner.check_blacklisted_edges(path, filter_data.edges_black):
            return SKIP_PATH, None

        if len(node.children) == 0:
            # block white check
            if not TreePruner.check_whitelisted_blocks(path, filter_data.blocks_white):
                return SKIP_PATH, None
            # edge white check
            if not TreePruner.check_whitelisted_edges(path, filter_data.edges_white):
                return SKIP_PATH, None
            # symbol range check. Weakref should be good since it is a leaf
            if not TreePruner.check_symbol_range(lwState.state_weakref, filter_data.range_symbols):
                return SKIP_PATH, None
        
        # limit fork check
        limit_child_number = False
        for block_id in blocks_id:
            if block_id in filter_data.max_fork:
                filter_data.max_fork[block_id][0] -= 1
                count, normal = filter_data.max_fork[block_id]
                if (
                    (normal and count < 0) or
                    (not normal and count >= 0)
                ):
                    limit_child_number = True

        # recursive call to children
        new_node  = Node(node.id, node.data, node.father_id)
        skip_path = False
        children = node.children
        # limit forks
        if children and limit_child_number:
            children = [self.choose_next(block_id, node.children, filter_data.fork_choices)]
        for child in children:
            cmd, res_node = self.__filter_tree(child, blocks_id[-1] if blocks_id else "", path, filter_data, tree)
            if cmd == ADD:
                new_node.children.append(res_node)
            elif cmd == SKIP_PATH:
                skip_path = True
        
        if skip_path and len(new_node.children) == 0:
            return SKIP_PATH, None
        tree.add_node(new_node)
        return ADD, new_node
    
    def filter_tree(self, filter_opts):
        filter_data = self.parse_options(filter_opts)

        new_tree = Tree()
        if self.symb_tree.is_empty():
            return new_tree

        node = self.symb_tree.root.children[0]
        self.__filter_tree(node, "", list(), filter_data, new_tree)

        return new_tree
