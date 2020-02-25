# import matplotlib.cm as cm
import json
from angr.state_plugins.sim_action import SimActionConstraint
from analyses.constrained_inputs import extract_indirect_inputs
from analyses.symbtree_builder import LightweightState
from utility.util import insert_or_add, combine_histograms, combine_histograms_max, check_weakref
from functools import reduce
from IPython import embed

def float_to_rgb(v):
    # r, g, b, _ = cm.Reds(v, 1, bytes=True)
    r, g, b = 0, 0, 0
    return r, g, b

class TreeAnalyzer(object):
    def __init__(self, symb_tree, address_to_block, angr_wrapper=None):
        self.angr_wrapper = angr_wrapper
        self.symb_tree = symb_tree
        if isinstance(address_to_block, dict):
            self.address_to_block = address_to_block
        else:
            with open(address_to_block, "r") as fin:
                self.address_to_block = json.load(fin)
    
    def compute_forks(self):
        forks = dict()
        for node_id in self.symb_tree.lookup:
            node = self.symb_tree.lookup[node_id]
            if len(node.children) > 1:

                lwChild = node.children[0].data
                sac = lwChild.last_constr
                assert sac is not None

                tmp = set()
                for c in sac.all_objects:
                    tmp = tmp.union(set(list(c.ast.variables)))
                
                indirect = extract_indirect_inputs(lwChild.constraints, tmp)
                tmp = tmp.union(indirect)
                
                lwState = node.data
                addr = lwState.block_addresses[-1]

                if addr in forks:
                    symbols, count = forks[addr]
                    symbols = symbols.union(tmp)
                    count += 1
                    forks[addr] = symbols, count
                else:
                    forks[addr] = tmp, 1

        # save info in json-like struct
        res = list()
        for addr in forks:
            d = dict()
            if str(addr) not in self.address_to_block:
                continue
            symbols, count = forks[addr]
            d["block"]   = self.address_to_block[str(addr)]
            d["count"]   = count
            d["symbols"] = list()
            for symbol in symbols:
                d["symbols"].append(symbol)
            res.append(d)
        
        return res

    def compute_visited_basic_blocks(self):
        visited = dict()
        for path in self.symb_tree.paths():
            self.tmp_dict = dict()
            for node in path:
                lwState = node.data
                for addr in lwState.block_addresses:
                    if addr not in self.tmp_dict:
                        self.tmp_dict[addr] = 1

                    for addr in lwState.callstack: 
                        if addr not in self.tmp_dict:
                            self.tmp_dict[addr] = 1
            for addr in self.tmp_dict:
                if addr in visited:
                    visited[addr] += 1
                else:
                    visited[addr]  = 1
        
        # save info in json-like struct
        added_blocks = set()  # to avoid duplicates
        res          = list()
        for addr in visited:
            d = dict()
            if str(addr) not in self.address_to_block:
                continue
            if self.address_to_block[str(addr)] in added_blocks:
                # angr bb and r2 bb are not aligned
                continue
            d["block"] = self.address_to_block[str(addr)]
            d["count"] = visited[addr]
            res.append(d)
            added_blocks.add(d["block"])
        return res

    @staticmethod
    def compute_max_most_visited(path):
        visited = dict()
        for node in path:
            for lwState in node.data:
                addr = lwState.address
                if addr in visited:
                    visited[addr] += 1
                else:
                    visited[addr]  = 1
        return max(visited.values())
    
    @staticmethod
    def compute_symbolic_pages(state):
        if state is None:
            return 0
        symbolic_pages = 0
        for page_addr in state.memory.mem._pages:
            page = state.memory.mem._pages[page_addr]
            for v in page._storage:
                if v is not None and state.solver.symbolic(v.object):
                    symbolic_pages += 1
                    break
        return symbolic_pages
    
    def compute_generated_symbols(self, path):  # improve performance
        if self.angr_wrapper is None:
            return -1
        _, node_id_to_merged_id = self.angr_wrapper.stb.simplify_symbtree()

        node_to_symbol = dict()
        for symbol_name in self.angr_wrapper.symbols:
            symbol = self.angr_wrapper.symbols[symbol_name]
            creation_node_id = node_id_to_merged_id[symbol.node_id] if symbol.node_id != 0 else 0
            if creation_node_id not in node_to_symbol:
                node_to_symbol[creation_node_id] = set([symbol_name])
            else:
                node_to_symbol[creation_node_id].add(symbol_name)
        
        res = 0
        for node in path:
            if node.id in node_to_symbol:
                res += len(node_to_symbol[node.id])
        return res
    
    @staticmethod
    def count_block_unique(path):
        res = set()
        for node in path:
            for block in node.data:
                res.add(block.address)
        return len(res)

    def compute_leaves_info(self):
        res = list()
        i = 0
        for path in self.symb_tree.simplify().paths():
            if not path: 
                return []
            leaf_state_weakref = path[-1].data[-1].state_weakref
            lp = dict()
            lp["id"] = path[-1].id
            lp["executed_basic_blocks"] = reduce(lambda x, y: x+y, [len(node.data) for node in path])
            lp["executed_basic_blocks_unique"] = TreeAnalyzer.count_block_unique(path)
            lp["max_rep_basic_block"] = TreeAnalyzer.compute_max_most_visited(path)
            lp["num_constraints"] = len(path[-1].data[-1].constraints)
            lp["mapped_pages"] = path[-1].data[-1].mapped_pages
            lp["symbolic_pages"] = TreeAnalyzer.compute_symbolic_pages(leaf_state_weakref)  # leaf weakref should be good
            lp["generated_symbols"] = self.compute_generated_symbols(path)
            lp["num_malloc_free"] = reduce(
                lambda x, y: x+y, 
                map(
                    lambda z: 1 if ("malloc" in str(z) or "free" in str(z)) else 0, 
                    leaf_state_weakref.history.events)) if leaf_state_weakref else 0
            res.append(lp)
            i += 1
        return res

    def __compute_edges(self, child, father, res):
        child_id  = str(child.data.address)
        father_id = str(father.data.block_addresses[-1]) if father.data else None

        if child_id not in self.address_to_block:
            child_block_id  = None
        else:
            child_block_id  = self.address_to_block[child_id]
        if father_id not in self.address_to_block:
            father_block_id = None
        else:
            father_block_id = self.address_to_block[father_id]
        
        if child_block_id and father_block_id:
            insert_or_add(res, (father_block_id, child_block_id), 1)
        
        for nephew in child.children:
            self.__compute_edges(nephew, child, res)
    
    def compute_edges(self):
        if self.symb_tree.is_empty():
            return dict()
        
        edges = dict()
        self.__compute_edges(self.symb_tree.root.children[0], self.symb_tree.root, edges)
        return edges
    
    def __compute_node_count_per_edge(self, child, father, edges_list_post, edges_list_pre, visited_edges, visited_nodes, dropped_edges):
        child_id  = str(child.data.address)
        father_id = str(father.data.block_addresses[-1]) if father.data else None
        nephew_visited_edges = visited_edges.copy()
        
        if child_id not in self.address_to_block:
            child_block_id  = None
        else:
            child_block_id  = self.address_to_block[child_id]
        if father_id not in self.address_to_block:
            father_block_id = None
        else:
            father_block_id = self.address_to_block[father_id]
        
        if child_block_id and father_block_id:
            nephew_visited_edges.add((father_block_id, child_block_id))

            # this edges is considered dropped. Return empty histogram
            if (father_block_id, child_block_id) in dropped_edges:
                return dict()
        
        # add node even if its block is not in R2
        # this is different with respect to "__compute_block_histogram_per_edge"
        nephew_visited_nodes = visited_nodes.copy()
        nephew_visited_nodes.add(child)
        
        nephews_blocks = 0
        for nephew in child.children:
            nephew_blocks = self.__compute_node_count_per_edge(
                nephew, child, edges_list_post, edges_list_pre, nephew_visited_edges, nephew_visited_nodes, dropped_edges)
            nephews_blocks += nephew_blocks
        
        # count the node even if its block is not in R2
        # this is different with respect to "__compute_block_histogram_per_edge"
        my_nodes = nephews_blocks + 1
        if child_block_id and father_block_id:
            edge_id = (father_block_id, child_block_id)
            if edge_id not in visited_edges:
                insert_or_add(edges_list_post, edge_id, my_nodes)
                if edge_id not in edges_list_pre:
                    edges_list_pre[edge_id] = visited_nodes
                else:
                    edges_list_pre[edge_id] = edges_list_pre[edge_id].union(visited_nodes)

        return my_nodes
    
    def compute_node_count_per_edge(self, dropped_edges=set()):
        if self.symb_tree.is_empty():
            return 0, dict(), dict()

        edges_post = dict()
        edges_pre  = dict()
        total_nodes = self.__compute_node_count_per_edge(
            self.symb_tree.root.children[0], self.symb_tree.root, edges_post, edges_pre, set(), set(), dropped_edges)

        for edge in edges_pre:
            visited = edges_pre[edge]
            new = len(visited)
            edges_pre[edge] = new
        return total_nodes, edges_post, edges_pre

    def __compute_node_count_per_block(self, node, nodes_list_post, nodes_list_pre, visited_blocks, visited_nodes, dropped_blocks):
        node_id  = str(node.data.address)
        child_visited_blocks = visited_blocks.copy()
        child_visited_nodes  = visited_nodes.copy()
        
        if node_id not in self.address_to_block:
            node_block_id = None
        else:
            node_block_id = self.address_to_block[node_id]
        
        if node_block_id:
            child_visited_blocks.add(node_block_id)

            # this edges is considered dropped. Return empty histogram
            if node_block_id in dropped_blocks:
                return dict()
        
        # add node even if its block is not in R2
        # this is different with respect to "__compute_block_histogram_per_edge"
        child_visited_nodes.add(node)
        
        children_blocks = 0
        for child in node.children:
            child_blocks = self.__compute_node_count_per_block(
                child, nodes_list_post, nodes_list_pre, child_visited_blocks, child_visited_nodes, dropped_blocks)
            children_blocks += child_blocks
        
        # count the node even if its block is not in R2
        # this is different with respect to "__compute_block_histogram_per_edge"
        my_nodes = children_blocks + 1
        if node_block_id:
            if node_block_id not in visited_blocks:
                insert_or_add(nodes_list_post, node_block_id, my_nodes)
                if node_block_id not in nodes_list_pre:
                    nodes_list_pre[node_block_id] = visited_nodes
                else:
                    nodes_list_pre[node_block_id] = nodes_list_pre[node_block_id].union(visited_nodes)

        return my_nodes

    def compute_node_count_per_block(self, dropped_nodes=set()):
        if self.symb_tree.is_empty():
            return 0, dict(), dict()

        blocks_post = dict()
        blocks_pre  = dict()
        total_nodes = self.__compute_node_count_per_block(
            self.symb_tree.root.children[0], blocks_post, blocks_pre, set(), set(), dropped_nodes)
        
        # calculate count pre
        for b in blocks_pre:
            visited = blocks_pre[b]
            new = len(visited)
            blocks_pre[b] = new

        return total_nodes, blocks_post, blocks_pre

    def __compute_block_histogram_per_edge(self, child, father, edges_list_post, edges_list_pre, visited_edges, visited_nodes, dropped_edges):
        child_id  = str(child.data.address)
        father_id = str(father.data.block_addresses[-1]) if father.data else None
        nephew_visited_edges = visited_edges.copy()
        nephew_visited_nodes = visited_nodes.copy()
        
        # find out whether the addresses of child and father are in R2 CFG
        # they cannot be there due to fake angr blocks (simprocedures)
        if child_id not in self.address_to_block:
            child_block_id  = None
        else:
            child_block_id  = self.address_to_block[child_id]
        if father_id not in self.address_to_block:
            father_block_id = None
        else:
            father_block_id = self.address_to_block[father_id]
        
        if child_block_id and father_block_id:
            nephew_visited_edges.add((father_block_id, child_block_id))

            # this edges is considered dropped. Return empty histogram
            if (father_block_id, child_block_id) in dropped_edges:
                return dict()
        
        if child_block_id:
            nephew_visited_nodes.add(child)
        
        # combine nephew histograms (if any)
        nephews_histogram = dict()
        for nephew in child.children:
            nephew_hist = self.__compute_block_histogram_per_edge(
                nephew, child, edges_list_post, edges_list_pre, nephew_visited_edges, nephew_visited_nodes, dropped_edges)
            combine_histograms(nephews_histogram, nephew_hist)

        my_histogram = nephews_histogram

        if child_block_id and father_block_id:
            # the current block is in R2. Add it to the histogram to be returned
            insert_or_add(my_histogram, child_block_id, 1)

            # merge my histogram to edges_list only if the current edge was not visited by parents
            # Otherwise -> double count (see TreeAnalyzerTests.test_6())
            edge_id = (father_block_id, child_block_id)
            if edge_id not in visited_edges:
                if edge_id not in edges_list_post:
                    edges_list_post[edge_id] = my_histogram
                else:
                    combine_histograms(edges_list_post[edge_id], my_histogram)

                if edge_id not in edges_list_pre:
                    edges_list_pre[edge_id] = visited_nodes
                else:
                    edges_list_pre[edge_id] = edges_list_pre[edge_id].union(visited_nodes)

        # return histogram. Copy it because it can be in edges_list_post
        return dict(my_histogram)

    def compute_block_histogram_per_edge(self, dropped_edges=set()):
        if self.symb_tree.is_empty():
            return dict(), dict(), dict()

        edges_post = dict()
        edges_pre  = dict()
        root_histogram = self.__compute_block_histogram_per_edge(
            self.symb_tree.root.children[0], self.symb_tree.root, edges_post, edges_pre, set(), set(), dropped_edges)
        
        # calculate histogram pre
        for edge in edges_pre:
            visited = edges_pre[edge]
            new = dict()
            for node in visited:
                block_id = self.address_to_block[str(node.data.address)]
                insert_or_add(new, block_id, 1)
            edges_pre[edge] = new

        # add the first node block to the root histogram
        first_node_addr = self.symb_tree.root.children[0].data.address
        if first_node_addr in self.address_to_block:
            insert_or_add(root_histogram, self.address_to_block[first_node_addr], 1)

        return root_histogram, edges_post, edges_pre
    
    def __find_first_blocks(self, node):
        node_id = str(node.data.address)
        res = set()
        if node_id not in self.address_to_block:
            for child in node.children:
                res = res.union(self.__find_first_blocks(child))
        else:
            res.add(self.address_to_block[node_id])
        return res

    def find_first_blocks(self):
        if self.symb_tree.is_empty():
            return None
        return self.__find_first_blocks(self.symb_tree.root.children[0])

    def __compute_block_histogram_per_block(self, node, nodes_list_post, nodes_list_pre, visited_blocks, visited_nodes, dropped_nodes):
        node_id  = str(node.data.address)
        child_visited_nodes  = visited_nodes.copy()
        child_visited_blocks = visited_blocks.copy()
        
        # find out whether the addresses of child and father are in R2 CFG
        # they cannot be there due to fake angr blocks (simprocedures)
        if node_id not in self.address_to_block:
            node_block_id  = None
        else:
            node_block_id = self.address_to_block[node_id]
        
        if node_block_id:
            child_visited_nodes.add(node)
            child_visited_blocks.add(node_block_id)

            # this edges is considered dropped. Return empty histogram
            if node_block_id in dropped_nodes:
                return dict()
        
        # combine nephew histograms (if any)
        children_histogram = dict()
        for child in node.children:
            child_hist = self.__compute_block_histogram_per_block(
                child, nodes_list_post, nodes_list_pre, child_visited_blocks, child_visited_nodes, dropped_nodes)
            combine_histograms(children_histogram, child_hist)

        my_histogram = children_histogram

        if node_block_id:
            # the current block is in R2. Add it to the histogram to be returned
            insert_or_add(my_histogram, node_block_id, 1)

            # merge my histogram to edges_list only if the current edge was not visited by parents
            # Otherwise -> double count (see TreeAnalyzerTests.test_6())
            if node_block_id not in visited_blocks:
                if node_block_id not in nodes_list_post:
                    nodes_list_post[node_block_id] = my_histogram
                else:
                    combine_histograms(nodes_list_post[node_block_id], my_histogram)

                if node_block_id not in nodes_list_pre:
                    nodes_list_pre[node_block_id] = visited_nodes
                else:
                    nodes_list_pre[node_block_id] = nodes_list_pre[node_block_id].union(visited_nodes)

        # return histogram. Copy it because it can be in edges_list_post
        return dict(my_histogram)

    
    def compute_block_histogram_per_block(self, dropped_nodes=set()):
        if self.symb_tree.is_empty():
            return dict(), dict(), dict()
        
        blocks_histogram_post = dict()
        blocks_histogram_pre  = dict()
        root_histogram = self.__compute_block_histogram_per_block(
            self.symb_tree.root.children[0], blocks_histogram_post, blocks_histogram_pre, set(), set(), dropped_nodes)
        
        # calculate histogram pre
        for b in blocks_histogram_pre:
            visited = blocks_histogram_pre[b]
            new = dict()
            for node in visited:
                block_id = self.address_to_block[str(node.data.address)]
                insert_or_add(new, block_id, 1)
            blocks_histogram_pre[b] = new
        
        return root_histogram, blocks_histogram_post, blocks_histogram_pre
    
    def compute_coverage_loss_per_edge_black(self, dropped_edges=set()):
        res = list()
        root_hist, edges_hist, _ = self.compute_block_histogram_per_edge(dropped_edges)
        total_nodes, edges_node_drop, _ = self.compute_node_count_per_edge(dropped_edges)
        total_blocks = len(root_hist.keys())

        for edge in edges_hist:
            hist = edges_hist[edge]
            drop = edges_node_drop[edge]
            lost_blocks = 0
            for block_id in hist:
                if root_hist[block_id] - hist[block_id] == 0:
                    lost_blocks += 1
            res.append({
                "src": edge[0],
                "dst": edge[1],
                "coverage_loss": round(lost_blocks * 100.0 / total_blocks, 2),
                "tree_reduction": round(drop * 100.0 / total_nodes, 2)
            })

        return res

    def compute_coverage_loss_per_edge_white(self, dropped_edges=set()):
        res = list()
        root_hist, edges_hist_post, edges_hist_pre = self.compute_block_histogram_per_edge(dropped_edges)
        total_nodes, edges_node_kept_post, edges_node_kept_pre = self.compute_node_count_per_edge(dropped_edges)
        total_blocks = len(root_hist.keys())

        for edge in edges_hist_post:
            hist_post = edges_hist_post[edge]
            hist_pre  = edges_hist_pre[edge]
            
            blocks = set(hist_post.keys()).union(set(hist_pre.keys()))
            drop   = total_nodes - (edges_node_kept_post[edge] + edges_node_kept_pre[edge])
            
            lost_blocks = len(set(root_hist.keys()) - blocks)
            res.append({
                "src": edge[0],
                "dst": edge[1],
                "coverage_loss": round(lost_blocks * 100.0 / total_blocks, 2),
                "tree_reduction": round(drop * 100.0 / total_nodes, 2)
            })

        return res
    
    def compute_coverage_loss_per_block_black(self, dropped_edges=set()):
        res = list()
        root_hist, blocks_hist, _ = self.compute_block_histogram_per_block(dropped_edges)
        total_nodes, blocks_node_drop, _ = self.compute_node_count_per_block(dropped_edges)
        total_blocks = len(root_hist.keys())

        for block in blocks_hist:
            hist = blocks_hist[block]
            drop = blocks_node_drop[block]
            lost_blocks = 0
            for block_id in hist:
                if root_hist[block_id] - hist[block_id] == 0:
                    lost_blocks += 1
            res.append({
                "block_id": block,
                "coverage_loss": round(lost_blocks * 100.0 / total_blocks, 2),
                "tree_reduction": round(drop * 100.0 / total_nodes, 2)
            })

        return res    
    def compute_coverage_loss_per_block_white(self, dropped_edges=set()):
        res = list()
        root_hist, blocks_hist_post, blocks_hist_pre = self.compute_block_histogram_per_block(dropped_edges)
        total_nodes, blocks_node_kept_post, blocks_node_kept_pre = self.compute_node_count_per_block(dropped_edges)
        total_blocks = len(root_hist.keys())

        for block in blocks_hist_post:
            hist_post = blocks_hist_post[block]
            hist_pre  = blocks_hist_pre[block]
            
            blocks = set(hist_post.keys()).union(set(hist_pre.keys()))
            drop   = total_nodes - (blocks_node_kept_post[block] + blocks_node_kept_pre[block])
            
            lost_blocks = len(set(root_hist.keys()) - blocks)
            res.append({
                "block_id": block,
                "coverage_loss": round(lost_blocks * 100.0 / total_blocks, 2),
                "tree_reduction": round(drop * 100.0 / total_nodes, 2)
            })

        return res
    
    def compute_coverage_loss(self):
        edges_white  = self.compute_coverage_loss_per_edge_white()
        edges_black  = self.compute_coverage_loss_per_edge_black()
        blocks_white = self.compute_coverage_loss_per_block_white()
        blocks_black = self.compute_coverage_loss_per_block_black()

        return {
            "edges": {
                "white": edges_white,
                "black": edges_black
            },
            "blocks": {
                "white": blocks_white,
                "black": blocks_black
            }
        }
    
    @staticmethod
    def compute_fork_symbols(node):
        if len(node.children) <= 1:
            return list()
        
        symbols = set()
        for child in node.children:
            lwState = child.data
            if isinstance(lwState, list):
                lwState = lwState[0]
            sac = lwState.last_constr
            assert sac is not None

            for c in sac.all_objects:
                symbols = symbols.union(set(list(c.ast.variables)))
            
            indirect = extract_indirect_inputs(lwState.constraints, symbols)
            symbols = symbols.union(indirect)
        return list(symbols)
    
    def get_blocks_state(self, state):
        blocks = []
        for addr in state.block_addresses:
            if str(addr) in self.address_to_block:
                block_id = self.address_to_block[str(addr)]
                if block_id not in blocks:
                    blocks.append(block_id)
        return blocks
    
    def linearize_tree(self, simplify=True):
        dst = list()
        
        if simplify:
            tree = self.symb_tree.simplify()
        else:
            tree = self.symb_tree

        for node in tree.DFS():
            node_json = dict()
            if not isinstance(node.data, list):
                states = [node.data]
            else:
                states = node.data
            
            node_json["id"]        = node.id
            node_json["father_id"] = node.father_id
            node_json["blocks"]    = list()
            for state in states:
                assert isinstance(state, LightweightState)
                if str(state.address) not in self.address_to_block:
                    continue
                node_json["blocks"].extend(self.get_blocks_state(state))
            if not node_json["blocks"]:
                continue
            node_json["children"]  = list()
            for child in node.children:
                node_json["children"].append(child.id)
            node_json["fork_symbols"] = TreeAnalyzer.compute_fork_symbols(node)
            
            dst.append(node_json)
        return dst

    def to_json(self, struct, out_path):
        with open(out_path, "w") as fout:
            json.dump(struct, fout)
    
    def colors_to_csv(self, out_path, fork_or_visited):
        struct = None
        if fork_or_visited == "fork":
            struct = self.compute_forks()
        elif fork_or_visited == "visited":
            struct = self.compute_visited_basic_blocks()
        else:
            raise Exception("Invalid input")

        max_count = 0
        for el in struct:
            max_count = max_count if max_count >= el["count"] else el["count"]
        
        with open(out_path, "w") as fout:
            for el in struct:
                # trick. Block id = B_%addr%
                block_addr = hex(int(el["block"][2:]))
                count = el["count"]
                r, g, b = float_to_rgb(count / max_count)
                fout.write("%s,%d,%d,%d\n" % (block_addr, r, g, b))
