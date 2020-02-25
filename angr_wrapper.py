import sys
import angr
import json
import time
import pickle
import claripy
from analyses.tree_analyzer import TreeAnalyzer
from analyses.tree_pruner import TreePruner
from analyses.symbtree_builder import (
    SymbtreeBuilder, LightweightState
)
from collections import namedtuple
from utility import util
from IPython import embed

Symbol = namedtuple("Symbol", ["id", "creation", "claripy_obj", "node_id", "block_id", "category"])

class SimConcretizationStrategyConcretizeUnlessJmp(angr.concretization_strategies.SimConcretizationStrategy):
    """
    Concretization strategy that concretize the address unless it is the destination of a jump.
    """

    def __init__(self, **kwargs):
        self.conc = True
        super(SimConcretizationStrategyConcretizeUnlessJmp, self).__init__(**kwargs)

    def _concretize(self, memory, addr):
        opcode = memory.load(memory.state.regs.ip, 1)
        # symbolic instruction? This definitely shouldn't happen
        assert not memory.state.solver.symbolic(opcode)
        opcode = memory.state.solver.eval(opcode)

        if opcode != 255:  # it is not a jump
            self.conc = True
            return [self._any(memory, addr)]
        # it is a jump. Concretize up to 1024 different values
        self.conc = False
        return self._eval(memory, addr, 1024)


class AngrWrapperPlugin(angr.SimStatePlugin):
    def __init__(self):
        super(AngrWrapperPlugin, self).__init__()
        self.recv_count = 0
        self.flag       = False
    
    def recv_inc(self):
        self.recv_count += 1

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        res = AngrWrapperPlugin()
        res.recv_count = self.recv_count
        return res


class AngrWrapper(object):
    def __init__(self, project, address_to_block, pickle_state=None, starting_state=None, concretize_addresses=False):
        self.project          = project           # angr project
        self.entry_state      = None              # entry state
        self.address_to_block = address_to_block  # file json which maps addresses to blocks
        self.smgr             = None              # simulation manager
        self.stb              = None              # simbolic tree builder
        self.symbols          = dict()            # symbol -> Symbol namedtuple
        self.concretized_symb = set()             # set of symbols that have been concretized
        self.tree_analyzer    = None              # tree analyzer (paths, forks, ...)
        self.tree_pruner      = None              # tree pruner

        if starting_state is None:
            if pickle_state is None:
                self.entry_state = self.project.factory.entry_state()
                self.entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                self.entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            else:
                self.entry_state = pickle.load(pickle_state)
        else:
            self.entry_state = starting_state
        
        # very very inefficient in terms of memory consumption
        # self.entry_state.options.add(angr.options.EFFICIENT_STATE_MERGING)
        if not hasattr(self.entry_state, 'angr_wrapper'):
            self.entry_state.register_plugin('angr_wrapper', AngrWrapperPlugin())
        self.entry_state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=self.symbol_creation)
        # not the correct way of doing this. There is another way?
        self.entry_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=self.symbol_concretization)
        if concretize_addresses:
            self.entry_state.memory.read_strategies[0] = SimConcretizationStrategyConcretizeUnlessJmp()

        self.smgr = self.project.factory.simulation_manager(self.entry_state)
        self.smgr.stashes['avoid'] = list()

        self.stb = SymbtreeBuilder(self.address_to_block)
        self.stb.update(self.entry_state)

        self.tree_analyzer = TreeAnalyzer(self.stb.tree, self.address_to_block, self)
        self.tree_pruner   = TreePruner(self.stb.tree, self.address_to_block, self.symbols)
    
    def filter_fun(self, avoid_blocks, avoid_edges):
        avoid_blocks = set(avoid_blocks) if avoid_blocks else set()
        avoid_edges  = set(avoid_edges)  if avoid_edges  else set()
        def f(state):
            if state.addr in avoid_blocks:
                return 'avoid'
            if not state.history.parent:
                return 'active'
            parent_id = LightweightState.hash_from_history(state.history.parent)
            parent = self.stb.tree.get_by_id(parent_id).data
            if (parent.address, state.addr) in avoid_edges:
                print("avoid edge")
                return 'avoid'
            return 'active'
        return f
    
    def init_run(self):
        should_exit = False
        while (
            len(self.smgr.active) == 1
        ):
            self.smgr.step()
            for state in self.smgr.active:
                self.stb.update(state)
                if state.angr_wrapper.flag:
                    should_exit = True
            if should_exit:
                break
    
    def run(
            self, 
            timer, 
            time_treshold=None, 
            mem_treshold=None, 
            avoid_blocks=None, 
            avoid_edges=None, 
            target=None, 
            print_mem_time_usage=True,
            print_dbg=False, 
            print_ext=False
        ):
        assert timer >= 0

        start_time   = time.time()
        current_time = time.time()
        current_mem  = util.get_memory_usage()

        filter_func = self.filter_fun(avoid_blocks, avoid_edges)

        tick = 0
        should_exit = False
        while (
            self.smgr.active and timer > 0 and 
            (not time_treshold or (current_time - start_time < time_treshold)) and
            (not mem_treshold or (current_mem < mem_treshold))  # mem_threshold in MB
        ):
            self.smgr.step(filter_func=filter_func)

            for state in self.smgr.active:
                self.stb.update(state)
                if print_ext and self.project.is_hooked(state.addr):
                    for el in state.callstack: 
                        print(hex(el.ret_addr), "<- ", end="")
                    print(str(self.project.hooked_by(state.addr)))
                    print()
                if state.addr == target or state.angr_wrapper.flag:
                    should_exit = True
            if should_exit:
                return
    
            if print_dbg:
                print(util.up(1), end="")
                if self.smgr.active:
                    states_str = str(self.smgr.active[0]) + "\t" + (str(self.smgr.active[1]) if len(self.smgr.active) > 1 else "")
                else:
                    states_str = ""
                print(str(tick) + " " + str(self.smgr) + "\t" + states_str)
                tick  += 1

            timer -= 1
            current_time = time.time()
            current_mem  = util.get_memory_usage()

            if print_mem_time_usage:
                print("mem: %s MB\t time: %.2f s" % (str(current_mem), current_time - start_time))
                print(util.up(1), end="")
    
    def symbol_concretization(self, state):
        expression     = state.inspect.address_concretization_expr
        concr_strategy = state.inspect.address_concretization_strategy
        if (
            isinstance(concr_strategy, angr.concretization_strategies.any.SimConcretizationStrategyAny) or
            (isinstance(concr_strategy, SimConcretizationStrategyConcretizeUnlessJmp) and concr_strategy.conc)
        ):
            symbols = set(expression.variables)
            assert set(self.symbols.keys()).intersection(symbols) == symbols
            self.concretized_symb = self.concretized_symb.union(symbols)
    
    def infer_category(self, address, symb_name):
        category = "UNKNOWN"
        if self.project.is_hooked(address):
            model_str = str(self.project.hooked_by(address))
            if "recv" in model_str:
                category = "NETWORK"
            elif "read" in model_str:
                category = "FILE_SYSTEM"
        if "uninitialized" in symb_name:
            category = "MEMORY"
        # category="COMMAND_LINE" -> set manually
        return category
    
    def find_cfg_block(self, state):
        addr = state.addr
        callstack = list(state.callstack)
        i = 0
        while self.project.is_hooked(addr):
            addr = callstack[i].call_site_addr
            i += 1
        assert addr != 0
        return self.tree_analyzer.address_to_block[str(addr)]
    
    # called when a new symbol is created
    def symbol_creation(self, state):
        symbol_name = state.inspect.symbolic_name
        symbol_expr = state.inspect.symbolic_expr
        address     = state.addr
        creation    = hex(address)
        node_id     = LightweightState.hash_from_state(state)
        block_id    = self.find_cfg_block(state)
        category    = self.infer_category(address, symbol_name)
        if self.project.is_hooked(state.addr):
            creation = str(self.project.hooked_by(state.addr)).replace("MODEL", "")
        assert symbol_name not in self.symbols
        self.symbols[symbol_name] = Symbol(
            symbol_name, creation, symbol_expr, node_id, block_id, category
        )
    
    def commit_filter(self, new_tree, constraints=[]):
        filtered_symbols = AngrWrapper.filter_symbols(self.symbols, new_tree)
        self.stb.tree                = new_tree
        self.tree_analyzer.symb_tree = new_tree
        self.tree_pruner.symb_tree   = new_tree
        self.symbols                 = filtered_symbols
        self.concretized_symb        = set(self.symbols.keys()).intersection(self.concretized_symb)

        tmp = list()
        for leaf in new_tree.leaves():
            if not leaf.data:
                # empty tree
                return
            if not util.check_weakref(leaf.data.state_weakref):
                continue
            # this return self. There is a better way?
            strongref_state = leaf.data.state_weakref._get_strongref()
            strongref_state.add_constraints(*constraints)
            if strongref_state in self.smgr.avoid:
                continue
            tmp.append(strongref_state)
        self.smgr.stashes['active'] = tmp

    @staticmethod
    def filter_symbols(symbols, tree):
        res = dict()
        for symbol_name in symbols:
            symbol = symbols[symbol_name]
            if tree.contains(symbol.node_id):
                res[symbol_name] = symbol
        return res
    
    def get_concretized_symbols_from_filter(self, filter_opts):
        res = set()
        for opt in filter_opts:
            if opt["type"] == "limit_symbol" and opt["symbol_id"] in self.concretized_symb:
                res.add(opt["symbol_id"])
        return res
    
    def get_filter_constraints(self, filter_opts):
        res = list()
        for opt in filter_opts:
            if opt["type"] == "limit_symbol":
                claripy_obj = self.symbols[opt["symbol_id"]].claripy_obj
                expr = claripy.And(
                    claripy.SGE(claripy_obj, int(opt["min"])),
                    claripy.SLE(claripy_obj, int(opt["max"]))
                )
                res.append(expr)
        return res
    
    def apply_filters(self, filter_opts, commit=False):
        res = self.get_concretized_symbols_from_filter(filter_opts)
        for symbol_id in res:
            print("WARNING: %s has been concretized during the symbolic execution. It might be necessary to rerun the exploration" % symbol_id)
        new_tree        = self.tree_pruner.filter_tree(filter_opts)
        tree_anal       = TreeAnalyzer(new_tree, self.address_to_block, self)
        tree_build      = SymbtreeBuilder(self.address_to_block, new_tree)
        new_cl_dict     = tree_anal.compute_coverage_loss()
        new_tree_dict   = tree_anal.linearize_tree()
        new_symb_dict   = self.compute_symbols_dict(
            AngrWrapper.filter_symbols(self.symbols, new_tree), tree_build)
        new_leaves_dict = tree_anal.compute_leaves_info()

        if commit:
            constraints = self.get_filter_constraints(filter_opts)
            self.commit_filter(new_tree, constraints)
        return {
            "symbolic_tree": new_tree_dict, 
            "coverage_loss": new_cl_dict, 
            "symbols":       new_symb_dict,
            "leaves":        new_leaves_dict
        }

    def dump_symbtree(self, out_path):
        res = self.tree_analyzer.linearize_tree()
        self.tree_analyzer.to_json(res, out_path)
    
    def dump_forks(self, out_path):
        res = self.tree_analyzer.compute_forks()
        self.tree_analyzer.to_json(res, out_path)
    
    def dump_block_frequencies(self, out_path):
        res = self.tree_analyzer.compute_visited_basic_blocks()
        self.tree_analyzer.to_json(res, out_path)

    def dump_leaves_info(self, out_path):
        res = self.tree_analyzer.compute_leaves_info()
        self.tree_analyzer.to_json(res, out_path)
    
    def dump_coverage_loss(self, out_path):
        res = self.tree_analyzer.compute_coverage_loss()
        self.tree_analyzer.to_json(res, out_path)
    
    def compute_symbols_dict(self, symbols, stb=None):
        res = list()

        if stb is None:
            stb = self.stb
        _, node_id_to_merged_id = stb.simplify_symbtree()
        for symbol_name in symbols:
            symbol = symbols[symbol_name]
            d = dict()
            d["id"]                = symbol.id
            d["creation_node_id"]  = node_id_to_merged_id[symbol.node_id] if symbol.node_id != 0 else 0
            d["creation_block_id"] = symbol.block_id
            d["creation_info"]     = symbol.creation
            d["size"]              = symbol_name[symbol_name.rfind("_")+1:]
            d["category"]          = symbol.category
            res.append(d)
        return res
    
    def dump_symbols(self, out_path):
        res = self.compute_symbols_dict(self.symbols)

        with open(out_path, "w") as fout:
            json.dump(res, fout)
