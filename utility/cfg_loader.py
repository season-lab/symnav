from IPython import embed
from utility.cfg import Block, Function, CFG, FuncRef
import r2pipe
import json
import os


class R2CFGLoader(object):
    def __init__(self, binary, base=None):
        self.binary        = binary
        self.base          = base
        self.r2            = None
        self.functions     = None
        self.entry         = None
        self.cfg           = None
        self.addr_to_block = None

    def process(self):
        if self.r2:
            return

        if self.base:
            self.r2 = r2pipe.open(self.binary, flags=['-B %s' % hex(self.base)])
        else:
            self.r2 = r2pipe.open(self.binary)

        self.r2.cmd("aaa")
        self.entry = self.r2.cmdj("iej")[0]["vaddr"]

    def get_functions(self):
        if not self.r2:
            self.process()
        if self.functions:
            return self.functions

        functions = self.r2.cmd("afl").strip().split("\n")
        self.functions = dict()
        for function in functions:
            splitted = function.split(" ")
            splitted = list(filter(lambda x: x, splitted))
            address  = splitted[0]
            name     = splitted[-1]
            self.functions[int(address, 16)] = name
        return self.functions

    @staticmethod
    def remove_invalid_successors(blocks):
        for block_id in blocks:
            block = blocks[block_id]
            new_successors = set()
            for successor_addr in block.successors:
                successor_id = "B_" + str(successor_addr)
                if successor_id in blocks:
                    new_successors.add(successor_addr)
            block.successors = new_successors

    def get_function_cfg(self, address):
        if not self.r2:
            self.process()
        if not self.functions:
            self.get_functions()

        self.r2.cmd("s %s" % hex(address))
        function_cfg = self.r2.cmdj("agj")
        if len(function_cfg) == 0:
            print("WARNING: %s empty function!" % hex(address))
            return None
        if len(function_cfg) > 1:
            print("WARNING: more than one graph. Taking the first one")

        function_cfg = function_cfg[0]
        f = Function(
            function_cfg["offset"],  # address
            function_cfg["name"],    # name
            function_cfg["offset"],  # entrypoint
            dict(),                  # blocks [id -> block]
            set(),                   # callers [empty, for now]
            set()                    # callees
        )
        for block in function_cfg["blocks"]:
            successors = set()
            if "jump" in block:
                successors.add(block["jump"])
            if "fail" in block:
                successors.add(block["fail"])

            b = Block(
                block["offset"],    # address
                f,                  # function
                successors,         # successor(s)
                set(),              # function refs (if any)
                list()              # code (list of string)
            )
            code_index = 0
            for op in block["ops"]:
                if not op:
                    print("WARNING: %s empty op" % hex(block["offset"]))
                    continue
                if op["type"] == "invalid":
                    print("WARNING: %s invalid opcode" % hex(op["offset"]))
                    b.code.append(hex(op["offset"]) + " " + op["type"])
                else:
                    b.code.append(hex(op["offset"]) + " " + op["disasm"])
                if "refs" in op:
                    for ref in op["refs"]:
                        if ref["type"] == "CODE":
                            b.successors.add(ref["addr"])
                        if ref["type"] == "CALL":
                            addr     = ref["addr"]
                            ref_type = "CALL"
                            if addr not in self.functions:
                                ref_type = "INVALID"
                            b.func_refs.add(
                                FuncRef(
                                    addr,
                                    code_index,
                                    ref_type
                                )
                            )
                            f.callees.add(ref["addr"])
                        if ref["type"] == "DATA":
                            addr = ref["addr"]
                            if addr in self.functions:
                                b.func_refs.add(
                                    FuncRef(
                                        addr,
                                        code_index,
                                        "DATA"
                                    )
                                )
                code_index += 1

            f.blocks[b.get_id()] = b

        R2CFGLoader.remove_invalid_successors(f.blocks)
        return f

    @staticmethod
    def resolve_callers(cfg):
        callees = dict()
        for f_id in cfg.functions:
            f = cfg.functions[f_id]
            for callee in f.callees:
                if callee in callees:
                    callees[callee].add(f.address)
                else:
                    callees[callee] = set([f.address])

        for f_id in cfg.functions:
            f = cfg.functions[f_id]
            if f.address in callees:
                f.callers = callees[f.address]
        return cfg

    def get_cfg(self):
        if self.cfg:
            return self.cfg
        if not self.functions:
            self.get_functions()

        cfg = CFG(
            self.entry,
            dict()
        )
        for address in self.functions:
            f = self.get_function_cfg(address)
            if f is None:
                continue
            cfg.functions[address] = f

        self.cfg = R2CFGLoader.resolve_callers(cfg)
        return self.cfg

    def get_addr_to_block(self):
        if self.addr_to_block:
            return self.addr_to_block
        if not self.cfg:
            self.get_cfg()

        addr_to_block = dict()
        for f_address in self.cfg.functions:
            f = self.cfg.functions[f_address]
            for b_address in f.blocks:
                block = f.blocks[b_address]
                for code in block.code:
                    insn_address = int(code.split(" ")[0], 16)
                    if insn_address in addr_to_block:
                        print("WARNING: collision")
                        continue
                    addr_to_block[insn_address] = block.get_id()

        self.addr_to_block = addr_to_block
        return addr_to_block

def compute_cfg(binary, dest_path, base=None):
    dest_json = os.path.join(dest_path, "cfg.json")
    dest_dict = os.path.join(dest_path, "cfg_atb.json")

    cfg_loader = R2CFGLoader(binary, base)
    cfg = cfg_loader.get_cfg()
    with open(dest_json, "w") as out:
        out.write(cfg.to_json())

    addr_to_block = cfg_loader.get_addr_to_block()
    with open(dest_dict, 'w') as json_file:
        json.dump(addr_to_block, json_file)


if __name__=="__main__":
    cfg_loader = R2CFGLoader("../binaries/ffmpeg")
    cfg = cfg_loader.get_cfg()
    with open("../data/graph.json", "w") as out:
        out.write(cfg.to_json())

    addr_to_block = cfg_loader.get_addr_to_block()
    with open('../data/addr_to_block.json', 'w') as json_file:
        json.dump(addr_to_block, json_file)
    embed()
