class FuncRef(object):
    def __init__(self, func_addr, code_id, ref_type):
        assert isinstance(func_addr, int)
        assert isinstance(code_id,   int)
        assert ref_type in { "CALL", "DATA", "INVALID" }

        self.func_addr = func_addr
        self.code_id   = code_id
        self.ref_type  = ref_type
    
    def __hash__(self):
        return hash((
            self.func_addr,
            self.code_id
        ))
    
    def __eq__(self, other):
        if not isinstance(other, FuncRef):
            return False
        return self.func_addr == other.func_addr and self.code_id == other.code_id
    
    def to_json(self):
        res  = "{"
        res += '"function": "%s", ' % ("F_" + str(self.func_addr))
        res += '"code_id":  %d, '   % self.code_id
        res += '"type": "%s"'       % self.ref_type
        res += "}"
        return res

class Block(object):
    def __init__(self, address, function, successors, func_refs, code):
        assert isinstance(address,       int)
        assert isinstance(function, Function)
        assert isinstance(successors,    set)
        assert isinstance(func_refs,     set)
        assert isinstance(code,         list)
        self.address    = address
        self.function   = function
        self.successors = successors
        self.func_refs  = func_refs
        self.code       = code
    
    def to_json(self):
        res  = "{"
        res += '"id": "%s", '       % self.get_id()
        res += '"address": "%s", '  % hex(self.address)
        res += '"function": "%s", ' % self.function.get_id()
        res += '"successors": %s, ' % str(list(map(lambda x: 'B_' + str(x), self.successors))).replace("'", '"')
        res += '"code": %s, '       % str(self.code).replace("'", '"')
        res += '"func_refs": ['
        flag = True
        for func_ref in self.func_refs:
            assert isinstance(func_ref, FuncRef)
            if flag:
                flag = False
            else:
                res += ", "
            res += func_ref.to_json()
        res += "]"
        res += "}"
        return res

    def get_id(self):
        return "B_" + str(self.address)

class Function(object):
    def __init__(self, address, name, entrypoint, blocks, callers, callees):
        assert isinstance(address,    int)
        assert isinstance(name,       str)
        assert isinstance(entrypoint, int)
        assert isinstance(blocks,    dict)
        assert isinstance(callers,    set)
        assert isinstance(callees,    set)
        self.address    = address
        self.name       = name
        self.entrypoint = entrypoint
        self.blocks     = blocks
        self.callers    = callers
        self.callees    = callees
    
    def to_json(self):
        res  = "{"
        res += '"id": "%s", '      % self.get_id()
        res += '"address": "%s", ' % hex(self.address)
        res += '"entry": "%s", '   % ("B_" + str(self.entrypoint))
        res += '"name": "%s", '    % self.name
        res += '"callees": %s, '   % str(list(map(lambda x: 'F_' + str(x), self.callees))).replace("'", '"')
        res += '"callers": %s, '   % str(list(map(lambda x: 'F_' + str(x), self.callers))).replace("'", '"')
        res += '"blocks": ['
        flag = True
        for address in self.blocks:
            if flag:
                flag = False
            else:
                res += ", "
            block = self.blocks[address]
            res += block.to_json()
        res += "]"
        res += "}"
        return res

    def get_id(self):
        return "F_" + str(self.address)

class CFG(object):
    def __init__(self, entrypoint, functions):
        assert isinstance(entrypoint, int)
        assert isinstance(functions, dict)
        self.entrypoint = entrypoint
        self.functions  = functions
    
    def to_json(self):
        res  = "{"
        res += '"id": "%s", '     % self.get_id()
        res += '"entry": "%s", '  % ("F_" + str(self.entrypoint))
        res += '"functions": ['
        flag = True
        for address in self.functions:
            if flag:
                flag = False
            else:
                res += ", "
            res += self.functions[address].to_json()
        res += "]"
        res += "}"
        return res

    def get_id(self):
        return "G_" + str(self.entrypoint)
