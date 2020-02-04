import claripy

class AngrStateStub(object):
    def __init__(self):
        self.solver = claripy.Solver()

class StateStub(object):
    def __init__(self, address):
        self.address         = address
        self.block_addresses = [address]
        self.state_weakref   = AngrStateStub()
    
    def __str__(self):
        return "<StateStub %s>" % str(self.address)
    
    def __repr__(self):
        return self.__str__()

def build_tree(tree_dict, tree, father_id):
    fid      = father_id
    cid      = tree_dict["id"]
    block    = tree_dict["block"]
    children = tree_dict["children"]
    
    s = StateStub(block)
    if "constraints" in tree_dict:
        for c in tree_dict["constraints"]:
            s.state_weakref.solver.add(c)
    tree.add_child(cid, s, fid)
    for child in children:
        build_tree(child, tree, cid)

def build_identity_dict(block_set):
    res = dict()
    for el in block_set:
        res[el] = el
    return res

class bcolors(object):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def fail(s):
    return bcolors.FAIL + "FAIL:\t\t" + s + bcolors.ENDC


def success(s):
    return bcolors.OKGREEN + "SUCCESS:\t" + s + bcolors.ENDC

def do_test(test):
    try:
        test()
        print(success("%s" % test.__name__))
    except:
        print(fail("%s" % test.__name__))
