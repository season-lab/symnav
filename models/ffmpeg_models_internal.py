import angr
import math
from IPython import embed


class logMODEL(angr.SimProcedure):
        def run(self, el):
            if self.state.solver.symbolic(el):
                print("WARNING: log with symbolic data. Concretizing")
            el = self.state.solver.eval(el)
            return math.log(el)
        
        def get_addr(self):
            return 0x13028 + 0x400000
