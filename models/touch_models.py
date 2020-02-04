from IPython import embed
import archinfo
import time
import angr

class EnvPlugin(angr.SimStatePlugin):
    def __init__(self):
        super(EnvPlugin, self).__init__()
        self.env = dict()
    
    def getenv(self, var):
        if var in self.env:
            return self.env[var]
        else:
            return None
    
    def setenv(self, var, value, overwrite):
        if var not in self.env or overwrite:
            self.env[var] = value

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        res = EnvPlugin()
        res.env = dict(self.env)
        return res

class strrchrMODEL(angr.SimProcedure):
# Locate last occurrence of character in string
# Returns a pointer to the last occurrence of character in the C string str.
# The terminating null-character is considered part of the C string. Therefore, it can also be located to retrieve a pointer to the end of a string.
    def run(self, string_p, char):
        solver = self.state.solver
        memory = self.state.memory

        if solver.symbolic(string_p):
            print("WARNING: string is symbolic, concretizing")
            embed()
        string_p = solver.eval(string_p)
        char     = char.ast[7:0]
        
        MAX_LEN = 20
        print("strrchr: Constructing the ITE")
        
        cur_chr = memory.load(string_p, 1)
        analyzed_buckets = list()

        i = 0
        while True:
            if solver.symbolic(cur_chr) and i >= MAX_LEN:
                self.state.add_constraints(cur_chr == solver.BVV(0, 8))
                break
            if not solver.symbolic(cur_chr) and solver.eval(cur_chr) == 0:
                break

            current_off    = string_p + i
            current_el     = cur_chr
            current_bucket = list()
            for _, _, buck in analyzed_buckets:
                buck.append(char != current_el)

            i += 1
            analyzed_buckets.append((
                current_off, current_el, current_bucket
            ))
            cur_chr = memory.load(string_p + i, 1)
        
        res = solver.BVV(0, self.state.arch.bits)  # NULL is the default case
        for off, el, buck in analyzed_buckets:
            and_expr = el == char
            for cond in buck:
                and_expr = solver.And(and_expr, cond)
            res = solver.If(and_expr, off, res)
        
        res = solver.simplify(res)
        # print("strrchr:", res)
        # print()
        return res

class getopt_longMODEL(angr.SimProcedure):
    # ad hoc model.
    def run(self, argc, argv, optstring, longindex):
        memory   = self.state.memory
        solver   = self.state.solver
        optarg_p = 0x0060F0B8  # 0x0060dfb0

        flag_p   = 0x0060F0E8  # 0x0060e342  # too lazy to write a plugin. BSS address with no xref (r2, are u reliable?)
        flag     = memory.load(flag_p, 1)
        assert not solver.symbolic(flag)
        if solver.eval(flag) == 1:
            return -1

        assert not solver.symbolic(argc) and solver.eval(argc) >= 2
        opt_p = memory.load(argv + self.state.arch.bits//8).reversed
        assert not solver.symbolic(opt_p)
        opt_sw = memory.load(opt_p, 8)
        assert not solver.symbolic(opt_sw)
        assert solver.eval(opt_sw) == 0x272d2d646174653d  # '--date=

        cur_chr = memory.load(opt_p + 8, 1)

        MAX_LEN = 15
        i   = 0
        res = None
        while True:
            if solver.symbolic(cur_chr) and i >= MAX_LEN:
                self.state.add_constraints(cur_chr == solver.BVV(39, 8))  # apex (')
                break
            if not solver.symbolic(cur_chr) and (solver.eval(cur_chr) == 39 or solver.eval(cur_chr) == 0):
                break

            if res is None:
                res = cur_chr
            else:
                res = res.concat(cur_chr)

            i += 1
            cur_chr = memory.load(opt_p + 8 + i, 1)

        if res is None:
            res = solver.BVV(0, 8)
        else:
            res = res.concat(solver.BVV(0, 8)) 
        
        string_p = self.state.heap.allocate(res.size())
        memory.store(string_p, res)
        memory.store(optarg_p, solver.BVV(string_p, self.state.arch.bits).reversed)
        memory.store(flag_p, 1, 1)
        # print("strrchr:", res)
        # print()
        return 100

class clock_gettimeMODEL(angr.SimProcedure):
    def run(self, which_clock, timespec_ptr):
        if not self.state.solver.is_true(which_clock == 0):
            raise angr.errors.SimProcedureError("clock_gettime doesn't know how to deal with a clock other than CLOCK_REALTIME")

        if self.state.solver.is_true(timespec_ptr == 0):
            return -1

        flt = 0xdeadbeef
        result = {'tv_sec': int(flt), 'tv_nsec': int(flt * 1000000000)}

        self.state.mem[timespec_ptr].struct.timespec = result
        return 0

class localtimeMODEL(angr.SimProcedure):
    # struct tm:
    # int    tm_sec   seconds [0,61]
    # int    tm_min   minutes [0,59]
    # int    tm_hour  hour [0,23]
    # int    tm_mday  day of month [1,31]
    # int    tm_mon   month of year [0,11]
    # int    tm_year  years since 1900
    # int    tm_wday  day of week [0,6] (Sunday = 0)
    # int    tm_yday  day of year [0,365]
    # int    tm_isdst daylight savings flag

    def run(self, sec_p):
        solver = self.state.solver
        memory = self.state.memory

        assert not solver.symbolic(sec_p)
        sec  = memory.load(sec_p, self.state.arch.bits//8)
        assert not solver.symbolic(sec)
        
        tm_p = self.state.heap.allocate(36)
        # 5 nov 1955. Doc would be proud
        memory.store(tm_p     , 0,   4, endness=archinfo.Endness.LE)   # seconds
        memory.store(tm_p + 4 , 0,   4, endness=archinfo.Endness.LE)   # minutes
        memory.store(tm_p + 8 , 6,   4, endness=archinfo.Endness.LE)   # hour
        memory.store(tm_p + 12, 5,   4, endness=archinfo.Endness.LE)   # day
        memory.store(tm_p + 16, 6,   4, endness=archinfo.Endness.LE)   # month
        memory.store(tm_p + 20, 55,  4, endness=archinfo.Endness.LE)   # years
        memory.store(tm_p + 24, 6,   4, endness=archinfo.Endness.LE)   # day of the week (saturday)
        memory.store(tm_p + 28, 308, 4, endness=archinfo.Endness.LE)   # day of year
        memory.store(tm_p + 32, 0,   4, endness=archinfo.Endness.LE)   # daylight

        return solver.BVV(tm_p, self.state.arch.bits)

class getenvMODEL(angr.SimProcedure):
    def run(self, varname_p):
        assert hasattr(self.state, "env")
        assert not self.state.solver.symbolic(varname_p)

        i = 0
        varname = ""
        while True:
            c = self.state.memory.load(varname_p + i, 1)
            assert not self.state.solver.symbolic(c)
            c = self.state.solver.eval(c)
            if c == 0:
                break
            varname += chr(c)
            i += 1
        
        res = self.state.env.getenv(varname)
        if not res:
            return 0
        
        ptr = self.state.heap.allocate(len(res))
        self.state.memory.store(ptr, bytes(res, "ascii"), len(res))
        return ptr

class setenvMODEL(angr.SimProcedure):
    def run(self, varname_p, value_p, overwrite):
        assert hasattr(self.state, "env")
        assert not self.state.solver.symbolic(varname_p)
        assert not self.state.solver.symbolic(value_p)
        assert not self.state.solver.symbolic(overwrite)

        i = 0
        varname = ""
        while True:
            c = self.state.memory.load(varname_p + i, 1)
            assert not self.state.solver.symbolic(c)
            c = self.state.solver.eval(c)
            if c == 0:
                break
            varname += chr(c)
            i += 1
        
        i = 0
        value = ""
        while True:
            c = self.state.memory.load(value_p + i, 1)
            # assert not self.state.solver.symbolic(c)
            if self.state.solver.symbolic(c):
                return -1  # unhandled
            c = self.state.solver.eval(c)
            if c == 0:
                break
            value += chr(c)
            i += 1
        value += "\x00"
        
        self.state.env.setenv(
            varname, 
            value, 
            self.state.solver.eval(overwrite) > 0
        )
        return 0

class freeMODEL(angr.SimProcedure):
    def run(self, ptr):
        # print("free:", ptr)
        # print()

        ptr_masked = (ptr & 0xffffffffffff0000)
        rsp_masked = (self.state.regs.rsp & 0xffffffffffff0000)
        if self.state.solver.satisfiable([ptr_masked == rsp_masked]):
            assert hasattr(self.state, 'angr_wrapper')
            self.state.angr_wrapper.flag = True

class setlocaleMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0  # the return value is not used

class bindtextdomainMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0  # the return value is not used

class textdomainMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0  # the return value is not used

class __cxa_atexitMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0  # the return value is not used
