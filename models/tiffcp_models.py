import angr

class getoptMODEL(angr.SimProcedure):
    # ad hoc model.
    def run(self, argc, argv, optstring, longindex):
        memory   = self.state.memory
        solver   = self.state.solver

        optint_p = 0x00608340  # ty ida
        optarg_p = 0x00608348  # ty ida

        flag_p   = 0x00608360  # too lazy to write a plugin. BSS address with no xref
        flag     = memory.load(flag_p, 1)
        assert not solver.symbolic(flag)
        if solver.eval(flag) == 1:
            return -1

        assert not solver.symbolic(argc) and solver.eval(argc) == 5
        opt_p = memory.load(argv + self.state.arch.bits//8).reversed
        assert not solver.symbolic(opt_p)
        opt_sw = memory.load(opt_p, 2)
        assert not solver.symbolic(opt_sw)
        assert solver.eval(opt_sw) == 0x2d70  # -p

        opt_p = memory.load(argv + 2*self.state.arch.bits//8).reversed
        assert not solver.symbolic(opt_p)
        opt_sw = memory.load(opt_p, 8)
        assert not solver.symbolic(opt_sw)
        assert solver.eval(opt_sw) == 0x7365706172617465

        memory.store(optarg_p, opt_p.reversed)
        memory.store(optint_p, solver.BVV(3, self.state.arch.bits).reversed)
        memory.store(flag_p, 1, 1)

        print("getopt:", opt_p)
        print()
        return ord("p")

class TIFFOpen(angr.SimProcedure):
    # struct TIFF{
    #     unsigned short tagIdentifier;
    #     unsigned short dataType;
    #     unsigned int numOfDataItems;
    #     unsigned int valueOfDataItem;
    # };

    def run(self, *args):
        pass