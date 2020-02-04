import angr
from IPython import embed

allocations = list()

class isattyMODEL(angr.SimProcedure):
    def run(self, *args):
        return 1

class av_mallocMODEL(angr.SimProcedure):
    def run(self, size):
        global allocations
        if self.state.solver.symbolic(size):
            print("WARNING: symbolic size")
            size = self.state.solver.eval(size)
        
        addr = self.state.heap.allocate(size)
        allocations.append((addr, size))
        return addr

class av_malloczMODEL(angr.SimProcedure):
    def run(self, size):
        global allocations
        if self.state.solver.symbolic(size):
            print("WARNING: symbolic size")
        size = self.state.solver.eval(size)
        
        addr = self.state.heap.allocate(size)
        self.state.memory.store(addr, b"\x00"*size, size)
        allocations.append((addr, size))
        return addr

class reallocMODEL(angr.SimProcedure):
    def run(self, ptr, size):
        if size.symbolic:
            try:
                size_int = self.state.solver.max(size, extra_constraints=(size < self.state.libc.max_variable_size,))
            except angr.errors.SimSolverError:
                size_int = self.state.solver.min(size)
            self.state.add_constraints(size_int == size)
        else:
            size_int = self.state.solver.eval(size)

        addr = self.state.heap.allocate(size_int)

        if self.state.solver.eval(ptr) != 0:
            for i in range(size_int):
                v = self.state.memory.load(ptr + i, 1)
                self.state.memory.store(addr + i, v, 1)

        allocations.append((addr, size_int))
        return addr

class open64MODEL(angr.SimProcedure):
    def run(self, p_addr, flags, mode):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        fd = self.state.posix.open(path, flags)
        if fd is None:
            return -1
        return fd

class lseek64MODEL(angr.SimProcedure):

    def run(self, fd, seek, whence):

        if self.state.solver.symbolic(whence):
            err = "Symbolic whence is not supported in lseek syscall."
            raise angr.errors.SimPosixError(err)

        whence = self.state.solver.eval(whence)
        if whence == 0:
            whence_str = 'start'
        elif whence == 1:
            whence_str = 'current'
        elif whence == 2:
            whence_str = 'end'
        else:
            return -1

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        success = simfd.seek(seek, whence_str)
        if self.state.solver.is_false(success):
            return -1
        return self.state.solver.If(success, simfd.tell(), -1)

class __fprintf_chkMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class selectMODEL(angr.SimProcedure):
    def run(self, nfds, readfds, writefds, exceptfds, timeout): # pylint: disable=unused-argument
        return 1
