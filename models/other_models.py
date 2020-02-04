import archinfo
import angr
from IPython import embed


class InitializeCriticalSectionMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class EnterCriticalSectionMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class LeaveCriticalSectionMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class timeMODEL(angr.SimProcedure):
    def run(self, time_star, *args):
        assert not self.state.solver.symbolic(time_star)
        self.state.memory.store(time_star, b"\x00\x00\x00\x00")
        return 0

class SleepMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class getenvMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class GetUserNameAMODEL(angr.SimProcedure):
    def run(self, lpBuffer, pcbBuffer):
        assert not self.state.solver.symbolic(lpBuffer)
        assert not self.state.solver.symbolic(pcbBuffer)
        self.state.memory.store(lpBuffer, b"user\x00", 5)
        self.state.memory.store(pcbBuffer, 5, endness=archinfo.Endness.LE)
        return 1

class gethostnameMODEL(angr.SimProcedure):
    def run(self, name, len):
        assert not self.state.solver.symbolic(name)
        assert not self.state.solver.symbolic(len)
        assert self.state.solver.eval(len)>4
        self.state.memory.store(name, b"user\x00", 5)
        return 0

class GetComputerNameAMODEL(angr.SimProcedure):
    def run(self, lpBuffer, nSize):
        assert not self.state.solver.symbolic(lpBuffer)
        assert not self.state.solver.symbolic(nSize)
        self.state.memory.store(lpBuffer, b"pc\x00", 3)
        self.state.memory.store(nSize, 3, endness=archinfo.Endness.LE)
        return 1

class GetModuleFileNameAMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class LoadLibraryAMODEL(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].string.concrete
        return self.load(lib)

    def load(self, lib):
        lib = lib.decode("ASCII")
        if '.' not in lib:
            lib += '.dll'
        loaded = self.project.loader.dynamic_load(lib)
        if loaded is None:
            return 0

        # Add simprocedures
        for obj in loaded:
            self.register(obj)

        return self.project.loader.find_object(lib).mapped_base

    def register(self, obj): # can be overridden for instrumentation
        self.project._register_object(obj)

class GetVersionExAMODEL(angr.SimProcedure):
    def run(self, lpVersionInformation):
        return 0

class _vsnprintfMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class GetSystemInfoMODEL(angr.SimProcedure):
    def run(self, lpSystemInfo):
        return

class RegOpenKeyExAMODEL(angr.SimProcedure):
    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):
        assert not self.state.solver.symbolic(phkResult)
        self.state.memory.store(phkResult, 0xdeadbeef, endness=archinfo.Endness.LE)
        return 0  # ERROR_SUCCESS

class RegQueryValueExAMODEL(angr.SimProcedure):
    def run(self, hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
        assert not self.state.solver.symbolic(lpType)
        assert not self.state.solver.symbolic(lpData)
        assert not self.state.solver.symbolic(lpcbData)
        self.state.memory.store(lpType, 1, endness=archinfo.Endness.LE)  # REG_SZ
        self.state.memory.store(lpData, b"a_string\x00", 9)
        self.state.memory.store(lpcbData, 9, endness=archinfo.Endness.LE)

class RegCloseKeyMODEL(angr.SimProcedure):
    def run(self, hKey):
        return 0
