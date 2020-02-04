import angr
from angr_wrapper import SimConcretizationStrategyConcretizeUnlessJmp
from IPython import embed


def read_until_zero(state, address):
    r = b""
    while not state.solver.symbolic(state.memory.load(address, 1)) and \
          state.solver.eval(state.memory.load(address, 1)).to_bytes(1, 'little') != b"\x00":
        r += state.solver.eval(state.memory.load(address, 1)).to_bytes(1, 'little')
        address += 1
    if state.solver.symbolic(state.memory.load(address, 1)):
        r += b"__symbolic__"
    return r


class WSAStartupMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class WSAIoctlMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class __WSAFDIsSetMODEL(angr.SimProcedure):
    def run(self, *args):
        return

class gethostbynameMODEL(angr.SimProcedure):
    # typedef struct hostent {
    #     char  *h_name;        4
    #     char  **h_aliases;    4
    #     short h_addrtype;     2
    #     short h_length;       2
    #     char  **h_addr_list;  4
    # }
    def run(self, name, *args):
        if not self.state.solver.symbolic(name):
            print("gethostbyname(%s) called" % read_until_zero(self.state, name))
        else:
            print("gethostbyname(%s) called" % str(name))
        
        hostent_star = self.state.heap.allocate(16)
        
        hname_star = self.state.heap.allocate(6)
        self.state.memory.store(hname_star, b"dummy\x00")
        self.state.memory.store(hostent_star, hname_star)

        h_aliases = self.state.heap.allocate(4)
        self.state.memory.store(h_aliases, b"\x00\x00\x00\x00")
        self.state.memory.store(hostent_star+4, h_aliases)

        # AF_INET
        # http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
        self.state.memory.store(hostent_star+8, b"\x02")
        
        self.state.memory.store(hostent_star+10, b"\x02")
        
        h_addr_list = self.state.heap.allocate(8)
        addr1 = self.state.heap.allocate(4)
        self.state.memory.store(h_addr_list, addr1)
        self.state.memory.store(h_addr_list + 4, b"\x00000000")
        self.state.memory.store(addr1, b"\x7f\x00\x00\x01")  # 127.0.0.1
        self.state.memory.store(hostent_star+12, h_addr_list)
        
        return hostent_star

class htonsMODEL(angr.SimProcedure):
    def run(self, to_convert):
        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert[15:0].reversed.zero_extend(len(to_convert) - 16)
        else:
            return to_convert

class socketMODEL(angr.SimProcedure):
    def run(self, domain, typ, protocol):
        conc_domain = self.state.solver.eval(domain)
        conc_typ = self.state.solver.eval(typ)
        conc_protocol = self.state.solver.eval(protocol)

        if self.state.posix.uid != 0 and conc_typ == 3: # SOCK_RAW
            return self.state.libc.ret_errno('EPERM')

        nonce = self.state.globals.get('socket_counter', 0) + 1
        self.state.globals['socket_counter'] = nonce
        fd = self.state.posix.open_socket(('socket', conc_domain, conc_typ, conc_protocol, nonce))
        return fd

class connectMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class ioctlsocketMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class setsockoptMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class selectMODEL(angr.SimProcedure):
    def run(self, nfds, readfds, writefds, exceptfds, timeout): # pylint: disable=unused-argument
        return 1

class sendMODEL(angr.SimProcedure):
    def run(self, fd, src, length, flags):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        send_succeeded = simfd.write(src, length)  # if send succeeds
        return send_succeeded

class recvMODEL(angr.SimProcedure):
    def run(self, fd, dst, length, flags):

        assert not self.state.solver.symbolic(dst)

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            print("WARNING. SOCKET NOT VALID")
            exit()
            return -1

        l = self.state.solver.eval(length)
        if self.state.solver.symbolic(length):
            if l > 100:
                l = 6
            self.state.solver.add(length == l)

            # fire address_concretization event. Intercepted by AngrWrapper
            self.state._inspect(
                'address_concretization',
                angr.BP_AFTER,
                address_concretization_expr=length,
                address_concretization_strategy=SimConcretizationStrategyConcretizeUnlessJmp(),
                address_concretization_action=None,
                address_concretization_memory=None,
                address_concretization_add_constraints=None,
                address_concretization_result=None
            )

        if hasattr(self.state, "angr_wrapper"):
            data = self.state.solver.BVS('recv#%d' % self.state.angr_wrapper.recv_count, l*8)
            self.state.angr_wrapper.recv_inc()
        else:
            raise Exception("NOT HERE")
            data = self.state.solver.BVS('recv', l*8)

        self.state.memory.store(dst, data)

        return l

class closesocketMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0

class shutdownMODEL(angr.SimProcedure):
    def run(self, *args):
        return 0