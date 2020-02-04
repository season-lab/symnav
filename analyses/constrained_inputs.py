import angr

def extract_indirect_inputs(constraints, direct_inputs):

    res = set()
    for constraint in constraints:
        variables = constraint.variables
        intersection = variables.intersection(direct_inputs)
        if len(intersection) > 0:
            for v in variables:
                if v not in direct_inputs:
                    res.add(v)

    return res


def extract_direct_inputs(constraints):
    res = set()
    for constraint in constraints:
        for v in constraint.variables:
            res.add(v)

    return res


def adding_constraint(state):
    constraints = state.inspect.added_constraints
    direct_inputs = extract_direct_inputs(constraints)
    indirect_inputs = extract_indirect_inputs(state.solver.constraints, direct_inputs)

    print("\nState at {}".format(state.regs.ip))
    print("Adding constraints: {}".format(constraints))
    print("Direct inputs: {}".format(direct_inputs))
    print("Indirect inputs: {}\n".format(indirect_inputs))


def test():
    binary = "data/branch"
    start = 0x40050d
    end = 0x40054b
    avoid = [0x40052c, 0x400552]

    project = angr.Project(binary, auto_load_libs=False)
    state = project.factory.blank_state(addr=start)

    # state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    # state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    state.inspect.b('constraints', when=angr.BP_BEFORE, action=adding_constraint)

    x = state.regs.edi
    y = state.regs.esi

    #state.add_constraints(x == y)

    manager = project.factory.simulation_manager(state)

    while len(manager.active) > 0:

        print(manager)

        manager.explore(n=1, find=end, avoid=avoid)

        if hasattr(manager, 'found') and len(manager.found) > 0:
            print("Reached target!")
            state = manager.found[0]
            print("x={} y={}".format(state.solver.eval(x), state.solver.eval(y)))
            print
            break


if __name__ == '__main__':
    test()
