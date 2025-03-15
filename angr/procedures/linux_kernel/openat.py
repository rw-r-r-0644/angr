from __future__ import annotations
import angr


class openat(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, dirfd, p_addr, flags, mode):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness="Iend_BE")
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        return self.state.posix.openat(path, flags)
