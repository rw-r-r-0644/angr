from __future__ import annotations
import angr

from .fstat import fstat


class newfstatat(fstat):
    AT_EMPTY_PATH = 0x1000

    def run(self, dirfd, p_addr, stat_buf, flags):
        flags = self.state.solver.eval(flags)

        # obtain pathname string
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness="Iend_BE")
        pathname = self.state.solver.eval(p_expr, cast_to=bytes)

        # fstat-like for AT_EMPTY_PATH and empty path
        if flags & self.AT_EMPTY_PATH and pathname == b'':
            return super().run(dirfd, stat_buf)

        # open temorary fd
        fd = self.state.posix.openat(dirfd, pathname, 0)

        # Use fstat to get the result and everything
        result = super().run(fd, stat_buf)

        # close temporary fd
        self.state.posix.close(fd)

        return result
