//go:build linux && amd64

package linux

import "syscall"

const (
	sysOpen    = syscall.SYS_OPEN
	sysOpenat  = syscall.SYS_OPENAT
	sysMkdir   = syscall.SYS_MKDIR
	sysMkdirat = syscall.SYS_MKDIRAT
	sysBind    = syscall.SYS_BIND
	sysConnect = syscall.SYS_CONNECT
)

type syscallFrame struct {
	Number uint64
	Args   [6]uint64
	Result int64
}

func readSyscallFrame(pid int) (syscallFrame, error) {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return syscallFrame{}, err
	}
	return syscallFrame{
		Number: regs.Orig_rax,
		Args:   [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9},
		Result: int64(regs.Rax),
	}, nil
}
