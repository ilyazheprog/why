//go:build linux && arm64

package linux

import "syscall"

const unsupportedSyscall = ^uint64(0)

const (
	sysOpen    = unsupportedSyscall
	sysOpenat  = syscall.SYS_OPENAT
	sysMkdir   = unsupportedSyscall - 1
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
		Number: regs.Regs[8],
		Args:   [6]uint64{regs.Regs[0], regs.Regs[1], regs.Regs[2], regs.Regs[3], regs.Regs[4], regs.Regs[5]},
		Result: int64(regs.Regs[0]),
	}, nil
}
