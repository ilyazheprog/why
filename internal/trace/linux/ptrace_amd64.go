//go:build linux && amd64

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"whytool.org/why/internal/model"
	"whytool.org/why/internal/trace"
)

type Tracer struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

type taskState struct {
	inSyscall bool
	syscall   uint64
	args      [6]uint64
}

func (t *Tracer) Run(ctx context.Context, command model.Command) (trace.Result, error) {
	if len(command.Args) == 0 {
		return trace.Result{}, errors.New("empty command")
	}
	started := time.Now()
	cmd := exec.Command(command.Args[0], command.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = t.Stdin, t.Stdout, t.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return trace.Result{}, err
	}
	root := cmd.Process.Pid
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(root, syscall.SIGKILL)
		case <-done:
		}
	}()
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(root, &status, 0, nil); err != nil {
		return trace.Result{}, err
	}
	const ptraceOExitKill = 0x00100000
	options := syscall.PTRACE_O_TRACESYSGOOD | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK | syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEEXEC | ptraceOExitKill
	if err := syscall.PtraceSetOptions(root, options); err != nil {
		return trace.Result{}, err
	}
	states := map[int]*taskState{root: {}}
	if err := syscall.PtraceSyscall(root, 0); err != nil {
		return trace.Result{}, err
	}
	var events []model.Event
	result := model.ProcessResult{PID: root}
	for len(states) > 0 {
		if ctx.Err() != nil {
			result.TimedOut = true
		}
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ECHILD) {
				break
			}
			return trace.Result{}, err
		}
		if ws.Exited() || ws.Signaled() {
			delete(states, pid)
			if pid == root {
				if ws.Exited() {
					code := ws.ExitStatus()
					result.ExitCode = &code
				}
				if ws.Signaled() {
					result.Signal = ws.Signal().String()
				}
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		state := states[pid]
		if state == nil {
			state = &taskState{}
			states[pid] = state
			_ = syscall.PtraceSetOptions(pid, options)
		}
		sig := ws.StopSignal()
		if sig == syscall.Signal(int(syscall.SIGTRAP)|0x80) {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
				if !state.inSyscall {
					state.inSyscall = true
					state.syscall = regs.Orig_rax
					state.args = [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
				} else {
					state.inSyscall = false
					if state.syscall == syscall.SYS_BIND && int64(regs.Rax) == -int64(syscall.EADDRINUSE) {
						if b, ok := readBind(pid, uintptr(state.args[1]), state.args[2]); ok {
							events = append(events, model.Event{BindFailure: b})
						}
					}
				}
			}
		} else if sig == syscall.SIGTRAP && ws.TrapCause() != 0 {
			if child, err := syscall.PtraceGetEventMsg(pid); err == nil && child != 0 {
				states[int(child)] = &taskState{}
			}
		} else if sig == syscall.SIGSTOP || sig == syscall.SIGTRAP {
			// Synthetic ptrace stop; do not deliver it to the target.
		} else {
			_ = syscall.PtraceSyscall(pid, int(sig))
			continue
		}
		_ = syscall.PtraceSyscall(pid, 0)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
	}
	result.Duration = time.Since(started)
	return trace.Result{Process: result, Events: events}, nil
}

func readBind(pid int, address uintptr, length uint64) (*model.BindFailure, bool) {
	if length < 8 {
		return nil, false
	}
	n := int(length)
	if n > 128 {
		n = 128
	}
	buf := make([]byte, n)
	if _, err := syscall.PtracePeekData(pid, address, buf); err != nil {
		return nil, false
	}
	family := binary.LittleEndian.Uint16(buf[:2])
	b := &model.BindFailure{PID: pid, Errno: "EADDRINUSE", Timestamp: time.Now()}
	switch family {
	case syscall.AF_INET:
		b.Network = "tcp4"
		b.Port = binary.BigEndian.Uint16(buf[2:4])
		b.Address = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
	case syscall.AF_INET6:
		if len(buf) < 24 {
			return nil, false
		}
		b.Network = "tcp6"
		b.Port = binary.BigEndian.Uint16(buf[2:4])
		b.Address = ipv6(buf[8:24])
	default:
		return nil, false
	}
	return b, true
}

func ipv6(b []byte) string {
	parts := make([]byte, 0, 39)
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			parts = append(parts, ':')
		}
		parts = strconv.AppendUint(parts, uint64(binary.BigEndian.Uint16(b[i:i+2])), 16)
	}
	return string(parts)
}
