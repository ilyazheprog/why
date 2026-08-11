package diagnosis

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"whytool.org/why/internal/model"
)

// EvaluateExecFailure classifies only facts that can be established from the
// command start error and executable metadata. It deliberately returns unknown
// for ambiguous ENOENT failures.
func EvaluateExecFailure(command []string, startErr error) model.Diagnosis {
	if len(command) == 0 {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	requested := command[0]
	path, lookErr := resolveExecutable(requested)
	if lookErr != nil {
		if errors.Is(lookErr, exec.ErrNotFound) || errors.Is(lookErr, os.ErrNotExist) {
			return execDiagnosis("exec.command_not_found", fmt.Sprintf("Command does not exist: %s", requested), requested, "ENOENT", nil)
		}
		return model.Diagnosis{Confidence: model.Unknown}
	}

	if errors.Is(startErr, syscall.EACCES) {
		return execDiagnosis("exec.permission_denied", fmt.Sprintf("Cannot execute %s: permission denied", path), path, "EACCES", nil)
	}
	if errors.Is(startErr, syscall.ENOEXEC) {
		return execDiagnosis("exec.invalid_executable", fmt.Sprintf("Invalid executable format: %s", path), path, "ENOEXEC", nil)
	}
	if errors.Is(startErr, syscall.ENOENT) {
		if interpreter, ok := missingShebangInterpreter(path); ok {
			return execDiagnosis("exec.interpreter_missing", "Script interpreter does not exist", path, "ENOENT", map[string]any{"interpreter": interpreter})
		}
		if interpreter, ok := missingELFInterpreter(path); ok {
			return execDiagnosis("elf.interpreter_missing", "ELF dynamic loader does not exist", path, "ENOENT", map[string]any{"interpreter": interpreter})
		}
	}
	return model.Diagnosis{Confidence: model.Unknown}
}

func execDiagnosis(id, summary, path, errno string, extra map[string]any) model.Diagnosis {
	data := map[string]any{"name": "execve", "path": path, "errno": errno}
	evidence := model.Evidence{ID: "e1", Type: "exec", Source: "kernel", Data: data}
	children := []model.Cause(nil)
	evidenceList := []model.Evidence{evidence}
	causeEvidence := []string{"e1"}
	if interpreter, ok := extra["interpreter"].(string); ok {
		interpreterEvidence := model.Evidence{ID: "e2", Type: "filesystem", Source: "filesystem", Data: map[string]any{"operation": "stat", "path": interpreter, "errno": "ENOENT"}}
		evidenceList = append(evidenceList, interpreterEvidence)
		causeEvidence = append(causeEvidence, "e2")
		childID := "exec.interpreter"
		if strings.HasPrefix(id, "elf.") {
			childID = "elf.interpreter"
		}
		children = []model.Cause{{ID: childID, Summary: interpreter, Confidence: model.Certain, Evidence: []string{"e2"}}}
	}
	cause := &model.Cause{ID: id, Summary: summary, Confidence: model.Certain, Evidence: causeEvidence, Children: children}
	return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: evidenceList}
}

func resolveExecutable(requested string) (string, error) {
	if strings.ContainsRune(requested, '/') {
		if _, err := os.Stat(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	return exec.LookPath(requested)
}

func missingShebangInterpreter(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	line, err := bufio.NewReader(io.LimitReader(f, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	if !strings.HasPrefix(line, "#!") {
		return "", false
	}
	fields := strings.Fields(strings.TrimPrefix(strings.TrimRight(line, "\r\n"), "#!"))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "", false
	}
	_, err = os.Stat(fields[0])
	return fields[0], errors.Is(err, os.ErrNotExist)
}

func missingELFInterpreter(path string) (string, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	for _, program := range f.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(program.Open(), 4096))
		if err != nil {
			return "", false
		}
		interpreter := strings.TrimRight(string(data), "\x00")
		if interpreter == "" || !strings.HasPrefix(interpreter, "/") {
			return "", false
		}
		_, err = os.Stat(interpreter)
		return interpreter, errors.Is(err, os.ErrNotExist)
	}
	return "", false
}
