package diagnosis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"whytool.org/why/internal/model"
)

func TestExecFailureDiagnoses(t *testing.T) {
	dir := t.TempDir()
	permissionDenied := writeTestExecutable(t, dir, "permission-denied", "#!/bin/sh\n", 0644)
	invalid := writeTestExecutable(t, dir, "invalid", "not an executable\n", 0755)
	missingInterpreter := writeTestExecutable(t, dir, "missing-interpreter", "#!/why-test/interpreter-does-not-exist\n", 0755)

	tests := []struct {
		name    string
		command string
		err     error
		id      string
	}{
		{"command missing", filepath.Join(dir, "does-not-exist"), syscall.ENOENT, "exec.command_not_found"},
		{"permission denied", permissionDenied, syscall.EACCES, "exec.permission_denied"},
		{"invalid executable", invalid, syscall.ENOEXEC, "exec.invalid_executable"},
		{"interpreter missing", missingInterpreter, syscall.ENOENT, "exec.interpreter_missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := EvaluateExecFailure([]string{test.command}, test.err)
			if d.Cause == nil || d.Cause.ID != test.id || d.Confidence != model.Certain {
				t.Fatalf("unexpected diagnosis: %#v", d)
			}
		})
	}
}

func TestAmbiguousExecENOENTRemainsUnknown(t *testing.T) {
	path := writeTestExecutable(t, t.TempDir(), "ambiguous", "plain data", 0755)
	d := EvaluateExecFailure([]string{path}, syscall.ENOENT)
	if d.Cause != nil || d.Confidence != model.Unknown {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func writeTestExecutable(t *testing.T, dir, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
