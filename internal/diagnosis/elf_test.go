package diagnosis

import (
	"debug/elf"
	"testing"

	"whytool.org/why/internal/model"
)

func TestMissingDirectELFDependency(t *testing.T) {
	const path = "/bin/sh"
	binary, err := elf.Open(path)
	if err != nil {
		t.Skip(err)
	}
	needed, err := binary.ImportedLibraries()
	binary.Close()
	if err != nil || len(needed) == 0 {
		t.Skip("fixture has no dynamic dependencies")
	}
	library := needed[0]
	events := []model.Event{
		{FileFailure: &model.FileFailure{PID: 1, Operation: "openat", Path: "/lib/a/" + library, Errno: "ENOENT"}},
		{FileFailure: &model.FileFailure{PID: 1, Operation: "openat", Path: "/lib/b/" + library, Errno: "ENOENT"}},
	}
	code := 127
	d := EvaluateMissingLibrary([]string{path}, events, model.ProcessResult{ExitCode: &code})
	if d.Cause == nil || d.Cause.ID != "elf.library_missing" || d.Confidence != model.Certain {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}

func TestELFLibraryRequiresMultipleFailedSearchPaths(t *testing.T) {
	events := []model.Event{{FileFailure: &model.FileFailure{PID: 1, Operation: "openat", Path: "/lib/libc.so.6", Errno: "ENOENT"}}}
	d := EvaluateMissingLibrary([]string{"/bin/sh"}, events, model.ProcessResult{})
	if d.Cause != nil || d.Confidence != model.Unknown {
		t.Fatalf("unexpected diagnosis: %#v", d)
	}
}
