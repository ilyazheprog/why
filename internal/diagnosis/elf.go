package diagnosis

import (
	"debug/elf"
	"path/filepath"
	"strconv"

	"whytool.org/why/internal/model"
)

// EvaluateMissingLibrary correlates a direct DT_NEEDED dependency with the
// loader's failed filesystem searches. Successful opens of the same basename
// are removed by the normalizer before this function is called.
func EvaluateMissingLibrary(command []string, events []model.Event, process model.ProcessResult) model.Diagnosis {
	if len(command) == 0 || process.TimedOut || process.Signal != "" || (process.ExitCode != nil && *process.ExitCode == 0) {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	path, err := resolveExecutable(command[0])
	if err != nil {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	binary, err := elf.Open(path)
	if err != nil {
		return model.Diagnosis{Confidence: model.Unknown}
	}
	defer binary.Close()
	needed, err := binary.ImportedLibraries()
	if err != nil {
		return model.Diagnosis{Confidence: model.Unknown}
	}

	for _, library := range needed {
		failures := matchingLibraryFailures(events, library)
		if len(failures) < 2 {
			continue
		}
		evidence := []model.Evidence{{ID: "e1", Type: "elf", Source: "elf", Data: map[string]any{"path": path, "needed": library}}}
		evidenceIDs := []string{"e1"}
		for i, failure := range failures {
			if i == 6 {
				break
			}
			id := evidenceID(i + 2)
			evidence = append(evidence, model.Evidence{ID: id, Type: "syscall", Source: "ptrace", ProcessID: failure.PID, Data: map[string]any{"name": failure.Operation, "path": failure.Path, "errno": failure.Errno}})
			evidenceIDs = append(evidenceIDs, id)
		}
		cause := &model.Cause{ID: "elf.library_missing", Summary: "Required shared library was not found: " + library, Confidence: model.Certain, Evidence: evidenceIDs,
			Children: []model.Cause{{ID: "elf.required_by", Summary: "Required by " + path, Confidence: model.Certain, Evidence: []string{"e1"}}}}
		return model.Diagnosis{Confidence: model.Certain, Cause: cause, Evidence: evidence}
	}
	return model.Diagnosis{Confidence: model.Unknown}
}

func matchingLibraryFailures(events []model.Event, library string) []*model.FileFailure {
	var failures []*model.FileFailure
	seen := make(map[string]bool)
	for _, event := range events {
		failure := event.FileFailure
		if failure == nil || failure.Errno != "ENOENT" || !isFileOpen(failure.Operation) || filepath.Base(failure.Path) != library || seen[failure.Path] {
			continue
		}
		seen[failure.Path] = true
		failures = append(failures, failure)
	}
	return failures
}

func isFileOpen(operation string) bool { return operation == "open" || operation == "openat" }

func evidenceID(number int) string {
	return "e" + strconv.Itoa(number)
}
