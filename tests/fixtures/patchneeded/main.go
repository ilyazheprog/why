package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: patchneeded INPUT OUTPUT")
		os.Exit(64)
	}
	binary, err := elf.Open(os.Args[1])
	if err != nil {
		fatal(err)
	}
	libraries, err := binary.ImportedLibraries()
	binary.Close()
	if err != nil || len(libraries) == 0 {
		fatal(fmt.Errorf("no imported libraries"))
	}
	old := libraries[0]
	if len(old) < 6 {
		fatal(fmt.Errorf("dependency name is too short"))
	}
	replacement := strings.Repeat("x", len(old)-5) + ".so.1"
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	index := bytes.Index(data, append([]byte(old), 0))
	if index < 0 {
		fatal(fmt.Errorf("dependency string not found"))
	}
	copy(data[index:index+len(old)], replacement)
	if err := os.WriteFile(os.Args[2], data, 0755); err != nil {
		fatal(err)
	}
	fmt.Println(replacement)
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
