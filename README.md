# Why

**Why is a system diagnostic tool that explains why a program failed.**

Unlike tracing tools that only expose low-level events, Why correlates operating-system evidence into causal diagnoses. Why does not guess: a root cause is reported only when observable evidence supports it.

The current development version implements direct Linux/amd64 execution under `ptrace`, structured command-start diagnostics, process-tree tracing, `bind(2)`/`EADDRINUSE` normalization, `/proc` listener ownership enrichment, signal termination diagnoses, and human or JSON output.

```console
$ why ./server

server exited with code 1 after 4ms

Root cause
└─ TCP port 8080 is already in use
   └─ nginx (PID 3812)

Evidence
  bind(0.0.0.0:8080) → EADDRINUSE
```

## Build

```sh
CGO_ENABLED=0 go build -buildvcs=false -o why ./cmd/why
```

No external commands or runtimes are invoked by the resulting binary.

## Install or update

```sh
bash <(curl -fsSL https://whytool.org/install.sh)
```

The installer downloads the latest release for the current Linux architecture, verifies it against the published `SHA256SUMS`, and installs it to `~/.local/bin/why`. Set `WHY_INSTALL_DIR` to choose another directory or `WHY_VERSION` to install a specific version.

## Development

```sh
make test
```

CI checks formatting, tests, `go vet`, the race detector, static Linux builds for amd64 and arm64, and the end-to-end `ptrace` address-conflict diagnosis.

Version tags matching `v*.*.*` run the release pipeline. It tests the tagged source, produces reproducible standalone archives for `linux/amd64` and `linux/arm64`, creates `SHA256SUMS`, and publishes the files to GitHub Releases.

## Usage

```text
why [OPTIONS] -- COMMAND [ARGS...]
why [OPTIONS] COMMAND [ARGS...]

--json
--quiet, -q
--verbose, -v, -vv
--timeout DURATION
--no-suggestions
--version
--help
```

Target stdout remains on stdout and target stderr remains on stderr. In JSON mode, the JSON report is written to stdout and both target streams are written to stderr. Why returns 0 for success, 1 for diagnosed failure, 2 for unknown failure, 64 for invalid usage, 65 for an internal error, and 124 for its own timeout.

## Current limits

- Trace backend: Linux/amd64 only.
- Command-start diagnostics cover missing commands, execution permission, invalid executable formats, missing shebang interpreters, and missing ELF loaders.
- Network diagnostics cover `bind(2)` address conflicts and `connect(2)` refusal, timeout, unreachable network/host, reset, and unavailable-address failures. Process termination diagnoses cover signals including `SIGSEGV`, `SIGABRT`, and `SIGKILL`.
- Filesystem candidates cover missing paths, permissions, read-only filesystems, space/quota exhaustion, file descriptor limits, and path type errors. They are reported conservatively as likely causes unless stronger causal evidence exists.
- `SIGKILL` alone is never reported as OOM. Deterministic cgroup correlation is not implemented yet.
- Listener lookup currently searches the tracing process's network namespace and may omit the owner when procfs permissions prevent inspection.
- Other target failures correctly return an unknown diagnosis.

The implementation is an initial vertical slice, not yet a v0.1 release.
