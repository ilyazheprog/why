<div align="center">

# Why

### Find out why it failed.

**An evidence-backed system diagnostic tool for Linux.**<br>
Put `why` before a command and get a causal explanation—not just a syscall dump.

[![CI](https://github.com/ilyazheprog/why/actions/workflows/ci.yml/badge.svg)](https://github.com/ilyazheprog/why/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ilyazheprog/why?sort=semver)](https://github.com/ilyazheprog/why/releases/latest)
[![Linux](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-FCC624?logo=linux&logoColor=black)](https://github.com/ilyazheprog/why/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Website](https://img.shields.io/badge/whytool.org-live-9cff57)](https://whytool.org)

[Website](https://whytool.org) · [Install](#install-or-update) · [Examples](#examples) · [JSON API](#json-output) · [Releases](https://github.com/ilyazheprog/why/releases)

</div>

---

```console
$ why ./server

server exited with code 1 after 184ms

Root cause
└─ TCP port 8080 is already in use
   └─ nginx (PID 3812)

Evidence
  bind(0.0.0.0:8080) → EADDRINUSE
```

Why runs the target directly under `ptrace`, follows its process tree, normalizes operating-system events, and correlates them into a causal diagnosis. Every claim points back to observable evidence.

> [!IMPORTANT]
> **Why does not guess.** If the available evidence cannot establish a cause, Why returns `unknown`. A false diagnosis is worse than no diagnosis.

## Install or update

```bash
bash <(curl -fsSL https://whytool.org/install.sh)
```

The installer:

- detects Linux/amd64 or Linux/arm64;
- downloads the latest GitHub release;
- verifies the archive against `SHA256SUMS`;
- installs `why` to `~/.local/bin`;
- uses the same command for future updates.

Choose another directory or version when needed:

```bash
WHY_INSTALL_DIR=/usr/local/bin \
  bash <(curl -fsSL https://whytool.org/install.sh)

WHY_VERSION=0.1.1 \
  bash <(curl -fsSL https://whytool.org/install.sh)
```

Or download a standalone archive from [GitHub Releases](https://github.com/ilyazheprog/why/releases/latest). The binary has no external command or runtime dependencies.

## Quick start

```bash
why ./server
why python3 app.py
why nginx -c ./nginx.conf
why -- ./server --port 8080
why --timeout 10s ./worker
why --json ./server
```

Why never implicitly invokes a shell. Arguments such as `$HOME`, `*`, pipes, and redirects are passed literally:

```bash
why echo '$HOME'             # prints $HOME
why sh -c 'echo "$HOME"'    # shell expansion was explicitly requested
```

## Examples

### Command not found

```console
$ why does-not-exist

does-not-exist could not be executed after 0s

Root cause
└─ Command does not exist: does-not-exist

Evidence
  execve("does-not-exist") → ENOENT
```

Stable ID: `exec.command_not_found`

### Missing script interpreter

```console
$ why ./report.py

report.py could not be executed after 1ms

Root cause
└─ Script interpreter does not exist
   └─ /usr/bin/python3.12

Evidence
  execve("./report.py") → ENOENT
  stat("/usr/bin/python3.12") → ENOENT
```

Given a script beginning with:

```text
#!/usr/bin/python3.12
```

Why reports `exec.interpreter_missing`, rather than the ambiguous message “file not found.”

### Permission denied

```console
$ why ./backup

backup exited with code 1 after 8ms

Likely cause
└─ openat("/mnt/backups/database.sql") failed: permission denied

Evidence
  openat("/mnt/backups/database.sql") → EACCES
```

Stable ID: `filesystem.permission_denied`

### Path does not exist

```console
$ why ./importer

importer exited with code 1 after 6ms

Likely cause
└─ openat("/data/customers.csv") failed: path does not exist

Evidence
  openat("/data/customers.csv") → ENOENT
```

A single `ENOENT` is not enough. Why waits for repeated unresolved failures and cancels the candidate when a later fallback succeeds.

### Read-only filesystem

```console
$ why ./writer

writer exited with code 1 after 5ms

Likely cause
└─ openat("/state/app.db") failed: filesystem is read-only

Evidence
  openat("/state/app.db") → EROFS
```

Stable ID: `filesystem.read_only`

### File descriptor limit

```console
$ why ./collector

collector exited with code 1 after 31ms

Likely cause
└─ openat("/dev/null") failed: process file descriptor limit was reached

Evidence
  openat("/dev/null") → EMFILE
```

Stable ID: `resource.file_descriptor_limit`

### Address already in use

```console
$ why ./api --port 8080

api exited with code 1 after 12ms

Root cause
└─ TCP port 8080 is already in use
   └─ nginx (PID 3812)

Evidence
  bind(0.0.0.0:8080) → EADDRINUSE

Suggestion
  Stop the process using this port or configure the application to use another port.
```

The owner is resolved directly through kernel socket tables and procfs—Why does not run `ss`, `netstat`, or `lsof`.

### Connection refused

```console
$ why ./worker

worker exited with code 1 after 14ms

Root cause
└─ Connection to 10.0.0.2:5432 was refused

Evidence
  connect(10.0.0.2:5432) → ECONNREFUSED
```

Why proves that the connection was refused. It does not invent a remote cause such as “PostgreSQL is down” or “the firewall rejected it.”

### Missing shared library

```console
$ why ./encoder

encoder exited with code 127 after 9ms

Root cause
└─ Required shared library was not found: libcodec.so.3
   └─ Required by ./encoder

Evidence
  ELF "./encoder" requires libcodec.so.3
  openat("/lib/libcodec.so.3") → ENOENT
  openat("/usr/lib/libcodec.so.3") → ENOENT
```

Why parses ELF metadata internally and correlates `DT_NEEDED` with the loader's unresolved searches. It never invokes `ldd`, `readelf`, or `objdump`.

### Signal termination

```console
$ why ./crasher

crasher terminated by SIGSEGV after 3ms

Root cause
└─ Process was terminated with SIGSEGV

Evidence
  signal: SIGSEGV
```

Why does not automatically call this a null-pointer dereference: `SIGSEGV` alone does not prove that.

### cgroup OOM correlation

```console
$ why ./memory-hungry-worker

memory-hungry-worker terminated by SIGKILL after 1.2s

Likely cause
└─ Process was likely killed after its memory cgroup reported an OOM kill

Evidence
  signal: SIGKILL
  cgroup /jobs/worker: oom_kill 4 → 5
```

This requires both target `SIGKILL` and an increase in its cgroup v2 `oom_kill` counter during execution. It remains `likely`, because that counter does not identify the individual victim PID. A bare `SIGKILL` is never labeled OOM.

### Why timeout

```console
$ why --timeout 5s ./stuck-worker

stuck-worker timed out after 5s

Root cause
└─ Process exceeded the 5s timeout

Evidence
  timeout after 5000ms
```

Why terminates the traced process tree and exits with status `124`. This is distinct from a target-originated `SIGKILL`.

### Successful command

```console
$ why true

Process succeeded.

Exit code: 0
Duration: 1ms
```

### Unknown is a valid result

```console
$ why ./application

application exited with code 1 after 2.8s

Why could not determine the root cause.
```

Why exits with status `2` here. It does not turn the last failed syscall into a convenient but unsupported story.

## JSON output

`--json` exposes a stable machine interface for CI, automation, monitoring, and diagnostic agents:

```bash
why --json ./server
```

```json
{
  "schema_version": "1",
  "command": ["./server"],
  "result": "failed",
  "process": {
    "pid": 4281,
    "exit_code": 1,
    "duration_ms": 184
  },
  "diagnosis": {
    "confidence": "certain",
    "cause": {
      "id": "network.bind.address_in_use",
      "summary": "TCP port 8080 is already in use",
      "confidence": "certain",
      "evidence": ["e1"]
    },
    "evidence": [
      {
        "id": "e1",
        "type": "syscall",
        "source": "ptrace",
        "pid": 4281,
        "data": {
          "name": "bind",
          "network": "tcp4",
          "address": "0.0.0.0",
          "port": 8080,
          "errno": "EADDRINUSE"
        }
      }
    ]
  }
}
```

Human wording may evolve. Consumers should rely on `schema_version`, diagnostic IDs, confidence values, evidence types, and documented exit codes. See [docs/json-schema.md](docs/json-schema.md).

## What Why diagnoses

| Domain | Evidence-backed diagnoses |
|---|---|
| Execution | command missing, permission denied, invalid executable, missing shebang interpreter, missing ELF loader |
| Filesystem | path missing, permission denied, read-only filesystem, space/quota exhaustion, file descriptor exhaustion, incorrect path type |
| Network | address in use, connection refused/timed out/reset, host/network unreachable, local address unavailable |
| ELF | missing interpreter, missing direct shared library |
| Process | non-zero/unknown exit, `SIGSEGV`, `SIGABRT`, `SIGKILL`, `SIGTERM`, `SIGILL`, `SIGFPE`, `SIGBUS` |
| Memory | cgroup v2 OOM-kill correlation |
| Supervisor | Why timeout across the complete traced process tree |

## Confidence model

| Confidence | Meaning | Human heading |
|---|---|---|
| `certain` | Evidence establishes the observed causal statement | `Root cause` |
| `likely` | Strong correlated evidence exists, but causality is not fully provable | `Likely cause` |
| `possible` | Evidence supports a candidate with meaningful alternatives | `Possible cause` |
| `unknown` | Why cannot responsibly identify a cause | `Why could not determine the root cause` |

## CLI

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

By default, target stdout stays on stdout, target stderr stays on stderr, and Why's human diagnosis goes to stderr. In JSON mode, the report goes to stdout and both target streams go to stderr.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Target succeeded |
| `1` | Target failed and Why produced a diagnosis |
| `2` | Target failed and the cause is unknown |
| `64` | Invalid Why usage |
| `65` | Internal Why error |
| `124` | Why timeout expired |

The original child exit code remains available in human and JSON output.

## How it works

```text
CLI → process supervisor → Linux ptrace backend → normalized events
    → bounded evidence store → enrichers → causal rules
    → diagnosis graph → human / JSON renderer
```

Why reads Linux interfaces directly: `ptrace`, procfs, cgroup v2 files, kernel socket tables, and ELF metadata. The released binary does not shell out to existing diagnostic utilities.

Architecture-specific register decoding is isolated for amd64 and arm64. Both feed the same normalized evidence and diagnosis pipeline.

## Build from source

Requires Go 1.24 or newer:

```bash
git clone https://github.com/ilyazheprog/why.git
cd why
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o why ./cmd/why
./why --version
```

Run the development checks:

```bash
make test
go test -race ./...
```

CI runs tests, formatting checks, `go vet`, the race detector, static builds, installer tests, and the complete ptrace integration suite on native Linux/amd64 and Linux/arm64 runners.

## Security and privacy

- no implicit shell;
- no setuid installation;
- no privilege escalation;
- no telemetry or uploads;
- no network payload capture;
- no arbitrary syscall buffer capture;
- bounded strings and event storage;
- ELF and procfs data treated as untrusted input;
- missing permissions reduce enrichment instead of creating a guessed diagnosis.

Read [docs/security.md](docs/security.md) before embedding Why in privileged automation.

## Current limits

- Linux process execution mode only; attaching to an existing PID is not implemented yet.
- DNS resolution is not yet represented as a first-class normalized event.
- ELF diagnosis currently focuses on the direct target and direct `DT_NEEDED` entries.
- Listener ownership lookup is limited to the tracing process's network namespace and may be unavailable under restrictive procfs permissions.
- Filesystem candidates are deliberately conservative and often remain `likely`.
- ptrace can substantially slow syscall-heavy workloads; Why is a diagnostic tool, not a zero-overhead profiler.

## Principles

```text
Correctness > number of diagnoses
Evidence    > heuristics
Unknown     > false root cause
Native APIs > shelling out
Small core  > huge dependency graph
```

## Contributing

Incorrect diagnoses destroy trust, so every new rule should include:

1. a deterministic failing fixture;
2. structured semantic assertions;
3. a false-positive or successful-fallback test;
4. architecture coverage where syscall ABI is involved.

Issues and pull requests are welcome. See the [architecture](docs/architecture.md), [JSON interface](docs/json-schema.md), and [security model](docs/security.md) first.

## License

[MIT](LICENSE-MIT) © Ilya Zhenetsky

---

<div align="center">

**Download one binary. Put `why` before a failing command. Get evidence instead of guesswork.**

[whytool.org](https://whytool.org)

</div>
