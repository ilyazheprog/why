# Changelog

## v0.1.1 — 2026-08-11

- Added a native Linux/arm64 ptrace backend and release artifact.
- Added the complete ptrace integration suite on native ARM64 runners.
- Added conservative cgroup v2 OOM-kill correlation.

## v0.1.0 — 2026-08-11

First public release for Linux/amd64.

- Direct, shell-free command execution under ptrace.
- Process-tree, timeout, exit, and signal observation.
- Evidence-backed execution, filesystem, TCP, and ELF loader diagnoses.
- Conservative confidence model with unknown as a first-class result.
- Stable JSON schema version 1 and diagnostic identifiers.
- Standalone static binary, checksum-verified installer, and GitHub release artifacts.
