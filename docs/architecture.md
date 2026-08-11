# Architecture

The current pipeline is:

```text
CLI → Linux ptrace tracer → normalized events → evidence/rule engine
    → causal diagnosis → human or JSON renderer
```

`internal/model` contains platform-neutral command, event, evidence, cause, diagnosis, and report types. `internal/trace` is the backend interface; architecture-specific register and syscall handling lives in `internal/trace/linux`. Rules consume normalized events rather than registers or raw syscall records.

Command-start failures are typed separately from tracer failures. The diagnosis engine correlates the kernel exec error with bounded shebang or ELF metadata inspection; ambiguous failures remain unknown. This prevents a ptrace policy error from being mislabeled as a target permission problem.

The tracer follows fork, vfork, and clone events and keeps per-task syscall entry/exit state. Its event storage is presently bounded by the number of promoted diagnostic events: irrelevant syscalls are discarded immediately.

Network enrichment reads kernel socket tables from procfs, obtains the socket inode, and scans process file-descriptor links for an owner. Failure to enrich does not invalidate the causal `EADDRINUSE` evidence.
