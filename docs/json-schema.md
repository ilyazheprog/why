# JSON interface

Every JSON document contains `schema_version`; the development schema is version `1`.

Top-level fields are `schema_version`, `command`, `result`, `process`, and `diagnosis`. A diagnosis contains a confidence (`certain`, `likely`, `possible`, or `unknown`), an optional cause graph, and referenced evidence. Implemented stable IDs include `exec.command_not_found`, `exec.permission_denied`, `exec.invalid_executable`, `exec.interpreter_missing`, `network.bind.address_in_use`, `network.connection_refused`, `network.connection_timeout`, `network.network_unreachable`, `network.host_unreachable`, `process.sigsegv`, `process.sigabrt`, and `process.sigkill`.

Filesystem IDs include `filesystem.path_missing`, `filesystem.permission_denied`, `filesystem.read_only`, `filesystem.no_space`, `filesystem.quota_exceeded`, and `resource.file_descriptor_limit`.

`elf.library_missing` requires correlation between a direct ELF `DT_NEEDED` entry and multiple unresolved loader search paths. A successful open of the same library basename cancels the candidate.

When Why terminates a target because `--timeout` expires, the stable ID is `process.timeout`, the process object includes `timed_out: true` and `timeout_ms`, and Why exits with status 124. This is distinct from a target-originated `SIGKILL`.

Human wording is not a machine interface. Consumers should use `schema_version`, diagnostic IDs, confidence, and typed evidence.
