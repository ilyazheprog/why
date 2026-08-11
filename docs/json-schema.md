# JSON interface

Every JSON document contains `schema_version`; the development schema is version `1`.

Top-level fields are `schema_version`, `command`, `result`, `process`, and `diagnosis`. A diagnosis contains a confidence (`certain`, `likely`, `possible`, or `unknown`), an optional cause graph, and referenced evidence. Implemented stable IDs include `exec.command_not_found`, `exec.permission_denied`, `exec.invalid_executable`, `exec.interpreter_missing`, `network.bind.address_in_use`, `network.connection_refused`, `network.connection_timeout`, `network.network_unreachable`, `network.host_unreachable`, `process.sigsegv`, `process.sigabrt`, and `process.sigkill`.

Human wording is not a machine interface. Consumers should use `schema_version`, diagnostic IDs, confidence, and typed evidence.
