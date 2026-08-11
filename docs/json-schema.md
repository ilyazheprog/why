# JSON interface

Every JSON document contains `schema_version`; the development schema is version `1`.

Top-level fields are `schema_version`, `command`, `result`, `process`, and `diagnosis`. A diagnosis contains a confidence (`certain`, `likely`, `possible`, or `unknown`), an optional cause graph, and referenced evidence. Implemented stable IDs include `network.bind.address_in_use`, `process.sigsegv`, `process.sigabrt`, and `process.sigkill`.

Human wording is not a machine interface. Consumers should use `schema_version`, diagnostic IDs, confidence, and typed evidence.
