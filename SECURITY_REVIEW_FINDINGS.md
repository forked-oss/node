# Application Security Review Findings

Commit scanned: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## 1. High: Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- Severity: High
- Primary location: `lib/child_process.js`
- Attacker: Untrusted code influencing child_process env while parent uses `--permission --allow-child-process`.
- Controlled input: `options.env.NODE_OPTIONS` and `options.execArgv`.
- Attack path: `copyPermissionModelFlagsToEnv` skips parent flags when `NODE_OPTIONS` contains `--permission` substring or `execArgv` has `--permission`; child parses attacker allow flags.
- Impact: Permission sandbox escalation in child including native addons and broader FS access.
- Remediation: Always propagate parent permission flags regardless of child `NODE_OPTIONS` content.

## 2. Medium: Permission model filesystem existence oracle via module resolution

- Severity: Medium
- Primary location: `src/node_file.cc`
- Attacker: Any party that can execute JavaScript in a process started with `--permission`.
- Controlled input: Filesystem paths passed into `require()`, `import()`, or `createRequire().resolve()`.
- Attack path: CJS/ESM loaders call `internalModuleStat()` before permission checks; `InternalModuleStat` performs raw `uv_fs_stat` with no permission gate.
- Impact: Enumeration of sensitive paths outside the allow-list without read permission.
- Remediation: Apply `PermissionScope::kFileSystemRead` checks inside `InternalModuleStat`.
