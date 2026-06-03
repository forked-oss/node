# Application Security Review — Node.js

**Commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
**Branch:** `cursor/application-security-review-1c80`  
**Scanned:** 2026-06-02

## Findings

### 1. [HIGH] Permission model bypass via attacker-controlled `NODE_OPTIONS` in `child_process` spawn/fork

| Field | Detail |
|-------|--------|
| **Location** | `lib/child_process.js` |
| **Attacker** | Untrusted code influencing `child_process` env while parent uses `--permission --allow-child-process` |
| **Controlled input** | `options.env.NODE_OPTIONS` and `options.execArgv` |
| **Attack path** | `copyPermissionModelFlagsToEnv` skips parent flags when `NODE_OPTIONS` contains `--permission` substring or `execArgv` has `--permission`; child parses attacker allow flags |
| **Impact** | Permission sandbox escalation in child including native addons and broader FS access |

### 2. [MEDIUM] `fs.realpathSync` bypasses `--permission` filesystem restrictions

| Field | Detail |
|-------|--------|
| **Location** | `lib/fs.js` |
| **Attacker** | Untrusted JavaScript running inside a `--permission`-restricted Node process (compromised dependency, eval gadget, prototype pollution) |
| **Controlled input** | Path argument to `fs.realpathSync()` |
| **Attack path** | `realpathSync` walks paths using `binding.lstat`, `binding.stat`, and `binding.readlink` directly. The C++ `LStat` handler has no `THROW_IF_INSUFFICIENT_PERMISSIONS`, unlike `Stat` and `ReadLink`. The public `lstatSync` wrapper enforces permissions in JS, but `realpathSync` never calls it. `fs.realpath.native` and async `realpath` are gated. |
| **Impact** | Existence oracle and canonical path disclosure for paths outside `--allow-fs-read`; symlink target resolution leaks paths the sandbox was meant to hide |
| **Remediation** | Add `THROW_IF_INSUFFICIENT_PERMISSIONS` to `LStat` in `src/node_file.cc`, and/or gate `realpathSync` the same way as `lstatSync` |
