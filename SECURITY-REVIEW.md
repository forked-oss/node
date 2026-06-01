# Application Security Review

**Branch:** `cursor/application-security-review-8f44`  
**Commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
**Reviewed:** 2026-06-01

## Findings

### [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process

| Field | Detail |
|-------|--------|
| **Location** | `lib/child_process.js` |
| **Attacker** | Untrusted code or input influencing `child_process.spawn()` / `fork()` environment while the parent runs with `--permission` and `--allow-child-process` |
| **Controlled input** | `options.env.NODE_OPTIONS` and/or `options.execArgv` |
| **Attack path** | `copyPermissionModelFlagsToEnv()` skips copying the parent's restrictive flags when `NODE_OPTIONS` contains the substring `--permission` (including `--permission-audit`) or when `execArgv` includes `--permission`. Attacker prepends permissive flags (`--allow-addons`, `--allow-fs-read=*`, etc.) that the child parses from `NODE_OPTIONS`/argv. In audit mode (`--permission-audit`), `THROW_IF_INSUFFICIENT_PERMISSIONS` logs but does not block when `warning_only()` is true. |
| **Impact** | Full permission-model escalation in child processes: native addons, inspector, broader filesystem/network access despite parent policy. |
| **Remediation** | When `permission.isEnabled()`, strip all permission-namespace flags from child `NODE_OPTIONS` and user `execArgv`; always inject parent profile via a non-user-writable channel; use exact token matching instead of `indexOf('--permission')`. |
