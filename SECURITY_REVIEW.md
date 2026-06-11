# Application Security Review

**Commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
**Scan date:** 2026-06-10 (PST)

## Findings

### 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Location:** `lib/child_process.js`

| Field | Detail |
|-------|--------|
| Attacker | Untrusted code influencing `child_process` env while parent uses `--permission --allow-child-process` |
| Controlled input | `options.env.NODE_OPTIONS` and `options.execArgv` |
| Attack path | `copyPermissionModelFlagsToEnv` skips parent flags when `NODE_OPTIONS` contains `--permission` substring or `execArgv` has `--permission`; child parses attacker-supplied broader `--allow-*` flags |
| Impact | Permission sandbox escalation in child, including native addons and broader filesystem access |

**Remediation:** Always merge parent permission flags into child `NODE_OPTIONS` (intersect or enforce parent allow-list) instead of returning early when `--permission` is already present.
