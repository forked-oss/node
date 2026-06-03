# Application Security Review

Repository: **node**
Scanned commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
Branch: `cursor/application-security-review-6a2c`

Validated medium-or-higher findings with end-to-end attack paths.

## 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS and options.execArgv
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission
- **Impact:** Permission sandbox escalation in child processes
- **Remediation:** Always propagate parent permission flags; strip attacker --permission in child env.
