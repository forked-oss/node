# Application Security Review

Commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
Branch: `cursor/application-security-review-7b43`

## Findings

### 1. [High] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing child_process env
- **Controlled input:** options.env.NODE_OPTIONS with --allow-* flags
- **Attack path:** copyPermissionModelFlagsToEnv skips when NODE_OPTIONS contains --permission
- **Impact:** Sandbox escalation in child
- **Remediation:** Always merge parent permission flags

### 2. [High] Worker permission model bypass via NODE_OPTIONS in custom worker env

- **Location:** `src/node_worker.cc`
- **Attacker:** Code spawning workers with attacker-influenced env
- **Controlled input:** Worker options.env.NODE_OPTIONS differing from parent
- **Attack path:** Worker parses NODE_OPTIONS with kAllowedInEnvvar; no copyPermissionModelFlagsToEnv
- **Impact:** Worker escapes parent permission restrictions
- **Remediation:** Mirror child_process permission flag copying for workers
