# Security Review — 2026-06-30

Commit scanned: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## New findings (this scan)

### High: Worker execArgv permission escalation bypasses parent permission sandbox

- **Location:** `src/node_worker.cc`
- **Attacker:** Untrusted code in a parent started with `--permission` and `--allow-worker` but without broader allow flags
- **Attack path:** `Worker` constructor parses attacker-supplied `execArgv` into per-isolate `EnvironmentOptions`, accepting `--allow-net` and other permission-namespace flags without inheriting/clamping to parent grants (unlike `child_process` `copyPermissionModelFlagsToEnv`)
- **Impact:** Complete permission sandbox escape in worker threads
- **Remediation:** When parent permission model is enabled, strip or clamp permission-namespace flags in worker `execArgv` to parent grants only

## Previously reported findings (9 total in tracker)

Includes NODE_OPTIONS child_process bypass, HTTP proxy NO_PROXY bypass, prototype pollution in spawn env, proxy credential leakage, source map permission bypass, node:ffi raw memory bypass, Array.prototype.includes bypass, and NODE_V8_COVERAGE fs-write bypass.
