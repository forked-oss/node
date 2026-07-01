# Security Review — 2026-07-01

Commit scanned: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

**Findings:** 9 (no new findings in this scan)

## All tracked findings

- **High:** Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork
- **Medium:** HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host
- **High:** Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration
- **Medium:** Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message
- **High:** Source map resolution reads arbitrary files without permission checks
- **High:** node:ffi raw memory accessors bypass --allow-ffi permission
- **High:** Permission model bypass via mutable Array.prototype.includes in child_process
- **High:** Permission model fs-write bypass via forced NODE_V8_COVERAGE in spawned children
- **High:** Worker execArgv permission escalation bypasses parent permission sandbox
