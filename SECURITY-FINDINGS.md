# Application Security Review — node

**Scan commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
**Review date:** 2026-07-03 (PST)

No new findings this scan.

## Active findings inventory

| Severity | Location | Title |
|----------|----------|-------|
| high | lib/child_process.js | Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork |
| medium | lib/_http_client.js | HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host |
| medium | lib/child_process.js | Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration |
| medium | lib/https.js | Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message |
| medium | lib/internal/source_map/source_map_cache.js | Source map resolution reads arbitrary files without permission checks |
| critical | lib/ffi.js | node:ffi raw memory accessors bypass --allow-ffi permission |
| high | lib/child_process.js | Permission model bypass via mutable Array.prototype.includes in child_process |
| medium | lib/child_process.js | Permission model fs-write bypass via forced NODE_V8_COVERAGE in spawned children |
| high | src/node_worker.cc | Worker execArgv permission escalation bypasses parent permission sandbox |
| medium | src/tcp_wrap.cc | TCPWrap Open bypasses net permission check on pre-adopted socket fds |
| medium | src/inspector_profiler.cc | CPU and heap profiler exit writes bypass fs-write permission |

Findings tracked in automation memory (`node---flagged-vulnerabilities.json`).
