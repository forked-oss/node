# Node.js Security Review

Commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## New findings (2026-07-01)

### Medium: TCPWrap Open bypasses net permission check on pre-adopted socket fds

- **Location:** `src/tcp_wrap.cc`
- **Attacker:** Untrusted JavaScript running under `--permission` without `--allow-net`
- **Controlled input:** Integer file descriptor passed to `new net.Socket({ fd })` or `TCPWrap.open(fd)`
- **Attack path:** `TCPWrap::Open` calls `uv_tcp_open` with no `THROW_IF_INSUFFICIENT_PERMISSIONS` check, unlike `Bind`, `Connect`, and `Listen`. Attacker adopts an inherited or IPC-transferred connected socket and reads/writes despite net denial.
- **Impact:** Network I/O bypass enabling data exfiltration or abuse of inherited sockets (e.g. docker.sock UDS if an FD is available).
- **Remediation:** Add `kNet` permission check to `TCPWrap::Open` and equivalent paths in `pipe_wrap.cc` / `udp_wrap.cc`.

### Medium: CPU and heap profiler exit writes bypass fs-write permission

- **Location:** `src/inspector_profiler.cc`
- **Attacker:** Untrusted code influencing process startup with profiler flags under `--permission` without `--allow-fs-write`
- **Controlled input:** `--cpu-prof`, `--cpu-prof-dir`, `--heap-prof`, or `--heap-prof-dir` via argv or `NODE_OPTIONS`
- **Attack path:** `V8ProfilerConnection::WriteProfile` calls `WriteFileSync` directly at process exit without permission-checked FS APIs.
- **Impact:** Arbitrary filesystem write at teardown to attacker-chosen directories.
- **Remediation:** Route profiler output through permission-aware file APIs or reject profiler flags when `fs.write` is denied.

## Previously reported findings

| Severity | Title |
|----------|-------|
| High | Permission model bypass via attacker-controlled NODE_OPTIONS in child_process |
| Medium | HTTP proxy NO_PROXY bypass via userinfo in options.host |
| Medium | Object.prototype pollution injects arbitrary environment variables into spawned children |
| Medium | Proxy credentials in HTTPS_PROXY leaked into ERR_PROXY_TUNNEL error message |
| Medium | Source map resolution reads arbitrary files without permission checks |
| Critical | node:ffi raw memory accessors bypass --allow-ffi permission |
| High | Permission model bypass via mutable Array.prototype.includes in child_process |
| Medium | Permission model fs-write bypass via forced NODE_V8_COVERAGE in spawned children |
| High | Worker execArgv permission escalation bypasses parent permission sandbox |
