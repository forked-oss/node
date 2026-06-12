# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-11 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.

## [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code with --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when attacker sets --permission in child env
- **Impact:** Permission sandbox escalation in child processes

## [MEDIUM] Malicious npm registry SSRF via unvalidated doneUrl in web OTP [NEW]

- **Location:** `deps/npm/node_modules/npm-profile/lib/index.js`
- **Attacker:** Malicious/compromised registry via .npmrc
- **Controlled input:** doneUrl in EOTP 401 response
- **Attack path:** webAuthCheckLogin fetch() polls attacker-chosen URL without host validation
- **Impact:** SSRF to internal services during npm authentication
