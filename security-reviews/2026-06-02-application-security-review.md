# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-5025`

## Summary

This review documents **2** validated finding(s) at medium severity or above.

## 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Location:** `lib/child_process.js`

**Attacker:** Untrusted code influencing `child_process` environment while the parent runs with `--permission` and `--allow-child-process`

**Controlled input:** `options.env.NODE_OPTIONS` and `options.execArgv`

**Attack path:** `copyPermissionModelFlagsToEnv` skips copying parent permission flags when `NODE_OPTIONS` already contains the `--permission` substring or when `execArgv` includes `--permission`; the child then parses attacker-supplied allow flags

**Impact:** Permission sandbox escalation in the child, including native addons and broader filesystem access

**Remediation:** Never treat attacker-controlled `NODE_OPTIONS` as proof that permission flags were intentionally set; always merge parent permission flags or strip untrusted permission-related tokens from child environment.

## 2. [MEDIUM] Permission model bypass via FileHandle futimes on read-only file descriptors

**Location:** `lib/internal/fs/promises.js`

**Attacker:** Untrusted JavaScript inside a `--permission`-restricted Node process

**Controlled input:** A path allowed by `--allow-fs-read` but denied by `--allow-fs-write`, opened with `fs.promises.open(path, 'r')`

**Attack path:** `FileHandle.utimes` calls internal `futimes` without `permission.isEnabled()` checks, while `fs.futimes` in `lib/fs.js` rejects with `ERR_ACCESS_DENIED`; the same gap exists for `fdatasync` and `fsync` on `FileHandle` versus their sync `fs.*` counterparts

**Impact:** Bypass of write-side permission restrictions to change atime/mtime or force kernel flush on read-only file descriptors

**Remediation:** Add the same `permission.isEnabled()` guards used in `lib/fs.js` to `futimes`, `fdatasync`, and `fsync` in `lib/internal/fs/promises.js`.
