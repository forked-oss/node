# Application Security Review — node

Scanned commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
Detected: 2026-06-02T03:19:18-07:00

Validated medium, high, and critical findings with end-to-end attack paths.

## 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Location:** `lib/child_process.js`

**Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process

**Controlled input:** options.env.NODE_OPTIONS and options.execArgv

**Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags

**Impact:** Permission sandbox escalation in child including native addons and broader FS access

## 2. [MEDIUM] Permission model read checks do not follow symlink targets allowing sandbox bypass

**Location:** `src/node_file.cc`

**Attacker:** Supply-chain actor or local attacker who can pre-create symlinks before permission-restricted startup

**Controlled input:** Symlink path granted via --allow-fs-read pointing to denied target

**Attack path:** CheckOpenPermissions validates symlink path string only; uv_fs_open follows symlink and reads out-of-scope files

**Impact:** Confidentiality bypass of --permission sandbox reading arbitrary files outside granted paths

## 3. [MEDIUM] Bundled npm pacote remote fetch lacks SSRF protections on resolved tarball URLs

**Location:** `deps/npm/node_modules/pacote/lib/remote.js`

**Attacker:** Supply-chain actor controlling dependency coordinates or registry packument dist.tarball

**Controlled input:** HTTP(S) dependency URL or registry dist.tarball pointing to internal/metadata hosts

**Attack path:** RemoteFetcher passes this.resolved directly to make-fetch-happen fetch with no private-IP blocking

**Impact:** SSRF from CI/build hosts to cloud metadata and internal services during npm install
