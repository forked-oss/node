# Application Security Review Findings

Scanned commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## Medium: Permission model module resolution leaks filesystem existence outside allowed paths

**Location:** `src/node_file.cc`

**Attacker:** Untrusted JavaScript running under `node --permission` with a narrow `--allow-fs-read` grant (e.g., only the entry script).

**Controlled input:** Any absolute path passed to `require()` or ESM `import()` (e.g., `/etc/passwd`, `/var/lib/app/secrets/`).

**Attack path:** CJS resolution calls `Module._stat()` → `internalModuleStat()` with no permission check. ESM resolution in `resolve.js` also calls `internalModuleStat()` before load-time permission enforcement. Return value distinguishes file (`0`), directory (`1`), and missing path (`< 0`), producing different error codes/messages. Attacker iterates paths to map the host filesystem outside the allowlist.

**Impact:** Filesystem reconnaissance/oracle against paths the operator intended to hide—file vs directory vs absent—without `--allow-fs-read` covering those paths.

**Remediation:** Enforce filesystem-read permission checks in `InternalModuleStat` before calling `uv_fs_stat`.

## Medium: ESM package-scope resolution reads package.json files without filesystem-read permission checks

**Location:** `src/node_modules.cc`

**Attacker:** Untrusted JavaScript under `node --permission` with restricted `--allow-fs-read`.

**Controlled input:** A `file://` URL in dynamic `import()` / ESM resolution pointing at (or under) a directory outside the allowlist.

**Attack path:** Format/resolution calls `getPackageScopeConfig()` → native `GetPackageScopeConfig`. That walks parent directories and calls `GetPackageJSON()` → `ReadFileSync()` for each `package.json` on the path with no `THROW_IF_INSUFFICIENT_PERMISSIONS`. Parsed fields (`name`, `main`, `type`, `exports`, `imports`) are cached and used for resolution. Actual module body read is blocked later, but `package.json` content was already read from disk.

**Impact:** Unauthorized read of `package.json` metadata (including `exports`/`imports` maps that reveal internal module layout) from paths outside `--allow-fs-read`.

**Remediation:** Add filesystem-read permission checks to `GetPackageJSON()` / `GetPackageScopeConfig`, matching `ReadPackageJSON()`.
