# Application Security Review

Commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## New Findings (2026-06-27)

### node:ffi raw memory accessors bypass --allow-ffi permission (Critical)

- **Location:** `lib/ffi.js`
- **Attacker:** Untrusted code running under `--permission` without `--allow-ffi` on FFI-capable builds
- **Controlled input:** Arbitrary non-zero BigInt addresses passed to `getInt8`, `setInt8`, `toBuffer`, and related exported accessors
- **Attack path:** `dlopen`, `dlsym`, and export helpers call `checkFFIPermission()`, but raw memory read/write exports are re-exported from `internalBinding('ffi')` with no permission guard. C++ accepts any non-null BigInt as a pointer and dereferences it.
- **Impact:** Arbitrary process memory read/write and potential code execution without `--allow-ffi`
- **Remediation:** Wrap all memory accessor exports with `checkFFIPermission()` or enforce the permission in the C++ binding

### Permission model bypass via mutable Array.prototype.includes in child_process (High)

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code in a parent process started with `--permission --allow-child-process`
- **Controlled input:** `Array.prototype.includes` replacement before `spawn()`/`fork()`
- **Attack path:** `copyPermissionModelFlagsToEnv()` uses `args.includes('--permission')` instead of the safe primordial `ArrayPrototypeIncludes`. A poisoned prototype makes the guard return early, so permission flags are not copied into child `NODE_OPTIONS`.
- **Impact:** Spawned children start without the permission sandbox, enabling full filesystem, network, and process access
- **Remediation:** Use `ArrayPrototypeIncludes` for all security-sensitive `includes()` checks in `copyPermissionModelFlagsToEnv()`
