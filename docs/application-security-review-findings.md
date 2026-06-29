# Application Security Review Findings

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-28 (scheduled automation)

Validated medium, high, and critical issues with end-to-end attack paths.

## Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Severity:** high
- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS and options.execArgv
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags
- **Impact:** Permission sandbox escalation in child including native addons and broader FS access

## HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

- **Severity:** medium
- **Location:** `lib/_http_client.js`
- **Attacker:** Any caller that can supply options.host to http.request() in an application running under --use-env-proxy with a NO_PROXY list excluding internal services
- **Controlled input:** options.host such as trusted.domain@restricted.internal.service
- **Attack path:** checkShouldUseProxy compares raw host against NO_PROXY but rewriteForProxiedHttp builds a WHATWG URL that strips userinfo before @ and sends the proxy to the hostname after @
- **Impact:** SSRF to internal services despite NO_PROXY exclusions

## Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

- **Severity:** medium
- **Location:** `lib/child_process.js`
- **Attacker:** Attacker who has achieved Object.prototype pollution in the Node.js process
- **Controlled input:** Object.prototype.NODE_OPTIONS or other env var names such as LD_PRELOAD
- **Attack path:** normalizeSpawnArguments for...in over env includes prototype chain values and appends them to child environment pairs
- **Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process

## Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message

- **Severity:** medium
- **Location:** `lib/https.js`
- **Attacker:** User of a Node application using built-in proxy support with credentialed HTTPS_PROXY who can influence outbound HTTPS fetch targets
- **Controlled input:** Target host causing proxy CONNECT to return non-200 status such as 403 or 407
- **Attack path:** onProxyData builds error from agent[kProxyConfig].href which stores raw proxyUrl including user:password; ERR_PROXY_TUNNEL propagates to request error handler and application logs or responses
- **Impact:** Disclosure of forward proxy credentials enabling SSRF pivoting past egress controls

## Source map resolution reads arbitrary files without permission checks

- **Severity:** medium
- **Location:** `lib/internal/source_map/source_map_cache.js`
- **Attacker:** Untrusted code running under Node.js permission sandbox with --deny-fs-read
- **Controlled input:** Attacker-controlled sourceMappingURL or inline source map sources array pointing at file:// paths outside allowed read scope
- **Attack path:** getOriginalSource calls readFileSync on file:// paths from map sources without process.permission.has fs.read check; stack trace and error source enrichment expose file contents
- **Impact:** Arbitrary file read bypassing fs.read permission sandbox via source map metadata

## node:ffi raw memory accessors bypass --allow-ffi permission

- **Severity:** critical
- **Location:** `lib/ffi.js`
- **Attacker:** Untrusted code running under --permission without --allow-ffi on FFI-capable builds
- **Controlled input:** Arbitrary non-zero BigInt addresses passed to getInt8 setInt8 toBuffer and related exported accessors
- **Attack path:** dlopen and export helpers call checkFFIPermission but raw memory read write exports are re-exported without guard; C++ accepts any non-null BigInt as pointer and dereferences it
- **Impact:** Arbitrary process memory read write and potential code execution without --allow-ffi

## Permission model bypass via mutable Array.prototype.includes in child_process

- **Severity:** high
- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code in parent process started with --permission --allow-child-process
- **Controlled input:** Array.prototype.includes replacement before spawn or fork
- **Attack path:** copyPermissionModelFlagsToEnv uses args.includes instead of ArrayPrototypeIncludes; poisoned prototype makes guard return early so permission flags are not copied into child NODE_OPTIONS
- **Impact:** Spawned children start without permission sandbox enabling full filesystem network and process access

## Permission model fs-write bypass via forced NODE_V8_COVERAGE in spawned children

- **Severity:** medium
- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted JavaScript under --permission with --allow-child-process when parent has NODE_V8_COVERAGE set
- **Controlled input:** spawn options.env omitting NODE_V8_COVERAGE
- **Attack path:** copyProcessEnvToEnv re-injects parent NODE_V8_COVERAGE; child setupCoverageHooks writes via native profiler without THROW_IF_INSUFFICIENT_PERMISSIONS
- **Impact:** Filesystem write bypass outside --allow-fs-write scope via coverage JSON and source-map cache files
