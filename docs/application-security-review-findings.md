# Application Security Review Findings

Repository: [node](https://github.com/forked-oss/node)

Total active findings: 12

## Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Severity:** high

**Location:** lib/child_process.js

**Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process

**Controlled input:** options.env.NODE_OPTIONS and options.execArgv

**Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags

**Impact:** Permission sandbox escalation in child including native addons and broader FS access

## HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

**Severity:** medium

**Location:** lib/_http_client.js

**Attacker:** Any caller that can supply options.host to http.request() in an application running under --use-env-proxy with a NO_PROXY list excluding internal services

**Controlled input:** options.host such as trusted.domain@restricted.internal.service

**Attack path:** checkShouldUseProxy compares raw host against NO_PROXY but rewriteForProxiedHttp builds a WHATWG URL that strips userinfo before @ and sends the proxy to the hostname after @

**Impact:** SSRF to internal services despite NO_PROXY exclusions

## Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

**Severity:** medium

**Location:** lib/child_process.js

**Attacker:** Attacker who has achieved Object.prototype pollution in the Node.js process

**Controlled input:** Object.prototype.NODE_OPTIONS or other env var names such as LD_PRELOAD

**Attack path:** normalizeSpawnArguments for...in over env includes prototype chain values and appends them to child environment pairs

**Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process

## Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message

**Severity:** medium

**Location:** lib/https.js

**Attacker:** User of a Node application using built-in proxy support with credentialed HTTPS_PROXY who can influence outbound HTTPS fetch targets

**Controlled input:** Target host causing proxy CONNECT to return non-200 status such as 403 or 407

**Attack path:** onProxyData builds error from agent[kProxyConfig].href which stores raw proxyUrl including user:password; ERR_PROXY_TUNNEL propagates to request error handler and application logs or responses

**Impact:** Disclosure of forward proxy credentials enabling SSRF pivoting past egress controls

## Source map resolution reads arbitrary files without permission checks

**Severity:** medium

**Location:** lib/internal/source_map/source_map_cache.js

**Attacker:** Untrusted code running under Node.js permission sandbox with --deny-fs-read

**Controlled input:** Attacker-controlled sourceMappingURL or inline source map sources array pointing at file:// paths outside allowed read scope

**Attack path:** getOriginalSource calls readFileSync on file:// paths from map sources without process.permission.has fs.read check; stack trace and error source enrichment expose file contents

**Impact:** Arbitrary file read bypassing fs.read permission sandbox via source map metadata

## node:ffi raw memory accessors bypass --allow-ffi permission

**Severity:** critical

**Location:** lib/ffi.js

**Attacker:** Untrusted code running under --permission without --allow-ffi on FFI-capable builds

**Controlled input:** Arbitrary non-zero BigInt addresses passed to getInt8 setInt8 toBuffer and related exported accessors

**Attack path:** dlopen and export helpers call checkFFIPermission but raw memory read write exports are re-exported without guard; C++ accepts any non-null BigInt as pointer and dereferences it

**Impact:** Arbitrary process memory read write and potential code execution without --allow-ffi

## Permission model bypass via mutable Array.prototype.includes in child_process

**Severity:** high

**Location:** lib/child_process.js

**Attacker:** Untrusted code in parent process started with --permission --allow-child-process

**Controlled input:** Array.prototype.includes replacement before spawn or fork

**Attack path:** copyPermissionModelFlagsToEnv uses args.includes instead of ArrayPrototypeIncludes; poisoned prototype makes guard return early so permission flags are not copied into child NODE_OPTIONS

**Impact:** Spawned children start without permission sandbox enabling full filesystem network and process access

## Permission model fs-write bypass via forced NODE_V8_COVERAGE in spawned children

**Severity:** medium

**Location:** lib/child_process.js

**Attacker:** Untrusted JavaScript under --permission with --allow-child-process when parent has NODE_V8_COVERAGE set

**Controlled input:** spawn options.env omitting NODE_V8_COVERAGE

**Attack path:** copyProcessEnvToEnv re-injects parent NODE_V8_COVERAGE; child setupCoverageHooks writes via native profiler without THROW_IF_INSUFFICIENT_PERMISSIONS

**Impact:** Filesystem write bypass outside --allow-fs-write scope via coverage JSON and source-map cache files

## Worker execArgv permission escalation bypasses parent permission sandbox

**Severity:** high

**Location:** src/node_worker.cc

**Attacker:** Untrusted code in a parent process started with --permission and --allow-worker but without broader allow flags

**Controlled input:** worker_threads Worker execArgv array containing --allow-net --allow-child-process or other permission-namespace flags

**Attack path:** WorkerThread constructs per-isolate options by parsing attacker-supplied execArgv with kDisallowedInEnvvar; EnvironmentOptions allow flags are accepted unlike child_process copyPermissionModelFlagsToEnv clamping

**Impact:** Complete permission sandbox escape in worker threads enabling network filesystem and subprocess access denied to the parent

## TCPWrap Open bypasses net permission check on pre-adopted socket fds

**Severity:** medium

**Location:** src/tcp_wrap.cc

**Attacker:** Untrusted JavaScript running under --permission without --allow-net

**Controlled input:** Integer file descriptor passed to new net.Socket({ fd }) or TCPWrap.open(fd)

**Attack path:** TCPWrap::Open calls uv_tcp_open with no THROW_IF_INSUFFICIENT_PERMISSIONS check, unlike Bind, Connect, and Listen. Attacker adopts an inherited or IPC-transferred connected socket and reads/writes despite net denial.

**Impact:** Network I/O bypass enabling data exfiltration or abuse of inherited sockets (e.g. docker.sock UDS if an FD is available).

## CPU and heap profiler exit writes bypass fs-write permission

**Severity:** medium

**Location:** src/inspector_profiler.cc

**Attacker:** Untrusted code influencing process startup with profiler flags under --permission without --allow-fs-write

**Controlled input:** --cpu-prof, --cpu-prof-dir, --heap-prof, or --heap-prof-dir via argv or NODE_OPTIONS

**Attack path:** V8ProfilerConnection::WriteProfile calls WriteFileSync directly at process exit without permission-checked FS APIs.

**Impact:** Arbitrary filesystem write at teardown to attacker-chosen directories.

## ESM getPackageScopeConfig reads ancestor package.json without fs.read permission checks *New in 2026-07-03 scheduled review*

**Severity:** medium

**Location:** src/node_modules.cc

**Attacker:** Untrusted ESM code running under --permission with restricted --allow-fs-read

**Controlled input:** Import specifier paths whose ancestor directories contain package.json outside the read sandbox

**Attack path:** GetPackageScopeConfig walks parent directories calling GetPackageJSON on each package.json path without process.permission fs.read checks

**Impact:** Filesystem reconnaissance and package.json metadata disclosure outside the read permission model
