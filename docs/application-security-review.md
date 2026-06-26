# Application Security Review

Automated security findings for **node**.

- **Generated:** 2026-06-26 02:00 UTC
- **Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
- **Active findings:** 5

## Summary

| Severity | Count |
|----------|------:|
| high | 1 |
| medium | 4 |

## Findings

### 1. Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Severity:** high
- **Status:** active
- **Location:** lib/child_process.js
- **Commit:** 58cd0b8df278d1932dac036e3ea93c16d1a7aaa6
- **Detected (PST):** 2026-05-31T19:30:00-07:00
- **Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS and options.execArgv
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags
- **Impact:** Permission sandbox escalation in child including native addons and broader FS access

### 2. HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

- **Severity:** medium
- **Status:** active
- **Location:** lib/_http_client.js
- **Commit:** 58cd0b8df278d1932dac036e3ea93c16d1a7aaa6
- **Detected (PST):** 2026-06-13T19:25:43-07:00
- **Reported:** https://github.com/forked-oss/node/pull/21
- **Attacker:** Any caller that can supply options.host to http.request() in an application running under --use-env-proxy with a NO_PROXY list excluding internal services
- **Controlled input:** options.host such as trusted.domain@restricted.internal.service
- **Attack path:** checkShouldUseProxy compares raw host against NO_PROXY but rewriteForProxiedHttp builds a WHATWG URL that strips userinfo before @ and sends the proxy to the hostname after @
- **Impact:** SSRF to internal services despite NO_PROXY exclusions

### 3. Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

- **Severity:** medium
- **Status:** active
- **Location:** lib/child_process.js
- **Commit:** 58cd0b8df278d1932dac036e3ea93c16d1a7aaa6
- **Detected (PST):** 2026-06-13T19:25:43-07:00
- **Reported:** https://github.com/forked-oss/node/pull/21
- **Attacker:** Attacker who has achieved Object.prototype pollution in the Node.js process
- **Controlled input:** Object.prototype.NODE_OPTIONS or other env var names such as LD_PRELOAD
- **Attack path:** normalizeSpawnArguments for...in over env includes prototype chain values and appends them to child environment pairs
- **Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process

### 4. Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message

- **Severity:** medium
- **Status:** active
- **Location:** lib/https.js
- **Commit:** 58cd0b8df278d1932dac036e3ea93c16d1a7aaa6
- **Detected (PST):** 2026-06-21T19:05:00-07:00
- **Reported:** https://github.com/forked-oss/node/pull/26
- **Attacker:** User of a Node application using built-in proxy support with credentialed HTTPS_PROXY who can influence outbound HTTPS fetch targets
- **Controlled input:** Target host causing proxy CONNECT to return non-200 status such as 403 or 407
- **Attack path:** onProxyData builds error from agent[kProxyConfig].href which stores raw proxyUrl including user:password; ERR_PROXY_TUNNEL propagates to request error handler and application logs or responses
- **Impact:** Disclosure of forward proxy credentials enabling SSRF pivoting past egress controls

### 5. Source map resolution reads arbitrary files without permission checks

- **Severity:** medium
- **Status:** active
- **Location:** lib/internal/source_map/source_map_cache.js
- **Commit:** 58cd0b8df278d1932dac036e3ea93c16d1a7aaa6
- **Detected (PST):** 2026-06-22T19:32:34-07:00
- **Reported:** https://github.com/forked-oss/node/pull/27
- **Attacker:** Untrusted code running under Node.js permission sandbox with --deny-fs-read
- **Controlled input:** Attacker-controlled sourceMappingURL or inline source map sources array pointing at file:// paths outside allowed read scope
- **Attack path:** getOriginalSource calls readFileSync on file:// paths from map sources without process.permission.has fs.read check; stack trace and error source enrichment expose file contents
- **Impact:** Arbitrary file read bypassing fs.read permission sandbox via source map metadata
