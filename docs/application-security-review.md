# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-16 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer triage; follow each project's security disclosure process before public discussion.

## 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS and options.execArgv
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags
- **Impact:** Permission sandbox escalation in child including native addons and broader FS access

## 2. [MEDIUM] HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

- **Location:** `lib/_http_client.js`
- **Attacker:** Any caller that can supply options.host to http.request() in an application running under --use-env-proxy with a NO_PROXY list excluding internal services
- **Controlled input:** options.host such as trusted.domain@restricted.internal.service
- **Attack path:** checkShouldUseProxy compares raw host against NO_PROXY but rewriteForProxiedHttp builds a WHATWG URL that strips userinfo before @ and sends the proxy to the hostname after @
- **Impact:** SSRF to internal services despite NO_PROXY exclusions

## 3. [MEDIUM] Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

- **Location:** `lib/child_process.js`
- **Attacker:** Attacker who has achieved Object.prototype pollution in the Node.js process
- **Controlled input:** Object.prototype.NODE_OPTIONS or other env var names such as LD_PRELOAD
- **Attack path:** normalizeSpawnArguments for...in over env includes prototype chain values and appends them to child environment pairs
- **Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process
