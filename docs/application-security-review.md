# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-14 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer triage; follow each project's security disclosure process before public discussion.

## 1. [MEDIUM] HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

- **Location:** `lib/_http_client.js`
- **Attacker:** Any caller that can supply `options.host` to `http.request()` in an application running under `--use-env-proxy` with a NO_PROXY list excluding internal services
- **Controlled input:** `options.host` such as `trusted.domain@restricted.internal.service`
- **Attack path:** `checkShouldUseProxy` compares the raw host string against NO_PROXY, but `rewriteForProxiedHttp` builds a WHATWG URL from the same string; the URL parser treats text before `@` as userinfo and connects the proxy to the hostname after `@`, which was never checked against NO_PROXY
- **Impact:** SSRF to internal services despite NO_PROXY exclusions

## 2. [MEDIUM] Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

- **Location:** `lib/child_process.js`
- **Attacker:** Attacker who has achieved `Object.prototype` pollution in the Node.js process
- **Controlled input:** `Object.prototype.NODE_OPTIONS` or other env var names such as `LD_PRELOAD`
- **Attack path:** `normalizeSpawnArguments` spreads `options.env` then runs `for (const key in env)` with an explicit comment that prototype values are intentionally included; polluted keys become real child environment variables
- **Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process
