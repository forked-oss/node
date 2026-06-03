# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-03

## Summary

**2** validated finding(s) at medium severity or above.

### 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Location:** `lib/child_process.js`

**Attacker:** Untrusted code influencing `child_process` environment while parent runs with `--permission --allow-child-process`

**Controlled input:** `options.env.NODE_OPTIONS` and `options.execArgv`

**Attack path:** `copyPermissionModelFlagsToEnv` skips copying parent permission flags when `NODE_OPTIONS` contains a `--permission` substring or when `execArgv` already includes `--permission`; the child parses attacker-supplied allow flags.

**Impact:** Permission sandbox escalation in the child, including native addons and broader filesystem access.

**Remediation:** Always propagate parent permission flags to children; ignore or strip untrusted `--permission` entries from `NODE_OPTIONS`/`execArgv` unless explicitly allowlisted.

### 2. [HIGH] Duck-typed URL objects inject socketPath/createConnection into http(s).request

**Location:** `lib/internal/url.js`

**Attacker:** Remote or local party who can supply a URL-like object to application code that passes it to `http.request`, `https.request`, or `http.get` (e.g. JSON body, deserialized API payload)

**Controlled input:** Plain object satisfying `isURL()`: `{ href, protocol }` with `auth === undefined` and `path === undefined`, plus extra enumerable fields such as `socketPath` or `createConnection`

**Attack path:** `isURL()` only checks `href`, `protocol`, and absence of legacy `auth`/`path`. `urlToHttpOptions()` spreads all enumerable own properties (`...url`) without stripping `socketPath`/`createConnection`. `_http_client.js` and `https.js` use `isURL(input)` then `urlToHttpOptions`; `ClientRequest` connects via `net.createConnection` to the Unix socket instead of the HTTP host in `href`.

**Impact:** Client-side SSRF to local Unix domain sockets (Docker API, DB sockets, internal daemons). `createConnection` injection allows fully attacker-controlled socket establishment. `fetch()`/undici string URLs are not affected.

**Remediation:** Strip or denylist `socketPath`, `createConnection`, and other connection overrides in `urlToHttpOptions`; tighten `isURL()` to reject objects with unexpected enumerable keys; document that only genuine `URL` instances should be passed from untrusted input.
