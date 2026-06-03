# Application Security Review

Commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`  
Branch: `cursor/application-security-review-116d`

## Findings

### 1. [High] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing `child_process` env while parent uses `--permission --allow-child-process`
- **Controlled input:** `options.env.NODE_OPTIONS` and `options.execArgv`
- **Attack path:** `copyPermissionModelFlagsToEnv` skips copying parent permission flags when `NODE_OPTIONS` already contains `--permission` or `execArgv` includes `--permission`; the child then parses attacker-chosen allow flags.
- **Impact:** Permission sandbox escalation in spawned children, including native addons and broader filesystem access.
- **Remediation:** Never treat pre-set `NODE_OPTIONS` as authoritative for permission inheritance; merge parent permission flags unconditionally or strip untrusted `NODE_OPTIONS` before spawn.

### 2. [Medium] HTTP proxy absolute-form rewrite allows SSRF via scheme-relative request path

- **Location:** `lib/_http_client.js`
- **Attacker:** Remote user controlling HTTP request `path` while the application validates only `hostname`
- **Controlled input:** `options.path` such as `//169.254.169.254/latest/meta-data/` when `HTTP_PROXY` is configured
- **Attack path:** `checkShouldUseProxy` keys off `reqOptions.host`; `rewriteForProxiedHttp` uses `new URL(req.path, 'http://' + host)` so a scheme-relative path replaces the host; the proxied request line targets an attacker-chosen absolute URL.
- **Impact:** SSRF to internal IPs and cloud metadata despite hostname allowlists that omit path validation.
- **Remediation:** Reject scheme-relative and absolute URLs in `req.path` before proxy rewriting, or validate the post-rewrite target host against the same policy used for direct requests.
