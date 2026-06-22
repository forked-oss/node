# Application Security Review Findings

Scanned commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## High: Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

- **Location:** `lib/child_process.js`
- **Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process
- **Controlled input:** options.env.NODE_OPTIONS and options.execArgv
- **Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission substring or execArgv has --permission; child parses attacker allow flags
- **Impact:** Permission sandbox escalation in child including native addons and broader FS access
- **Remediation:** Always propagate parent permission flags regardless of child NODE_OPTIONS content

## Medium: HTTP proxy NO_PROXY bypass via userinfo '@' in options.host rewrites proxy target to restricted internal host

- **Location:** `lib/_http_client.js`
- **Attacker:** Any caller that can supply options.host to http.request() in an application running under --use-env-proxy with a NO_PROXY list excluding internal services
- **Controlled input:** options.host such as trusted.domain@restricted.internal.service
- **Attack path:** checkShouldUseProxy compares raw host against NO_PROXY but rewriteForProxiedHttp builds a WHATWG URL that strips userinfo before @ and sends the proxy to the hostname after @
- **Impact:** SSRF to internal services despite NO_PROXY exclusions
- **Remediation:** Reject hosts containing @ in proxy routing or apply NO_PROXY check after URL normalization

## Medium: Object.prototype pollution injects arbitrary environment variables into spawned child processes via intentional for...in enumeration

- **Location:** `lib/child_process.js`
- **Attacker:** Attacker who has achieved Object.prototype pollution in the Node.js process
- **Controlled input:** Object.prototype.NODE_OPTIONS or other env var names such as LD_PRELOAD
- **Attack path:** normalizeSpawnArguments for...in over env includes prototype chain values and appends them to child environment pairs
- **Impact:** Prototype pollution escalates to arbitrary code execution in every subsequently spawned child process
- **Remediation:** Use Object.hasOwn or Object.keys when iterating env objects

## Medium: Proxy credentials in HTTPS_PROXY user:password leaked into ERR_PROXY_TUNNEL error message

- **Location:** `lib/https.js`
- **Attacker:** User of a Node application using built-in proxy support with credentialed HTTPS_PROXY who can influence outbound HTTPS fetch targets
- **Controlled input:** Target host causing proxy CONNECT to return non-200 status such as 403 or 407
- **Attack path:** onProxyData builds error from agent[kProxyConfig].href which stores raw proxyUrl including user:password; ERR_PROXY_TUNNEL propagates to request error handler and application logs or responses
- **Impact:** Disclosure of forward proxy credentials enabling SSRF pivoting past egress controls
- **Remediation:** Strip credentials from proxy URL in error messages and stored href
