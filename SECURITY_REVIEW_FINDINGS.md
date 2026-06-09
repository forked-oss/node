# Application Security Review Findings

Scanned commit: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## High: Worker thread drops parent --permission sandbox when execArgv or custom env is supplied

- **Location:** `src/node_worker.cc`
- **Attacker:** Untrusted JavaScript running under `--permission` with only `--allow-worker` (and limited `--allow-fs-*`)
- **Controlled input:** `new Worker(code, { eval: true, execArgv: [] })` or `{ execArgv: ['--allow-child-process', ...] }` or `{ env: { NODE_OPTIONS: '...' } }`
- **Attack path:** `Worker::New` allocates a fresh `PerIsolateOptions` when `execArgv` is an array instead of cloning the parent; an explicit `execArgv` array replaces the parent's `exec_argv` so no `--permission` flag is parsed; `Environment` only enables the permission model when `options_->permission` is set; worker runs without the sandbox and can use `child_process`, unrestricted `fs`, `net`, etc.
- **Impact:** Full sandbox escape inside the worker: arbitrary process execution, unrestricted filesystem/network access, bypassing all permission flags the parent did not grant
- **Remediation:** Always inherit parent permission flags into worker `PerIsolateOptions`, or reject custom `execArgv`/`env` when parent has `--permission` enabled
