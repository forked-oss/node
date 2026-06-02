# Application Security Review Findings

Commit scanned: `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`

## 1. Medium: Permission model bypass via pre-existing symlinks

- Severity: Medium
- Primary location: `src/node_file.cc`
- Attacker: A local attacker, an earlier install step, or a co-tenant who can create a symlink or hardlink inside an allowlisted directory (for example via `ln -s` outside Node, not through the blocked `fs.symlink` API).
- Controlled input: Filesystem path passed to `fs.readFile`, `fs.open`, or similar under an allowed prefix (for example `/app/uploads/evil-link`).
- Attack path: The attacker plants `evil-link -> /etc/passwd` in `/app/uploads/` before or outside the restricted process. The application runs with `--permission --allow-fs-read=/app/uploads/`. The application reads `/app/uploads/evil-link`. `CheckOpenPermissions` in `src/node_file.cc` calls `THROW_IF_INSUFFICIENT_PERMISSIONS` with the literal path string. `is_tree_granted` in `src/permission/fs_permission.cc` uses lexical `PathResolve` only (no `realpath` / symlink follow). The permission check passes on the symlink path. The kernel follows the symlink and returns content from the blocked target. Regression tests in `test/fixtures/permission/fs-symlink.js` document that pre-existing symlinks are intentionally not affected by the permission model.
- Impact: Read or write access to files outside the intended permission boundary while enforcement appears active.
- Remediation: Resolve paths with `realpath` (or equivalent) before permission checks, or reject opens when the resolved target lies outside the granted tree.
