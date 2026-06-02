# Application Security Review — node

**Scanned commit:** `58cd0b8df278d1932dac036e3ea93c16d1a7aaa6`
**Review date:** 2026-06-02 (scheduled cron)
**Branch:** `cursor/application-security-review-bcf6`

## Summary

This review documents **2** validated finding(s) at medium severity or above.

## 1. [HIGH] Permission model bypass via attacker-controlled NODE_OPTIONS in child_process spawn/fork

**Location:** `lib/child_process.js`

**Attacker:** Untrusted code influencing child_process env while parent uses --permission --allow-child-process

**Controlled input:** options.env.NODE_OPTIONS and options.execArgv

**Attack path:** copyPermissionModelFlagsToEnv skips parent flags when NODE_OPTIONS contains --permission

**Impact:** Permission sandbox escalation in child

## 2. [HIGH] Permission model bypass via pre-existing symlinks for read and write **[NEW this scan]**

**Location:** `src/permission/fs_permission.cc`

**Attacker:** Untrusted JavaScript under --permission or supply-chain symlink planting

**Controlled input:** Path under allowed directory via pre-existing symlink to blocked target

**Attack path:** FSPermission::is_granted checks symlink path only; uv_fs follows to outside scope

**Impact:** Confidentiality and integrity bypass of permission model sandbox
