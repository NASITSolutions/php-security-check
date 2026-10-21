# NAS Solutions — PHP Security Check

A Linux Bash utility for assessing and updating discovered PHP installations against **CVE-2026-109618** and **CVE-2026-109619**. Developed by [NAS Solutions](https://nassolutions.sa).

**Version:** 2.1 · **Advisory baseline:** 21 October 2026

## What it does

- Discovers host PHP CLI, CGI, FPM and LiteSpeed binaries, including common cPanel EasyApache, Remi and CloudLinux layouts.
- Checks executable regular files, resolves symlinks and groups repeated binaries by installation/version.
- Compares PHP versions with the upstream fixed releases below.
- Identifies owning RPM packages and records vendor/build/signature information.
- Diagnoses available package updates, repository query failures, exclusion-related blocking and changelog references to both CVEs.
- Records version-lock configuration. Detects disabled repository definitions whose URL hostnames match a built-in vendor-domain list; these are **review candidates**, not verified compatible repositories.
- Requests **one approval** before updating installed PHP packages and their dependencies through existing `dnf` or `yum` repositories.
- Restarts detected running PHP/web services only after a successful transaction that changes the tracked package versions, then checks installed versions again.
- Checks for deleted PHP executable/module mappings in running processes.
- Keeps terminal output short and colored; writes command output and detailed evidence to a private `operation.log`.

## Fixed upstream releases

| PHP branch | Minimum fixed version |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Older/EOL branches, prereleases and unreadable/unknown versions require vendor verification. A vendor may backport a fix without changing the upstream version number. Changelog matches are evidence to review, **not automatic proof that a build is patched**. This is a fixed advisory baseline, not a general scanner for future PHP vulnerabilities.

## Requirements

- Linux with RPM and `dnf` or `yum`.
- Bash 4 or later, root privileges, and an interactive terminal.
- Standard GNU/Linux command-line utilities (including `find`, `sort`, `awk`, `grep`, `readlink` and `rpm`).
- Access to configured package repositories.
- `systemctl` for automatic service discovery/restarts. Custom/panel-managed workers need separate verification.
- Optional: Python 3 for disabled repository domain classification; `timeout` for bounded version probes.

Designed for RPM-based environments such as AlmaLinux, Rocky Linux and RHEL-compatible systems. Compatibility with every distribution, control panel and package-manager version is not guaranteed. It does not support apt-based systems or macOS.

## Usage

Download or clone this repository, inspect the script, and run it from an interactive SSH terminal:

```bash
git clone https://github.com/NASITSolutions/php-security-check.git
cd php-security-check
sudo bash php-security-check.sh
```

Take a tested backup/snapshot and use a maintenance window. Approval includes PHP/dependency updates and restarts of detected running PHP/web services when tracked packages change; websites and control-panel services may be interrupted. Package-manager metadata is refreshed during diagnosis, before approval. Declining approval skips package updates.

The script runs its scans/update commands quietly and waits for completion. It is **not a detached daemon**: keep the terminal session connected.

### Optional web-root triage

```bash
sudo bash php-security-check.sh /home/example/public_html
```

This adds read-only PHP-package integrity checks, recent web-file metadata, heuristic suspicious-file matching, recent cron/systemd file metadata and recent warning-level journal entries. It can be I/O intensive. Matches can be legitimate; no malicious files are deleted or quarantined.

## Reading the result

| Result | Meaning / next step |
| --- | --- |
| Packages changed successfully | RPM versions changed; review the post-update PHP assessment separately. |
| No package changes | No tracked RPM version changed. Review enabled repositories, exclusions, locks and vendor availability in the log. |
| Update available | A newer package is visible; it is not necessarily the CVE fix. Verify the installed result. |
| Blocked by exclusion | A diagnostic query finds an update only when exclusions are ignored. Configuration is left unchanged. |
| Vendor backport evidence | Both CVEs appear in the installed package changelog. Verify the exact vendor advisory/build. |
| Upgrade or ELS required | Older cPanel PHP may require a supported-version migration or vendor Extended Lifecycle Support. Test application compatibility first. |
| Disabled official-domain candidate | Review repository ownership, compatibility, signing, subscription and production status manually before enabling. |
| Fixed | The discovered binary meets the upstream release threshold for these two CVEs only. |
| Unresolved | Older, unknown, EOL or unreadable runtime remains; remediation is not confirmed. |

The script **does not** install new repositories, enable disabled ones, switch module streams, remove exclusions/version locks or bypass GPG checking. It does not migrate PHP major/minor branches or remove EOL installations automatically.

## Logs

Each run creates a root-private directory such as:

```text
/var/tmp/php-security-XXXXXXXX/operation.log
```

The final screen prints the exact path. The log includes command output, package inventories, before/after runtime details, repository diagnostics, changelogs, service restart results and supplemental evidence. Side files remain in the same directory. Log files may contain sensitive operational information: review and redact them before sharing. Do not commit production logs to this public repository.

## Scope and limitations

**Patching does not prove that a host is free of compromise.** This tool does not send exploit requests and cannot certify that exploitation has not occurred. It does not remove persistence or replace EDR/incident response.

Discovery covers common host locations, not every possible embedded runtime. Containers, virtual machines, chroots, custom PHP builds, Apache modules and all vhosts/pools must be checked separately. Service-active status is not an application health test. Absence of deleted mappings does not prove every worker is patched. Vendor backports remain unresolved until verified independently.

Exit status `0` means no unresolved discovered runtime/update/restart/stale-mapping condition was flagged by the script; it is not a clean-host certificate. Exit status `1` generally indicates an unresolved condition or failure; other command failures can retain their command exit status. Interrupted runs use status `130`.

## Validation

Bash syntax checks and focused mocked diagnosis tests were performed (update available, exclusion blocking, repository failure, no update), along with directory-filtering and installation-grouping checks. This does not constitute full production integration testing across supported distributions.

## References

- [PHP official security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018)
- [PHP advisory: OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory: stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

## Copyright

Copyright (c) 2026 NAS Solutions. All rights reserved.

Website: https://nassolutions.sa

Public visibility does not grant an open-source license. No additional license is granted by this repository.
