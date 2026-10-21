#!/usr/bin/env bash
# Copyright (c) 2026 NAS Solutions. All rights reserved.
# https://nassolutions.sa
# PHP advisory snapshot: 2026-10-21. No exploit requests are sent.
# https://cert.europa.eu/publications/security-advisories/2026-018
# https://www.php.net/archive/2026.php#2026-10-21-5
set -Eeuo pipefail
((BASH_VERSINFO[0] >= 4)) || { echo "Bash 4+ required (Linux)."; exit 1; }
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077
[[ ${EUID} -eq 0 ]] || { echo 'Run with sudo bash php-security-check.sh'; exit 1; }
[[ -t 0 ]] || { echo 'Interactive terminal required.'; exit 1; }
for c in rpm find sort awk tee mktemp timeout; do command -v "$c" >/dev/null || { echo "Missing: $c"; exit 1; }; done
if command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
else echo 'This script requires yum or dnf and RPM.'; exit 1; fi
OUT=$(mktemp -d /var/tmp/php-security-XXXXXXXX)
LOG="$OUT/operation.log"
exec 3>&1
exec >>"$LOG" 2>&1
trap 'rc=$?; echo "ERROR line $LINENO exit=$rc command=$BASH_COMMAND"; printf "\033[1;31mERROR: operation failed at line %s (exit %s). Log: %s\033[0m\n" "$LINENO" "$rc" "$LOG" >&3; exit "$rc"' ERR
trap 'printf "\033[1;33mInterrupted; see %s\033[0m\n" "$LOG" >&3; exit 130' INT TERM
RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[1;36m'; RESET=$'\033[0m'
color() { printf '%s%s%s\n' "$1" "$2" "$RESET" >&3; printf '%s\n' "$2"; }
# Stream only error lines to the terminal; keep all command output in its log.
ERROR_COUNT=0
REPO_FAILED=0
PM_SEQUENCE=0
pm_run() {
  local mode=$1 rc=0 capture worker monitor
  shift
  PM_SEQUENCE=$((PM_SEQUENCE + 1))
  capture="$OUT/pm-$PM_SEQUENCE.txt"
  : > "$capture"
  : > "$capture"
  : > "$capture"
  : > "$capture"
  : > "$capture"
  if [[ "$mode" == query ]]; then
    timeout --signal=TERM --kill-after=5 90 "$PM" --setopt=timeout=15 --setopt=retries=1 "$@" >"$capture" 2>&1 &
  else
    # Never forcibly terminate a package transaction: RPM may be writing its database.
    "$PM" --setopt=timeout=15 --setopt=retries=1 "$@" >"$capture" 2>&1 &
  fi
  worker=$!
  (
    trap - ERR
    tail -n +1 --pid="$worker" -f "$capture" |
      awk 'tolower($0) ~ /error|failed|fatal|cannot|could not|curl.*\([0-9]+\)/ {
        if (++n <= 4) {printf "\033[1;31m  ERROR: %s\033[0m\n", $0; fflush()}
      }' >&3
  ) &
  monitor=$!
  wait "$worker" || rc=$?
  wait "$monitor" || true
  cat "$capture"
  case "$rc" in
    0|100) ;;
    *) ERROR_COUNT=$((ERROR_COUNT + 1))
       if [[ "$rc" == 124 || "$rc" == 137 ]]; then
         color "$RED" "  ERROR: $PM repository query timed out (90s); see $LOG"
       else
         color "$RED" "  ERROR: $PM ${*} failed (exit $rc); see $LOG"
       fi;;
  esac
  return "$rc"
}
color "$BLUE" 'NAS Solutions | PHP Security Check v2.2'
color "$GREEN" 'Copyright (c) 2026 NAS Solutions. All rights reserved.'
color "$BLUE" 'https://nassolutions.sa'
# All diagnostic commands use the log by default. FD 3 is reserved for minimal UI.

UPDATE=NOT_NEEDED; RESTART=NOT_ATTEMPTED; CHANGED=0; FAILED=0
WEBROOT=${1:-}
if [[ -n "$WEBROOT" && ( "$WEBROOT" != /* || ! -d "$WEBROOT" || "$WEBROOT" == / ) ]]; then
  echo 'Optional argument must be an absolute web-root directory, other than /.'; exit 1
fi
echo "PHP SECURITY CHECK — $(date -u +%FT%TZ)"
echo "Copyright (c) 2026 NAS Solutions. All rights reserved."
echo "https://nassolutions.sa"
echo "Report: $OUT (private; may contain sensitive operational data)"
echo 'Scope: host RPM packages and discovered PHP runtimes. Containers/VMs/chroots require separate checks.'
echo 'A patched version does NOT prove absence of a previous compromise.'
echo 'Fixed upstream releases: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.'
echo 'Repository availability changes over time; no arbitrary third-party repositories are installed.'
echo 'Older/EOL, prerelease, unknown and vendor-backported versions remain UNVERIFIED.'
echo 'Take a tested backup/snapshot first. Updates and restarts may interrupt websites.'

echo "OS and repository context:"
cat /etc/os-release 2>/dev/null || true
pm_run query repolist || REPO_FAILED=1
packages() {
  rpm -qa --qf '%{NAME}\n' | awk '/^(php($|-)|php[0-9]+-php($|-)|ea-php[0-9]+($|-)|alt-php([0-9]+|-internal)($|-)|lsphp[0-9]*($|-))/' | sort -u
}
mapfile -t PKGS < <(packages)
printf '%s\n' "${PKGS[@]}" > "$OUT/packages.txt"
if ((${#PKGS[@]})); then
  rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "${PKGS[@]}" > "$OUT/rpm-before.txt"
  cat "$OUT/rpm-before.txt"
fi
# Inspect version output only, with configuration/extensions disabled.
# No untrusted PHP application files are executed.
inventory() {
  local stage=$1 p v status minimum branch
  local -a paths=()
  if ((${#PKGS[@]})); then
    mapfile -t paths < <(rpm -ql "${PKGS[@]}" | awk '/\/(php|php-cgi|php-fpm|lsphp)$/')
  fi
  while IFS= read -r p; do paths+=("$p"); done < <(
    find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /usr/local/lsws /usr/local/php \
      -maxdepth 7 \( -type f -o -type l \) \( -name php -o -name php-cgi -o -name php-fpm -o -name lsphp \) \
      -print 2>"$OUT/discovery-errors-$stage.txt" || true
  )
  : > "$OUT/versions-$stage.tsv"
  while IFS= read -r p; do
    [[ -n "$p" && -f "$p" && -x "$p" ]] || continue
    p=$(readlink -f -- "$p") || continue
    v=$({ if command -v timeout >/dev/null; then timeout 10 "$p" -n -v; else "$p" -n -v; fi; } 2>/dev/null | awk '/^PHP [0-9]/{print $2; exit}') || v=''
    status=UNVERIFIED; minimum='unknown'
    if [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
      branch=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
      case "$branch" in
        8.2) minimum=8.2.35;; 8.3) minimum=8.3.36;; 8.4) minimum=8.4.27;; 8.5) minimum=8.5.12;;
      esac
      if [[ "$minimum" != unknown ]]; then
        if [[ $(printf '%s\n' "$minimum" "$v" | sort -V | head -n1) == "$minimum" ]]; then
          status=UPSTREAM_FIXED
        else status=BELOW_UPSTREAM_FIX_VENDOR_CHECK_REQUIRED; fi
      fi
    fi
    printf '%s\t%s\t%s\t%s\n' "$p" "${v:-UNREADABLE}" "$minimum" "$status" >> "$OUT/versions-$stage.tsv"
    echo "$p | ${v:-UNREADABLE} | $status | required $minimum"
  done < <(printf '%s\n' "${paths[@]}" | sort -u)
  sort -u "$OUT/versions-$stage.tsv" -o "$OUT/versions-$stage.tsv"
  [[ -s "$OUT/versions-$stage.tsv" ]] || echo 'NO PHP BINARIES FOUND: not proof that PHP is absent (embedded runtimes/mod_php may exist).'
}
group_inventory() {
  awk -F '\t' 'BEGIN {OFS="\t"} {
    root=$1
    if (root ~ /\/usr\/(bin|sbin)\//) sub(/\/usr\/(bin|sbin)\/.*/,"",root)
    else if (root ~ /\/(bin|sbin)\//) sub(/\/(bin|sbin)\/.*/,"",root)
    if(root=="") root="system"
    key=root OFS $2 OFS $3 OFS $4
    if(!seen[key]++) print key
  }' "$OUT/versions-$1.tsv" | sort -u > "$OUT/groups-$1.tsv"
}
# Read-only diagnosis. No repo configuration, stream, exclusions or locks are changed.
diagnose_updates() {
  local stage=$1 path version minimum state owner vendor result rc
  local file="$OUT/diagnosis-$stage.tsv"
  : > "$file"
  if ((REPO_FAILED == 0)); then
    pm_run query repolist --all > "$OUT/repositories-$stage.txt" 2>&1 || REPO_FAILED=1
  fi
  grep -RniE '^[[:space:]]*(exclude|excludepkgs|includepkgs)[[:space:]]*=' \
    /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/ > "$OUT/exclusions-$stage.txt" 2>&1 || true
  # Existing locks are evidence only. Never remove them automatically.
  for lock in /etc/dnf/plugins/versionlock.list /etc/yum/pluginconf.d/versionlock.list; do
    if [[ -f "$lock" ]]; then echo "=== $lock ==="; cat "$lock"; fi
  done > "$OUT/versionlocks-$stage.txt"
  : > "$OUT/diagnosed-owners-$stage.txt"
  while IFS=$'\t' read -r path version minimum state; do
    [[ "$state" != UPSTREAM_FIXED ]] || continue
    if ! owner=$(rpm -qf --qf '%{NAME}' -- "$path" 2>/dev/null); then
      printf '%s\tUNMANAGED\tmanual source/embedded runtime remediation\n' "$path" >> "$file"
      continue
    fi
    grep -Fxq -- "$owner" "$OUT/diagnosed-owners-$stage.txt" && continue
    printf '%s\n' "$owner" >> "$OUT/diagnosed-owners-$stage.txt"
    vendor=$(rpm -q --qf '%{VENDOR} | %{VERSION}-%{RELEASE} | %{SIGPGP:pgpsig}' "$owner" 2>/dev/null) || vendor=unknown
    echo "Runtime: $path; package: $owner; vendor/signature: $vendor"
    rpm -q --changelog "$owner" > "$OUT/changelog-$stage-$owner.txt" 2>&1 || true
    if grep -q 'CVE-2026-109618' "$OUT/changelog-$stage-$owner.txt" &&
       grep -q 'CVE-2026-109619' "$OUT/changelog-$stage-$owner.txt"; then
      printf '%s\tBACKPORT_EVIDENCE\tchangelog mentions both CVEs; verify exact vendor advisory/build\n' "$owner" >> "$file"
    fi
    if ((REPO_FAILED)); then
      printf '%s\tREPOSITORY_QUERY_FAILED\tSkipped repeated network query after repository failure\n' "$owner" >> "$file"
      continue
    fi
    rc=0
    pm_run query check-update "$owner" > "$OUT/check-update-$stage-$owner.txt" 2>&1 || rc=$?
    case "$rc" in
      100) result=UPDATE_AVAILABLE;;
      0) result=NO_ENABLED_REPO_UPDATE;;
      *) result=REPOSITORY_QUERY_FAILED;;
    esac
    printf '%s\t%s\t%s\n' "$owner" "$result" "$vendor" >> "$file"
    if [[ "$result" == REPOSITORY_QUERY_FAILED ]]; then
      REPO_FAILED=1
      continue
    fi
    # A diagnostic comparison only; real updates continue to respect exclusions.
    rc=0
    pm_run query --disableexcludes=all check-update "$owner" > "$OUT/no-excludes-$stage-$owner.txt" 2>&1 || rc=$?
    if [[ "$rc" != 0 && "$rc" != 100 ]]; then REPO_FAILED=1; continue; fi
    if [[ "$rc" != 0 && "$rc" != 100 ]]; then REPO_FAILED=1; continue; fi
    if [[ "$rc" != 0 && "$rc" != 100 ]]; then REPO_FAILED=1; continue; fi
    if [[ "$rc" != 0 && "$rc" != 100 ]]; then REPO_FAILED=1; continue; fi
    if [[ "$rc" != 0 && "$rc" != 100 ]]; then REPO_FAILED=1; continue; fi
    if [[ "$result" == NO_ENABLED_REPO_UPDATE && "$rc" == 100 ]]; then
      printf '%s\tBLOCKED_BY_EXCLUSION\tupdate appears only when excludes are ignored; configuration unchanged\n' "$owner" >> "$file"
    fi
    pm_run query list --showduplicates "$owner" > "$OUT/available-$stage-$owner.txt" 2>&1 || REPO_FAILED=1
    if [[ "$owner" == ea-php7[0-3]* ]]; then
      printf '%s\tUPGRADE_OR_ELS_REQUIRED\tcheck vhost usage; migrate with compatibility testing or vendor ELS\n' "$owner" >> "$file"
    fi
  done < "$OUT/versions-$stage.tsv"
  # Inspect only existing repo definitions. Domain hints are not proof of compatibility.
  # Never add URLs from web searches or enable testing/rollout repos automatically.
  if command -v python3 >/dev/null; then
    python3 - "$OUT/official-repo-candidates-$stage.tsv" <<'REPOS'
import configparser, glob, sys
from urllib.parse import urlsplit
known = {'cpanel.net', 'cloudlinux.com', 'tuxcare.com', 'almalinux.org', 'rockylinux.org', 'redhat.com'}
with open(sys.argv[1], 'w') as out:
    for path in sorted(glob.glob('/etc/yum.repos.d/*.repo')):
        c = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            c.read(path)
            for section in c.sections():
                r = c[section]
                if r.get('enabled', '1').strip().lower() not in ('0', 'false', 'no'): continue
                urls = ' '.join(r.get(k, '') for k in ('baseurl', 'mirrorlist', 'metalink')).split()
                hosts = [urlsplit(u).hostname or '' for u in urls]
                official = bool(hosts) and all(any(h == d or h.endswith('.' + d) for d in known) for h in hosts)
                if official:
                    print(section, path, ','.join(hosts), 'MANUAL_COMPATIBILITY_AND_SIGNATURE_REVIEW_REQUIRED', sep='\t', file=out)
        except (configparser.Error, ValueError) as e:
            print('Repo parse failed:', path, str(e), file=sys.stderr)
REPOS
  else
    echo 'python3 unavailable: official-domain repo classification skipped.'
    : > "$OUT/official-repo-candidates-$stage.tsv"
  fi
  cat "$file"
}
show_diagnosis() {
  local stage=$1 owner state detail shown=''
  while IFS=$'\t' read -r owner state detail; do
    case "$state" in
      UPDATE_AVAILABLE) color "$GREEN" "  - $owner: update available";;
      BLOCKED_BY_EXCLUSION) color "$YELLOW" "  - $owner: update blocked by exclusion; manual review";;
      BACKPORT_EVIDENCE) color "$YELLOW" "  - $owner: vendor backport evidence; verify advisory/build";;
      UPGRADE_OR_ELS_REQUIRED) color "$YELLOW" "  - $owner: supported-version migration or ELS required";;
      REPOSITORY_QUERY_FAILED) color "$RED" "  - $owner: repository query failed; inspect log";;
    esac
  done < "$OUT/diagnosis-$stage.tsv"
  if [[ -s "$OUT/official-repo-candidates-$stage.tsv" ]]; then
    color "$YELLOW" '  Disabled official-domain repo candidates (manual compatibility/signature review):'
    local repo config host review count=0
    while IFS=$'\t' read -r repo config host review; do
      if ((count < 5)); then color "$YELLOW" "    - $repo | $host"; fi
      count=$((count + 1))
    done < "$OUT/official-repo-candidates-$stage.tsv"
    if ((count > 5)); then color "$YELLOW" '    More candidates are listed in the log.'; fi
  fi
}
echo "STEP 1: inventory"
inventory before &
wait "$!"
group_inventory before
: > "$OUT/owners.txt"
while IFS=$'\t' read -r path _; do
  rpm -qf --qf '%{NAME}\n' -- "$path" >> "$OUT/owners.txt" 2>>"$LOG" || true
done < "$OUT/versions-before.tsv"
{ printf '%s\n' "${PKGS[@]}"; cat "$OUT/owners.txt"; } | awk 'NF && $0 !~ / /' | sort -u > "$OUT/managed-packages.txt"
mapfile -t PKGS < "$OUT/managed-packages.txt"
if ((${#PKGS[@]})); then
  rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "${PKGS[@]}" | sort > "$OUT/rpm-before.txt"
fi
NEEDS=$(awk -F '\t' '$4 != "UPSTREAM_FIXED" {n++} END {print n+0}' "$OUT/groups-before.tsv")
SERVICES=()
if command -v systemctl >/dev/null; then
  systemctl list-units --type=service --state=running --no-legend --no-pager > "$OUT/running-services-before.txt" || true
fi
ps -eo pid,ppid,user,lstart,args > "$OUT/processes-before.txt"
command -v ss >/dev/null && { ss -tunap > "$OUT/connections-before.txt" 2>&1 || true; }

if [[ -f "$OUT/running-services-before.txt" ]]; then
  mapfile -t SERVICES < <(awk '$1 ~ /(php.*fpm|httpd|apache2|lsws|litespeed|frankenphp).*\.service$/ {print $1}' "$OUT/running-services-before.txt")
fi
if ((NEEDS)); then
  if ((REPO_FAILED == 0)); then
    pm_run query makecache --refresh || REPO_FAILED=1
  fi
  diagnose_updates before
fi
if ((NEEDS == 0)) && [[ -s "$OUT/versions-before.tsv" ]]; then
  color "$GREEN" 'Installed PHP: discovered binaries already meet upstream fixes.'
else
  color "$YELLOW" 'PHP requiring attention (one row per installation/version):'
  while IFS=$'\t' read -r root version minimum status; do
    [[ "$status" != UPSTREAM_FIXED ]] || continue
    if [[ "$status" == BELOW_UPSTREAM_FIX_VENDOR_CHECK_REQUIRED ]]; then
      color "$RED" "  - $root | PHP $version | upstream affected; fixed $minimum"
    else
      color "$YELLOW" "  - $root | PHP $version | EOL/unknown; vendor verification required"
    fi
  done < "$OUT/groups-before.tsv"
  [[ -s "$OUT/versions-before.tsv" ]] || color "$YELLOW" '  - No readable PHP runtime discovered; coverage unknown.'
  color "$YELLOW" 'Vendor backports may fix older versions; version numbers alone cannot verify them.'
  show_diagnosis before
  if ((REPO_FAILED)); then
    UPDATE=REPOSITORY_FAILED; FAILED=1
    color "$RED" '  Update blocked: repository access failed. Fix repository connectivity and rerun.'
  elif ((${#PKGS[@]})); then
    echo 'Packages proposed for update:'; printf '%s\n' "${PKGS[@]}"
    echo 'Services proposed for restart:'; printf '%s\n' "${SERVICES[@]}"
    color "$BLUE" 'Repositories, streams, exclusions and version locks will remain unchanged.'
    color "$BLUE" "Update via $PM; restart ${#SERVICES[@]} detected service(s) if packages change."
    color "$YELLOW" 'Use a tested backup/maintenance window; service interruption is possible.'
    printf 'Update and restart if needed? [y/N] ' >&3
    APPROVE=''
    read -r APPROVE || true
    echo "User approval: ${APPROVE:-declined}"
    if [[ "$APPROVE" == y || "$APPROVE" == Y ]]; then
      UPDATE=FAILED
      if pm_run transaction -y --setopt=gpgcheck=1 update "${PKGS[@]}"; then
        UPDATE=TRANSACTION_OK
      fi
    else UPDATE=DECLINED; fi
  else UPDATE=NO_MANAGED_PACKAGES; fi
fi
if ((${#PKGS[@]})); then
  rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "${PKGS[@]}" | sort > "$OUT/rpm-after.txt"
  rpm -q --changelog "${PKGS[@]}" > "$OUT/vendor-changelogs.txt" 2>&1 || true
  echo 'Vendor changelog references (evidence hints, NOT automatic backport approval):'
  grep -nE 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp' "$OUT/vendor-changelogs.txt" || true
fi

if [[ "$UPDATE" == TRANSACTION_OK ]]; then
  if cmp -s "$OUT/rpm-before.txt" "$OUT/rpm-after.txt"; then
    UPDATE=NO_PACKAGE_CHANGE
  else
    UPDATE=PACKAGES_UPDATED; CHANGED=1
  fi
  RESTART=NO_SERVICES_DISCOVERED
  if ((CHANGED)) && ((${#SERVICES[@]})); then
    RESTART=OK
    for svc in "${SERVICES[@]}"; do
      if systemctl restart "$svc" && systemctl is-active --quiet "$svc"; then
        echo "Restart successful: $svc"
      else
        color "$RED" "  ERROR: service restart failed: $svc"; RESTART=FAILED; FAILED=1
      fi
    done
  fi
  ((CHANGED)) || RESTART=SKIPPED_NO_CHANGE
fi
echo "STEP 3: verify"
inventory after &
wait "$!"
group_inventory after
if [[ "$UPDATE" == NO_PACKAGE_CHANGE || "$UPDATE" == FAILED || "$UPDATE" == PACKAGES_UPDATED ]]; then
  diagnose_updates after
fi
# Deleted mappings identify stale code, not every possible unpatched worker.
echo 'Scanning processes for deleted PHP executable/module mappings...'
: > "$OUT/stale-php-mappings.txt"
for maps in /proc/[0-9]*/maps; do
  [[ -r "$maps" ]] || continue
  { grep -E '/[^ ]*(php|lsphp)[^ ]*.*\(deleted\)' "$maps" | sed "s|^|$maps: |" >> "$OUT/stale-php-mappings.txt"; } 2>/dev/null || true
done
cat "$OUT/stale-php-mappings.txt"

if [[ -n "$WEBROOT" ]]; then
  echo 'This is heuristic triage, not CVE-specific exploit detection or forensic clearance.'
  if ((${#PKGS[@]})); then rpm -V "${PKGS[@]}" > "$OUT/rpm-integrity.txt" 2>&1 || true; fi
  if [[ -n "$WEBROOT" && "$WEBROOT" == /* && -d "$WEBROOT" && "$WEBROOT" != / ]]; then
    # Do not follow symlinks. Record metadata and suspicious filenames only.
    find "$WEBROOT" -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %u %s %p\n' > "$OUT/recent-web-files.txt" 2>"$OUT/web-scan-errors.txt" || true
    find "$WEBROOT" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '.user.ini' -o -name '.htaccess' \) -print0 |
      xargs -0 -r grep -IlE '(eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate)|shell_exec[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST)|auto_prepend_file)' > "$OUT/heuristic-review-files.txt" 2>"$OUT/heuristic-errors.txt" || true
  elif [[ -n "$WEBROOT" ]]; then echo 'Invalid web root; scan skipped.'; fi
  find /etc/cron.d /etc/cron.daily /var/spool/cron /etc/systemd/system -xdev -type f -mtime -7 -ls > "$OUT/recent-persistence-files.txt" 2>"$OUT/persistence-errors.txt" || true
  if command -v journalctl >/dev/null; then
    journalctl --since '7 days ago' --no-pager -p warning -n 5000 > "$OUT/recent-warnings.txt" 2>&1 || true
  fi
  echo 'Review triage files: recent legitimate changes can match, and an attacker can evade these checks.'
fi
echo 'Full before/after inventories:'
cat "$OUT/versions-before.tsv" "$OUT/versions-after.tsv"
color "$BLUE" 'Summary'
if ((ERROR_COUNT)); then
  color "$RED" "  Errors: $ERROR_COUNT failed package-manager operation(s); see log."
  FAILED=1
fi
if [[ -f "$OUT/diagnosis-after.tsv" ]]; then show_diagnosis after; fi
case "$UPDATE" in
  PACKAGES_UPDATED) color "$GREEN" '  Update: packages changed successfully.';;
  NOT_NEEDED) color "$GREEN" '  Update: not needed for discovered binaries.';;
  REPOSITORY_FAILED) color "$RED" '  Update: not attempted; repository access failed.'; FAILED=1;;
  FAILED) color "$RED" '  Update: FAILED; partial changes possible.'; FAILED=1;;
  NO_PACKAGE_CHANGE) color "$YELLOW" '  Update: no package changes; see repository/backport diagnosis in log.';;
  DECLINED) color "$YELLOW" '  Update: declined.';;
  *) color "$YELLOW" '  Update: no managed packages; manual remediation required.';;
esac
FIXED=$(awk -F '\t' '$4=="UPSTREAM_FIXED" {n++} END {print n+0}' "$OUT/groups-after.tsv")
UNRESOLVED=$(awk -F '\t' '$4!="UPSTREAM_FIXED" {n++} END {print n+0}' "$OUT/groups-after.tsv")
if [[ ! -s "$OUT/groups-after.tsv" ]]; then
  color "$YELLOW" '  PHP: no readable runtime; coverage unknown.'; FAILED=1
elif ((UNRESOLVED)); then
  color "$YELLOW" "  PHP installations: $FIXED fixed; $UNRESOLVED affected upstream/unverified."
  while IFS=$'\t' read -r root version minimum status; do
    [[ "$status" == UPSTREAM_FIXED ]] || color "$YELLOW" "    - $root | $version | unresolved"
  done < "$OUT/groups-after.tsv"
  FAILED=1
else color "$GREEN" "  PHP installations: $FIXED meet upstream fixes."; fi
case "$RESTART" in
  OK) color "$GREEN" '  Services: restarted and active.';;
  FAILED) color "$RED" '  Services: restart failure.'; FAILED=1;;
  SKIPPED_NO_CHANGE|NOT_ATTEMPTED) color "$BLUE" '  Services: no restarts performed.';;
  *) color "$YELLOW" '  Services: manual restart verification required.';;
esac
if [[ -s "$OUT/stale-php-mappings.txt" ]]; then
  color "$RED" '  Workers: stale PHP code detected; restart required.'; FAILED=1
fi
color "$YELLOW" '  Compromise: not determined; host/containers/web coverage requires review.'
# Consolidate all detailed side files into one chronological operation log.
for detail in "$OUT"/*; do
  [[ "$detail" == "$LOG" || ! -f "$detail" ]] && continue
  printf '\n===== %s =====\n' "${detail##*/}"
  cat -- "$detail"
done
echo "Finished $(date -u +%FT%TZ); exit=$FAILED"
color "$BLUE" "Full log: $LOG"
exit "$FAILED"
