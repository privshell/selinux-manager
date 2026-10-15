#!/system/bin/sh
# SELinux Manager backend. The WebUI calls it with single-quoted arguments.
MODDIR=/data/adb/modules/selinux_manager
CONF=/data/adb/selinux_manager
RULES=$MODDIR/sepolicy.rule
BAK=$CONF/backups
HIST=$CONF/history.log
OUT=/sdcard/Download/SELinuxManager
PATH=/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/system/bin:/system/xbin:$PATH
export PATH
mkdir -p "$CONF" "$BAK"

T=none; TB=
for p in /data/adb/ksud /data/adb/ksu/bin/ksud; do
  if [ -x "$p" ]; then T=ksud; TB=$p; break; fi
done
if [ "$T" = none ]; then
  if command -v magiskpolicy >/dev/null 2>&1; then T=magiskpolicy
  elif command -v supolicy >/dev/null 2>&1; then T=supolicy; fi
fi

note() {
  echo "$(date '+%F %T') $*" >> "$HIST"
  tail -n 300 "$HIST" > "$HIST.t" 2>/dev/null && mv -f "$HIST.t" "$HIST"
}

patch_rule() {
  case "$T" in
    ksud)         "$TB" sepolicy patch "$1" ;;
    magiskpolicy) magiskpolicy --live "$1" ;;
    supolicy)     supolicy --live "$1" ;;
    *) echo "no policy tool found" >&2; return 1 ;;
  esac
}

rule_lines() {
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$line" in ''|'#'*) continue ;; esac
    printf '%s\n' "$line"
  done < "$1"
}

# Keeps the ten newest copies of the rules file.
backup_rules() {
  [ -f "$RULES" ] || return 0
  cp -f "$RULES" "$BAK/$(date +%Y%m%d-%H%M%S)-$$.rule"
  ls -1t "$BAK"/*.rule 2>/dev/null | tail -n +11 | while read -r f; do rm -f "$f"; done
}

apply_file() {
  ok=0; fail=0; tmp=$CONF/.apply.$$
  rule_lines "$1" > "$tmp"
  while IFS= read -r line; do
    if out=$(patch_rule "$line" 2>&1); then ok=$((ok+1))
    else fail=$((fail+1)); echo "FAIL: $line"; [ -n "$out" ] && echo "  -> $out"; fi
  done < "$tmp"
  rm -f "$tmp"
  [ "$ok" -gt 0 ] && touch "$CONF/live_changed"
  echo "ok=$ok fail=$fail"
}

# Paths where a wrong label can stop the phone from booting.
path_protected() {
  p=$(printf '%s' "$1" | sed 's#/*$##'); [ -z "$p" ] && p=/
  case "$p" in
    /|/system|/system/*|/vendor|/vendor/*|/product|/product/*|/system_ext|/system_ext/*|\
    /odm|/odm/*|/apex|/apex/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/data|/data/data|\
    /data/user|/data/user/0|/data/app|/data/system|/data/system/*|/data/adb|/metadata|/metadata/*)
      return 0 ;;
  esac
  return 1
}

safe_name() { case "$1" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac; return 0; }

case "$1" in
  status)
    echo "mode=$(getenforce 2>/dev/null)"
    echo "node=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
    echo "policyvers=$(cat /sys/fs/selinux/policyvers 2>/dev/null)"
    echo "context=$(tr -d '\0' < /proc/self/attr/current 2>/dev/null)"
    echo "tool=$T"
    echo "android=$(getprop ro.build.version.release)"
    echo "sdk=$(getprop ro.build.version.sdk)"
    echo "kernel=$(uname -r)"
    echo "device=$(getprop ro.product.model)"
    echo "bootmode=$(cat "$CONF/boot_mode" 2>/dev/null || echo none)"
    echo "rules=$(rule_lines "$RULES" | wc -l | tr -d ' ')"
    echo "live_changed=$([ -f "$CONF/live_changed" ] && echo 1 || echo 0)"
    echo "safemode=$(cat "$CONF/safemode" 2>/dev/null)"
    echo "recording=$(cat "$CONF/rec_start" 2>/dev/null)"
    echo "revert_at=$(cat "$CONF/revert_at" 2>/dev/null)"
    echo "guard_test=$([ -f "$CONF/guard_test" ] && echo 1 || echo 0)"
    echo "trial=$([ -f "$CONF/trial.rule" ] && rule_lines "$CONF/trial.rule" | wc -l | tr -d ' ')"
    echo "boot_denials=$([ -f "$CONF/boot-denials.log" ] && wc -l < "$CONF/boot-denials.log" | tr -d ' ' || echo 0)"
    ;;
  kernel)
    for f in enforce policyvers deny_unknown reject_unknown mls checkreqprot; do
      [ -r "/sys/fs/selinux/$f" ] && echo "$f=$(cat "/sys/fs/selinux/$f" 2>/dev/null)"
    done
    for f in /sys/fs/selinux/policy_capabilities/*; do
      [ -r "$f" ] && echo "cap.${f##*/}=$(cat "$f" 2>/dev/null)"
    done
    [ -r /sys/fs/selinux/avc/cache_stats ] && sed 's/^/avc /' /sys/fs/selinux/avc/cache_stats
    echo "prop.ro.boot.selinux=$(getprop ro.boot.selinux)"
    echo "prop.ro.build.selinux=$(getprop ro.build.selinux)"
    echo "prop.ro.build.type=$(getprop ro.build.type)"
    echo "prop.ro.debuggable=$(getprop ro.debuggable)"
    ;;
  setmode)
    case "$2" in 0|1) ;; *) echo "refused: mode must be 0 or 1"; exit 1 ;; esac
    setenforce "$2" 2>&1
    now=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    echo "mode=$(getenforce 2>/dev/null)"
    if [ "$now" = "$2" ]; then note "mode -> $2"; echo "verified"; else echo "not applied"; fi
    ;;
  bootmode)
    case "$2" in
      enforcing|permissive) echo "$2" > "$CONF/boot_mode" ;;
      *) rm -f "$CONF/boot_mode" ;;
    esac
    note "boot mode -> ${2:-none}"
    echo "bootmode=$(cat "$CONF/boot_mode" 2>/dev/null || echo none)"
    ;;
  rules-read)
    cat "$RULES" 2>/dev/null
    ;;
  rules-write)
    raw=$CONF/.rules.raw; tmp=$RULES.tmp
    printf '%s\n' "$2" | base64 -d > "$raw" 2>/dev/null || { rm -f "$raw"; echo "decode failed, nothing saved"; exit 1; }
    tr -d '\r' < "$raw" > "$tmp"; rm -f "$raw"
    backup_rules
    mv -f "$tmp" "$RULES" && chmod 644 "$RULES" || { echo "write failed"; exit 1; }
    note "rules saved ($(rule_lines "$RULES" | wc -l | tr -d ' ') rules)"
    echo "saved"
    ;;
  rules-check)
    [ "$T" = ksud ] || { echo "check needs ksud (found: $T)"; exit 2; }
    tmp=$CONF/.check.$$; printf '%s\n' "$2" | base64 -d > "$tmp" 2>/dev/null || { rm -f "$tmp"; echo "decode failed"; exit 1; }
    good=0; bad=0
    while IFS= read -r line; do
      if out=$("$TB" sepolicy check "$line" 2>&1); then good=$((good+1))
      else bad=$((bad+1)); echo "BAD: $line"; [ -n "$out" ] && echo "  -> $out"; fi
    done <<EOR
$(rule_lines "$tmp")
EOR
    rm -f "$tmp"
    echo "good=$good bad=$bad"
    ;;
  backups)
    ls -1t "$BAK"/*.rule 2>/dev/null | while read -r f; do echo "${f##*/}|$(rule_lines "$f" | wc -l | tr -d ' ')"; done
    ;;
  backup-read)
    safe_name "$2" || { echo "bad name"; exit 1; }
    cat "$BAK/$2" 2>/dev/null
    ;;
  backup-restore)
    safe_name "$2" && [ -f "$BAK/$2" ] || { echo "no such backup"; exit 1; }
    backup_rules
    cp -f "$BAK/$2" "$RULES" && chmod 644 "$RULES" && note "rules restored from $2" && echo "restored"
    ;;
  rules-apply)
    note "apply all saved rules live"
    apply_file "$RULES"
    ;;
  rules-apply-file)
    [ -f "$2" ] || { echo "no such file"; exit 1; }
    note "apply file live: $2"
    apply_file "$2"
    ;;
  rule-apply)
    if patch_rule "$2" 2>&1; then touch "$CONF/live_changed"; note "live: $2"; echo "ok"; fi
    ;;
  export)
    mkdir -p "$OUT" && cp -f "$RULES" "$OUT/sepolicy.rule" && echo "exported=$OUT/sepolicy.rule"
    ;;
  history)
    tail -n "${2:-200}" "$HIST" 2>/dev/null
    ;;
  denials)
    n=${2:-800}; case "$n" in *[!0-9]*|'') n=800 ;; esac
    { logcat -d -b all 2>/dev/null; dmesg 2>/dev/null; } | grep 'avc: ' | tail -n "$n"
    ;;
  boot-denials)
    cat "$CONF/boot-denials.log" 2>/dev/null
    ;;
  rec-start)
    date +%s > "$CONF/rec_start"; echo "recording=$(cat "$CONF/rec_start")"
    ;;
  rec-stop)
    rm -f "$CONF/rec_start"; echo "recording="
    ;;
  owners)
    # pid|uid|package|cmdline for each live pid given as arguments.
    shift
    for pid in "$@"; do
      case "$pid" in *[!0-9]*|'') continue ;; esac
      [ -d "/proc/$pid" ] || continue
      uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)
      cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/ *$//')
      pkg=$(awk -v u="$uid" '$2==u{print $1; exit}' /data/system/packages.list 2>/dev/null)
      echo "$pid|$uid|$pkg|$cmd"
    done
    ;;
  packages)
    cat /data/system/packages.list 2>/dev/null
    ;;
  modules-scan)
    for d in /data/adb/modules/*/; do
      id=${d%/}; id=${id##*/}
      [ -f "$d/sepolicy.rule" ] || continue
      st=enabled; [ -f "$d/disable" ] || [ -f "$d/remove" ] && st=disabled
      echo "### $id $st"
      cat "$d/sepolicy.rule" 2>/dev/null; echo
    done
    ;;
  ps)
    ps -AZ 2>&1
    ;;
  props)
    getprop -Z 2>/dev/null | grep -i -- "${2:-.}" | head -n 300
    ;;
  ls)
    ls -laZd -- "$2" 2>&1; echo; ls -laZ -- "$2" 2>&1 | head -n 300
    ;;
  chcon)
    if path_protected "$3"; then echo "refused: $3 is a system path"; exit 1; fi
    if [ "$4" = "1" ]; then chcon -R -- "$2" "$3" 2>&1; else chcon -- "$2" "$3" 2>&1; fi
    got=$(ls -Zd -- "$3" 2>/dev/null | awk '{print $1}')
    echo "read back: $got"
    if [ "$got" = "$2" ]; then note "chcon $2 $3"; echo "verified"; else echo "not applied"; fi
    ;;
  restorecon)
    p=$(printf '%s' "$2" | sed 's#/*$##')
    case "$p" in ''|/|/data) echo "refused: too broad, pick a narrower path"; exit 1 ;; esac
    restorecon -Rv -- "$2" 2>&1 | tail -n 100
    note "restorecon $2"
    echo "read back: $(ls -Zd -- "$2" 2>/dev/null | awk '{print $1}')"
    ;;
  report)
    echo "== SELinux Manager report $(date '+%F %T')"
    sh "$0" status; echo; echo "== kernel"; sh "$0" kernel
    echo; echo "== rules"; rule_lines "$RULES"
    echo; echo "== modules with sepolicy.rule"; sh "$0" modules-scan | grep '^###'
    echo; echo "== history (last 30)"; tail -n 30 "$HIST" 2>/dev/null
    echo; echo "== recent denials (last 60)"; sh "$0" denials 60
    ;;
  permissive-for)
    n=$2; case "$n" in ''|*[!0-9]*) n=60 ;; esac
    [ "$n" -lt 10 ] && n=10; [ "$n" -gt 600 ] && n=600
    setenforce 0 2>&1
    [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = 0 ] || { echo "not applied"; exit 1; }
    echo $(( $(date +%s) + n )) > "$CONF/revert_at"
    # Detached, so closing the WebUI cannot stop the switch back.
    job="sleep $n; setenforce 1; rm -f '$CONF/revert_at'"
    if command -v setsid >/dev/null 2>&1; then setsid sh -c "$job" </dev/null >/dev/null 2>&1 &
    else nohup sh -c "$job" </dev/null >/dev/null 2>&1 & fi
    note "permissive for ${n}s"
    echo "verified"; echo "revert_in=$n"
    ;;
  guard-arm)
    echo 2 > "$CONF/boot_count"; touch "$CONF/guard_test"
    note "boot guard test armed"; echo "armed"
    ;;
  guard-disarm)
    echo 0 > "$CONF/boot_count"; rm -f "$CONF/guard_test"; echo "disarmed"
    ;;
  test-file)
    f=/data/local/tmp/selinux_manager_test
    echo "test" > "$f" && echo "path=$f" && ls -Z "$f"
    ;;
  trial-write)
    tmp=$CONF/trial.rule
    printf '%s\n' "$2" | base64 -d > "$tmp.raw" 2>/dev/null || { rm -f "$tmp.raw"; echo "decode failed"; exit 1; }
    tr -d '\r' < "$tmp.raw" > "$tmp"; rm -f "$tmp.raw"
    note "trial rules set for next boot ($(rule_lines "$tmp" | wc -l | tr -d ' ') rules)"
    echo "trial=$(rule_lines "$tmp" | wc -l | tr -d ' ')"
    ;;
  trial-clear)
    rm -f "$CONF/trial.rule"; echo "cleared"
    ;;
  trial-log)
    cat "$CONF/trial.log" 2>/dev/null
    ;;
  safemode-clear)
    rm -f "$CONF/safemode" "$CONF/boot_count"; echo "cleared"
    ;;
  *)
    echo "usage: sectl.sh status|kernel|setmode|bootmode|rules-read|rules-write|rules-check|backups|backup-read|backup-restore|rules-apply|rule-apply|export|history|denials|boot-denials|rec-start|rec-stop|owners|packages|modules-scan|ps|props|ls|chcon|restorecon|report|permissive-for|guard-arm|guard-disarm|test-file|trial-write|trial-clear|trial-log|safemode-clear"
    ;;
esac
