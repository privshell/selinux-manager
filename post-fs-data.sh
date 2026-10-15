#!/system/bin/sh
# Boot guard. service.sh resets the counter once the phone has fully booted.
# Two boots in a row that never reach boot_completed disable this module and drop the
# boot mode, so a bad rule in sepolicy.rule cannot keep the phone in a boot loop.
MODDIR=${0%/*}
CONF=/data/adb/selinux_manager
mkdir -p "$CONF"
n=$(cat "$CONF/boot_count" 2>/dev/null); case "$n" in ''|*[!0-9]*) n=0 ;; esac
n=$((n+1))
echo "$n" > "$CONF/boot_count"
if [ "$n" -ge 3 ]; then
  touch "$MODDIR/disable"
  rm -f "$CONF/boot_mode"
  if [ -f "$CONF/guard_test" ]; then
    echo "test: the boot guard worked, module disabled $(date '+%F %T')" > "$CONF/safemode"
  else
    echo "$((n-1)) unfinished boots, module disabled $(date '+%F %T')" > "$CONF/safemode"
  fi
  echo 0 > "$CONF/boot_count"
fi
