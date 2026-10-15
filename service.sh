#!/system/bin/sh
CONF=/data/adb/selinux_manager
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
sleep 3
echo 0 > "$CONF/boot_count"
rm -f "$CONF/live_changed" "$CONF/revert_at"
[ -f "$CONF/guard_test" ] && rm -f "$CONF/guard_test"
# Denials from boot are gone from the ring buffers by the time anyone opens the WebUI,
# so they are saved once here.
{ dmesg 2>/dev/null; logcat -d -b all 2>/dev/null; } | grep 'avc: ' | tail -n 2000 > "$CONF/boot-denials.log"
case "$(cat "$CONF/boot_mode" 2>/dev/null)" in
  enforcing)  setenforce 1 ;;
  permissive) setenforce 0 ;;
esac

# Trial rules: applied live once on this boot and then forgotten, so the next reboot is clean.
if [ -f "$CONF/trial.rule" ]; then
  sh /data/adb/modules/selinux_manager/bin/sectl.sh rules-apply-file "$CONF/trial.rule" > "$CONF/trial.log" 2>&1
  rm -f "$CONF/trial.rule"
fi
