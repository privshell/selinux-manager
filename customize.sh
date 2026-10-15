SKIPUNZIP=0
ui_print "- SELinux Manager 1.0.0"
mkdir -p /data/adb/selinux_manager

# keep the user's rules on upgrade
OLD=/data/adb/modules/selinux_manager/sepolicy.rule
if [ -f "$OLD" ]; then
  cp -f "$OLD" "$MODPATH/sepolicy.rule"
  ui_print "- Existing custom rules kept"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/sectl.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
ui_print "- Done. Reboot, then open the module WebUI."
