# SELinux Manager

**A SELinux toolkit for KernelSU, in a WebUI. See what SELinux blocks, find the app behind it, write the narrowest rule that fixes it, and keep it across boots.**

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![KernelSU](https://img.shields.io/badge/KernelSU-module-green)
![Version](https://img.shields.io/badge/version-1.0.0-8ab4f8)

Made for module developers and people who debug ROMs. Every change is read back before it is reported, and every change is written to a history log.

## Features

**Status**
- Current mode read from the kernel node, switch with read-back, mode after every boot.
- Device, Android, kernel, policy version, policy tool in use, number of saved rules.
- Notes when live rules are active, when a recording is running, or when the boot guard tripped.

**Rules**
- Editor for `sepolicy.rule`, loaded by KernelSU at every boot.
- *Check* validates every line with `ksud sepolicy check` without touching the live policy.
- *Save* shows what was added and removed. Rules that widen an app domain, use a wildcard or make a domain permissive ask once before saving.
- Ten automatic backups, each with a diff against the editor and one-tap restore.
- Builder for `allow`, `deny`, `auditallow`, `dontaudit`, `permissive`, `enforce`.
- Templates for common cases, and export to `Download/SELinuxManager/sepolicy.rule` for use in your own module.

**Denials**
- *Recent*: from logcat and dmesg, one kernel event counted once even when it appears in both.
- *From boot*: saved by the module right after boot, before the buffers roll over.
- *Recording*: start, do the thing that fails, load. Only what happened in between is shown.
- Grouped by source, target and class, with process name, object path and `permissive=1` flag.
- *Find apps* maps the processes behind a denial to their package names while they are running.
- Per group: add as `allow`, add as `dontaudit` (hides the log line, allows nothing), or apply live.

**Modules**
- Lists the rules every installed module adds at boot, flags permissive lines and rules added by more than one module.

**Inspect**
- Domains from running processes with counts and process names.
- Apps with uid and seinfo, and the domain they run in right now.
- File labels, `restorecon`, and `chcon` with read-back.
- Property labels from `getprop -Z`.

**More**
- Kernel SELinux values (`deny_unknown`, policy capabilities, AVC cache) and which ones apps can see.
- History of every change made by this module.
- Report: status, kernel, rules, modules, history and recent denials as one text to paste into an issue.

## Safe tests

The *More* tab has ways to try the risky parts without leaving anything behind:

- **Permissive for 60 seconds**: switches back to enforcing by itself, even if the WebUI is closed.
- **Trial next boot** (Rules editor): the editor's rules are applied once after the next boot and then forgotten. Saved rules are untouched, so the boot after that is clean.
- **Boot guard test**: makes the next normal boot count as the third unfinished one. The phone boots as usual, the module disables itself and reports that the guard worked.
- **Test file for labels**: a file in `/data/local/tmp` to try `chcon` and `restorecon` on.

## Limits, stated plainly

- A rule applied live stays in the policy until reboot. Nothing can remove it earlier.
- *Check* needs `ksud`. With Magisk or APatch tooling the button says it is not available.
- *Find apps* only matches processes that are still running.
- Only tested on one phone so far (Redmi Note 14 4G, HyperOS 3, Android 16, KernelSU).

## Safety

- Every argument from the WebUI is single-quoted; backup names are validated.
- Saves are atomic, and the previous file is always backed up first.
- `chcon` refuses system paths such as `/system`, `/vendor`, `/apex`, `/data/system` and `/data/adb`. `restorecon` refuses `/` and `/data` as a whole.
- **Boot guard**: if two boots in a row never finish, the module disables itself and drops the boot mode, so a bad rule cannot keep the phone in a boot loop.

## Install

1. Download the zip from Releases and install it in KernelSU Manager > Modules.
2. Reboot.
3. Open KernelSU Manager > Modules > SELinux Manager.

Emergency disable, from a root shell or recovery:

```sh
su -c "touch /data/adb/modules/selinux_manager/disable"
```

## Build

```sh
node tests/core.test.js
zip -r selinux-manager-1.0.0.zip module.prop customize.sh post-fs-data.sh service.sh uninstall.sh sepolicy.rule bin webroot
```

## Files

| Path | Role |
|---|---|
| `bin/sectl.sh` | every command the WebUI runs |
| `post-fs-data.sh` | boot guard counter |
| `service.sh` | saves boot denials, applies the boot mode and trial rules, resets the guard |
| `webroot/core.js` | parsers and rule logic, unit-tested in `tests/` |
| `webroot/app.js`, `index.html`, `style.css` | the WebUI |

Settings, backups, history and saved denials live in `/data/adb/selinux_manager` and are removed on uninstall.

## Support

SELinux Manager is free and open source, built in spare time. If it saved you time, you can [support the work with a small crypto donation](https://github.com/privshell/privshell/blob/main/DONATE.md) (USDT on TRC20, or USDC / SOL on Solana). Starring the repo or opening a clear issue helps just as much.

## License

MIT, see [LICENSE](LICENSE).
