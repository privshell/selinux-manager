# Changelog

## 1.0.0 (versionCode 100)

First public release, rebuilt from the earlier private versions.

- Status: mode with kernel read-back, boot mode, device and policy info, boot guard and live-rule notes.
- Rules: editor with syntax check (ksud), save with diff, ten automatic backups with diff and restore, builder for six actions, templates, export to Download.
- Denials: recent, saved at boot, or recorded between two moments; grouped by source, target and class; one event counted once across logcat and dmesg; app name from the process; allow or dontaudit per group.
- Modules: every installed module's sepolicy.rule, with permissive lines and rules shared between modules.
- Inspect: domains from running processes, app seinfo, file labels with restorecon and chcon read-back, property labels.
- More: kernel SELinux values and what apps can see, change history, one-tap report.
- Boot guard: two unfinished boots disable the module and drop the boot mode.
- Safe tests: permissive for 60 seconds with automatic revert, trial rules applied once on the next boot, boot guard test, harmless test file for labels.
- Denials: pid and time read from the logcat header when the audit line has none, so Find apps and Recording work for logcat events.
