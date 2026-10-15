## SELinux Manager v1.0.0

First public release.

- Status: mode switch with kernel read-back, boot mode, device and policy info, boot guard
- Rules: editor with syntax check, save with diff, ten automatic backups with restore, rule builder, templates, export
- Denials: recent, from boot, or recorded between two moments; grouped, with app names; allow or dontaudit per group
- Modules: every installed module's sepolicy.rule, with permissive lines and shared rules flagged
- Inspect: domains, app seinfo, file labels with restorecon and chcon read-back, property labels
- Safe tests: permissive for 60 seconds with automatic revert, trial rules applied once on the next boot, boot guard test
- Boot guard: two unfinished boots disable the module and drop the boot mode
