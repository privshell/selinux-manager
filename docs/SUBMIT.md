# Publishing SELinux Manager on KernelSU Modules

One-time setup, then every release is automatic.

## 1. Enable immutable releases
**Settings → General → Releases → Enable release immutability**, before the first release.

## 2. Enable the release workflow
Copy `docs/release.yml` to `.github/workflows/release.yml`.

## 3. Cut the release
Bump `version` and `versionCode` in `module.prop` if needed, then **Actions → Release → Run workflow**. It tags the commit, stages the module files, validates the ZIP and publishes `selinux_manager-<versionCode>-<version>.zip` as an immutable release.

## 4. Register the module
1. Sign in at [developers.kernelsu.org](https://developers.kernelsu.org) with GitHub.
2. Install the KernelSU Modules GitHub App on this repository.
3. **My repositories → Precheck**, fix anything marked as an error.
4. **Submit**, confirm the module ID `selinux_manager`, send it for review.

## 5. After approval
Add to `module.prop`:

```
updateJson=https://modules.kernelsu.org/api/v1/modules/selinux_manager/update.json
```
