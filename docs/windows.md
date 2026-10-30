# Windows x86_64

PathTrial can be built for `x86_64-pc-windows-msvc`. The release workflow packages it like the macOS and Linux archives, with a SHA-256 file beside the `.tar.gz`. `scripts/install.ps1` checks that hash and copies `pathtrial.exe` into `%LOCALAPPDATA%\PathTrial`. It does not edit `PATH`, firewall rules, DNS, or routes.

The published `v1.5.0-rc.1` release does not contain a Windows archive. `scripts/verify-release.ps1` records `windows_published_asset=absent` in that case. That line is not a successful download. A later tag that includes the asset is what the installer can fetch. Until then, use a source build or the Windows CI artifact from a pull request. A CI artifact is not a GitHub Release.

## What is measured

TCP, TLS, HTTP, DNS (when English `ipconfig /all` or `Get-NetIPAddress` exposes resolvers), UDP Echo, QUIC, HTTP/3, proxies, and collect/correlate use the normal sockets. ICMP uses `ping.exe`. Route defaults come from `route print` when the English text parses. Interface addresses prefer `Get-NetIPAddress`.

## What is not established

- `--bind-interface` returns an error. PathTrial does not fall back to another interface.
- Per-target route lookup is not performed. A missing target route is not evidence that no route exists.
- `ping.exe` summaries do not include jitter. Jitter stays empty.
- `netsh wlan` signal is a percentage. It is not converted to dBm.
- `ipconfig` text that is not English may yield no addresses. That is a tool limit, not a network failure.
- Child-process cleanup kills the direct child. It does not claim a Unix process-group result.
- `SKIP` is not a pass.

These limits are also returned by `pathtrial_capabilities` on a Windows binary.
