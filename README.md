# gil-sec-net

OS-level companion to `gil-sec`. Where `gil-sec`'s Node monitor only sees
processes that `require()` it, this acts system-wide — every process, any
language:

- Intercepts outbound TCP traffic and resets any connection whose TLS SNI
  (port 443) or HTTP `Host` header (port 80) matches a blocklisted domain.
- Watches file deletions and flags/optionally kills a **Node-family**
  process (`node`/`node.exe`/`electron`) that deletes an unusual number of
  files in a short window — a bulk-wipe/ransomware-style pattern.

Builds for Windows, Linux, and macOS from the same source — but the three
platforms are **not equally verified**. Read the confidence table below
before trusting any of this beyond Windows.

## Confidence per platform

| | Windows | Linux | macOS |
|---|---|---|---|
| Network filter | ✅ Live-tested-adjacent — built against WinDivert's own official `webfilter.c` sample, struct layouts verified byte-for-byte | ✅ High confidence — built against `go-nfqueue`'s own example, checksum math self-verified by test, but never run on a real box | ⚠️ **Experimental** — no verified reference implementation existed to build the divert-socket code against (see `network_darwin.go`); may simply not work as written |
| File-delete watch | ✅ ETW API verified against real `golang-etw` source | ✅ Standard `auditd`/`auditctl` mechanism, parser unit-tested, but log format assumed from documented examples, not a live audit.log | ⚠️ **Best-effort only** — `fs_usage` output format wasn't verifiable; real PID-attributed detection needs Apple's EndpointSecurity entitlement (a separate approval process, unrelated to code) |
| PID/process lookup | Verified via `iphlpapi` | Standard `/proc` parsing | Shells out to `ps`/`lsof` |

None of this has run on real Linux or macOS hardware — only cross-compiled
(`GOOS=linux`/`GOOS=darwin go build`) to catch build errors. If you run
either, please report back what breaks.

## How the network filter works (Windows: WinDivert, Linux: NFQUEUE, macOS: pf divert-to)

1. Intercepts outbound, non-loopback TCP packets on port 80/443 that carry
   payload (the first data segment of each request — where the SNI/Host
   lives) — via WinDivert on Windows, an NFQUEUE (`iptables -j NFQUEUE`) on
   Linux, or a `pf divert-to` socket on macOS.
2. Parses the TLS ClientHello or HTTP request line by hand — these are all
   plain wire-format IPv4/TCP, no platform-specific parsing needed
   (`packet.go`/`inspect.go`, shared across all three builds).
3. On a match: drops the packet (never reinjected) and crafts+sends two RST
   packets — one toward the remote server, one spoofed as if from the
   server toward the local client (delivered locally since the destination
   is this machine's own IP) — so the connection dies immediately instead
   of hanging until a retransmit timeout. `reset.go` (shared) builds the
   packets; Windows uses `WinDivertHelperCalcChecksums`, Linux/macOS compute
   the IP/TCP checksums by hand (`finalizeChecksums`, self-verified by a
   unit test).
4. Everything else is passed through unchanged.
5. Blocked connections are logged as JSON lines to `gil-sec-net.log`,
   including the owning PID/process path.

Default blocklist (`blocklist.json`) mirrors gil-sec's
`network-monitor.js` blocklist — known Ethereum RPC endpoints commonly
abused for wallet-draining exfiltration. Edit that file and restart to
change it.

**Safety nets built into the rule setup, so a crash doesn't lock the box
off the network:**

- Linux: the iptables rule uses `--queue-bypass`, so if this process isn't
  running, matching packets are accepted normally instead of stalling.
- macOS: the pf rules live in their own anchor (`gil-sec-net`) and
  shutdown only flushes that anchor — pf itself is never globally disabled,
  even if it was off before this program enabled it.
- Windows: WinDivert's own driver model has no equivalent failure mode —
  packets simply aren't intercepted if the handle isn't open.

## How the file-delete watch works (Windows: ETW, Linux: auditd, macOS: fs_usage)

1. **Windows** opens a real-time ETW session on `Microsoft-Windows-Kernel-File`
   (`NameDelete`/`DeletePath` events) — the same facility Process Monitor is
   built on. Every event carries the emitting PID in its header.
2. **Linux** installs an `auditctl` rule watching
   `unlink`/`unlinkat`/`rmdir`/`rename`/`renameat`/`renameat2` syscalls
   system-wide, then tails `/var/log/audit/audit.log` for matching
   `SYSCALL` records (which carry `pid=`/`exe=`). **Requires `auditd` to
   already be installed and running** — the network filter works without
   it, but this half of the tool does nothing if there's no audit log to
   tail.
3. **macOS** shells out to `fs_usage -w -f filesys` and does a defensive,
   best-effort parse for delete-related syscalls — see the confidence
   table above. This is not a substitute for the Windows/Linux mechanisms;
   it's what's achievable without Apple's EndpointSecurity entitlement.
4. All three funnel into the same shared policy (`delete_policy.go`):
   only `node`/`node.exe`/`node64.exe`/`electron`/`electron.exe` are acted
   on — everything else is ignored by design, this isn't general
   file-integrity monitoring.
5. A per-PID sliding-window counter (`ratewatch.go`) flags a process once
   it crosses **15 deletes within 3 seconds** (tunable in
   `delete_policy.go`). Logged as `bulk-delete-alert` always.
6. **Termination is opt-in.** By default, a crossing is only logged/printed.
   Pass `-kill` to actually terminate the offending PID
   (`TerminateProcess` on Windows, `SIGKILL` on Linux/macOS).

   ⚠️ **This heuristic is unvalidated against real workloads.** Legitimate
   Node tooling — `rimraf`, `jest --clearCache`, webpack/Vite clean steps,
   `npm install` pruning `node_modules` — can absolutely delete dozens of
   files in under 3 seconds. Run without `-kill` first, watch
   `gil-sec-net.log` for `bulk-delete-alert` entries during your normal
   workflow, and raise the threshold/window until it stays quiet during
   legitimate use before ever enabling `-kill`. Killing a dev server or
   build mid-`npm install` on a false positive is a worse outcome than the
   thing you're defending against.
7. **Pause switch for intentional bulk deletes.** Create a file named
   `gil-sec-net.pause` next to the exe before running a legitimate cleanup,
   delete it when done:

   ```powershell
   New-Item gil-sec-net.pause          # pause (PowerShell)
   Remove-Item gil-sec-net.pause       # resume
   ```

   ```sh
   touch gil-sec-net.pause             # pause (Linux/macOS)
   rm gil-sec-net.pause                # resume
   ```

   While it exists, deletes are still logged but not fed into the rate
   tracker — no alert/kill can fire. Checked every 250ms.

## Build

```sh
# Windows (from any OS with Go installed)
GOOS=windows GOARCH=amd64 go build -o gil-sec-net.exe .

# Linux
GOOS=linux GOARCH=amd64 go build -o gil-sec-net .

# macOS (Apple Silicon / Intel)
GOOS=darwin GOARCH=arm64 go build -o gil-sec-net .
GOOS=darwin GOARCH=amd64 go build -o gil-sec-net .
```

Building *for* Windows only needs `WinDivert.dll`/`WinDivert64.sys`
(already in this directory — official v2.2.2 binaries from
basil00/WinDivert, LGPL/GPL) next to the exe at **run** time, not build
time. Linux/macOS builds don't need any extra files, just external tools
present on the target machine at runtime (see below).

## Run

All three platforms need elevated privileges — Administrator on Windows,
root on Linux/macOS (kernel-level packet interception and raw sockets
aren't available otherwise).

**Windows** (WinDivert loads a kernel driver on first use):

```
cd c:\xampp\htdocs\mine\gil-sec-net
.\gil-sec-net.exe          # observe/log only (recommended first)
.\gil-sec-net.exe -kill    # also terminates on a confirmed bulk-delete pattern
```

**Linux** (needs `iptables` and `auditctl` on PATH, and `auditd` running for
the file-delete half):

```sh
sudo ./gil-sec-net
sudo ./gil-sec-net -kill
```

**macOS** (needs `pfctl`, `fs_usage` — both built in; EXPERIMENTAL, see
confidence table):

```sh
sudo ./gil-sec-net
sudo ./gil-sec-net -kill
```

To test the network filter, re-run mytest's connectivity check while this
is running — it should now fail/timeout against `cloudflare-eth.com`
regardless of which process made the request. To test the file watch,
delete a bunch of files quickly from a `node -e "..."` script and watch
for `[ALERT]` in the console / `bulk-delete-alert` entries in
`gil-sec-net.log`.

Stop with Ctrl+C — the network intercept and file-delete watch, and any
iptables/auditctl/pf rules this program installed, are torn down on exit
(Linux/macOS teardown happens in a background goroutine, so the process
waits ~1s on shutdown to let it finish first). None of the three platforms
install this as a startup service — that's a separate, deliberate step
(see gil-sec's own `startup:install` for the pattern) not taken on here,
since a system-wide packet/process interceptor auto-starting is a bigger
decision than a one-off run.

## Known limitations

**Network filter (all platforms):**

- IPv4 only.
- Assumes the TLS ClientHello / HTTP request line fits in the first TCP
  segment — true for virtually all real clients, but a deliberately
  fragmented ClientHello would slip through unseen (same limitation the
  official WinDivert `webfilter.c` sample documents).
- No IP-level fallback: a client that hardcodes an IP and skips SNI
  entirely (very unusual for HTTPS) isn't inspected — domain-based, not
  IP-based, blocklist model.
- macOS: experimental, may not work at all — see confidence table.

**File-delete watch:**

- Only attributes/acts on Node-family processes — by design, not general
  file-integrity monitoring of every process.
- The rate threshold/window are unvalidated heuristics — see the warning
  above before ever enabling `-kill`.
- `-kill` only stops *further* deletion by that process for that run — it
  does not recover files already deleted. This is a circuit-breaker, not a
  backup; pair it with actual backups/snapshots for real recovery.
- Linux: does nothing if `auditd` isn't installed/running.
- macOS: best-effort only; genuine PID-attributed detection needs Apple's
  EndpointSecurity entitlement (a real approval process from Apple, not a
  coding task) plus cgo/Objective-C framework work that can't be
  cross-compiled from a non-Mac machine in the first place.

The `reference/` folder has the primary sources everything here was built
against: the WinDivert header + official `webfilter.c` sample, the
`golang-etw` source consulted for the ETW API, `go-nfqueue`'s source +
example, and `go-libaudit`'s README (all kept `.go.txt`/`.md.txt` so
they're never compiled as part of this module).
