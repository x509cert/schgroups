# schgroups

A Schannel TLS 1.3 server that can listen on one or more ports. On startup it:
1. reads the **OS default** key-establishment group list, once
2. validates each port's policy and acquires its credential
3. shows the configured groups for each port
4. listens only if every port was configured successfully

The OS configuration is never changed.

## Reusable module: `schannel_groups.h` / `.cpp`

All the group logic lives in a standalone module, with no logging, sockets or console I/O. It needs C++23 (`std::expected`). Copy the two files into another project, or link the `schannel_groups` CMake target.

| API | Purpose |
|---|---|
| `GetOsDefaultGroups()` | OS-configured group list: GPO, else `Get-TlsEccCurve`, else `SslEnumEccCurves`. Returns `std::expected<OsGroupList, wstring>` |
| `GroupPolicy::Build(base, Mode::Disable \| EnableOnly \| Defaults, names, &warnings)` | Resolves names (Windows, IANA or OpenSSL spellings) against the base list. Check `valid()` |
| `policy.Allows(groupId)` | Allowlist test for a negotiated code point; fails closed |
| `SchCredentialData(certs, policy, disabledProtocols)` | Owns an `SCH_CREDENTIALS` + `TLS_PARAMETERS` block if you call `AcquireCredentialsHandle` yourself |
| `AcquireServerCredential(cert, policy, kTls13OnlyServer)` | Returns `std::expected<Credential, SECURITY_STATUS>`; `Credential` frees the handle |
| `NegotiatedGroup(&ctx)` / `ViolatesPolicy(&ctx, policy)` | Post-handshake check of the negotiated group |
| `BuildFatalAlert(cred, &ctx)` | Encrypted fatal alert record to send before closing |
| `FindGroup(name\|id)`, `SameGroup`, `KnownGroups()` | Group catalog: names and code points |

```cpp
#include "schannel_groups.h"     // include after winsock2.h if you use sockets
auto os     = schgroups::GetOsDefaultGroups();                 // check os.has_value()
auto policy = schgroups::GroupPolicy::Build(os->groups, schgroups::Mode::EnableOnly, {L"SecP384r1_MLKEM1024"});
auto cred   = schgroups::AcquireServerCredential(cert, policy, schgroups::kTls13OnlyServer);
// ... handshake with cred->get() ...
if (schgroups::ViolatesPolicy(&ctx, policy))
    if (auto alert = schgroups::BuildFatalAlert(cred->get(), &ctx)) { /* send *alert, then close */ }
```

`ViolatesPolicy` fails closed. Both `EnableOnly` and `Disable` require a known, enabled group, even when `EnableOnly` names the entire OS list. A group that isn't reported at all (a TLS 1.2 RSA or DHE key exchange, or a failed query) counts as a violation. Only `Defaults` accepts an unreported group.

## Build (VS 2026, MSVC v145, Windows SDK 10.0.28000+)

```
build.cmd                              # x64 Release (CMake)
build.cmd -Arch arm64 -Config Debug
build.cmd -NoCMake                     # Enter-VsDevShell + cl.exe directly
```

## Run

```
schgroups --port 9443                                        # OS defaults, nothing changed
schgroups --port 9443 --disable curve25519                   # defaults minus curve25519
schgroups --port 9443 --enable X25519_MLKEM768,SecP384r1_MLKEM1024   # only these two

# several ports, one process
schgroups --port 8443 --enable SecP384r1_MLKEM1024 --port 9443 --disable X25519_MLKEM768,curve25519 --port 10443
schgroups --port 8443:enable=SecP384r1_MLKEM1024 --port 9443:disable=curve25519     # shorthand
```

- **Port scoping:** `--disable`/`--enable` apply to the `--port` before them. Given before any `--port`, they apply to every port that sets neither. A port with neither uses the OS defaults.
- **`--disable` and `--enable` are mutually exclusive per port.** Both require a nonempty list. `--disable` rejects names outside the OS list; `--enable` keeps the intersection with the OS list and rejects an empty intersection.
- **Source of the OS default list,** in order of preference:
  - the Group Policy `ECC Curve Order` setting, if it is set
  - otherwise `Get-TlsEccCurve`
  - otherwise `SslEnumEccCurves`
- **Group names:** `curve25519`, `NistP256`, `NistP384`, `NistP521`, `X25519_MLKEM768`, `SecP256r1_MLKEM768`, `SecP384r1_MLKEM1024`. Case and underscores don't matter, and OpenSSL/IANA names such as `X25519MLKEM768` or `secp256r1` also work.
- **Cert:** by default the server makes a temporary RSA-3072 self-signed cert, and its key is deleted on exit. `--key p256` or `--key p384` gives you an ECDSA cert instead. In testing, an ECDSA cert made handshakes on ML-KEM hybrid groups fail with `SEC_E_ALGORITHM_MISMATCH` (no alert), while classical groups such as X25519 still worked. RSA worked for both. To use your own cert, pass `--cert <sha1>`; add `--machine` to read it from `LocalMachine\My`.
- **TLS 1.2:** `--tls12` also allows TLS 1.2; the default is TLS 1.3 only.

Each connection logs the protocol, cipher suite and negotiated group. The server also returns them in its HTTP response. To quit, type `q` and press Enter, or use Ctrl+C.

## Testing with OpenSSL (3.5+)

```
openssl s_client -connect localhost:9443 -tls1_3 -groups X25519MLKEM768 -brief
```

If the group is disabled, the handshake fails.

To probe every PQ and classic group one at a time, then offer them all at once:

```
.\test-groups.ps1 -Port 9443          # PowerShell
./test-groups.sh localhost 9443       # bash / WSL
```

## Full test matrix

After a CMake Release build, run `ctest --test-dir build\x64 -C Release --output-on-failure` for the policy and CLI regression tests. These do not need a configured PQ provider or a running server.

`run-tests.ps1` runs 25 OpenSSL tests against the four-port setup: PQ hybrid only, classic only, OS defaults, and pure ML-KEM only. The KeyUpdate case requires both peers to update their TLS 1.3 traffic keys and a successful HTTP response on the same connection. For each test the script prints the expected and observed result and PASS/FAIL, then an overall result. The exit code is 0 on pass and 1 on fail.

```
.\schgroups.exe --port 8443 --enable SecP384r1_MLKEM1024 --port 9443 --enable curve25519,NistP256,NistP384 --port 10443 --port 11443 --enable MLKEM1024
.\run-tests.ps1                       # -OpenSsl <path>, -PqPort/-ClassicPort/-DefaultPort to override
```

## Security behaviour

- **Loopback by default.** The server listens on `127.0.0.1` and `::1` only. Use `--bind any` for all interfaces, or `--bind <ip>` for one address. Testing from another machine needs one of those.
- **Disabled groups are enforced after the handshake.** Schannel documents per-credential disable IDs only for the NIST curves (`ECDH_P256`, `ECDH_P384`, `ECDH_P521`). For curve25519 and the ML-KEM groups the server passes the group name, and in testing Schannel refused `X25519_MLKEM768` that way but let `SecP384r1_MLKEM1024` and `MLKEM1024` through. So after every handshake the server checks the negotiated group, and if the port doesn't allow it, sends a fatal `handshake_failure` alert and closes.
- **What that check can't do.** The client has already finished the handshake when it is refused, so its first application data may have been sent under the disallowed group. Only a group Schannel itself refuses, or an OS-wide `Disable-TlsEccCurve`, prevents that.
- **`--no-enforce`** turns the check off, to see what Schannel alone accepts.
- **TLS 1.2 (`--tls12`).** Client-initiated renegotiation is refused. On a port with restricted groups, a TLS 1.2 connection is refused unless Schannel reports an allowed group for it.
- **Limits.** At most 256 concurrent connections; 10 s for a handshake and 30 s for a whole connection.
