# Deco TMP-over-SSH protocol (Deco app v3.10.666)

**Scope.** This spec covers how the Deco Android app talks to a Deco on the LAN, as far as the decompiled code shows it:

- TDP discovery
- SSH login
- the TMP v1 frame layer
- the AppBusiness V2 layer, including the session token
- the JSON envelope
- the bring-up sequence
- the opcodes a UniFi wrapper needs, with their JSON schemas

**Where things live.**

- **Citation paths** are relative to `scratchpad/deco-jadx/out/sources/` unless they say otherwise.
- **Dex annotations:** `dexcheck/sn6.txt` and `sn7.txt` are `@SerializedName` values extracted with `dexdump -a` from `base.apk` `classes6.dex` and `classes7.dex`. jadx drops these from enum constants.
- **Go code:** `internal/deco`. This spec was written beside a Go reference (`scratchpad/spec/go/`), which passed `go vet` and `go test -race` against an in-process emulator and had never talked to a real Deco. `internal/deco` was ported from it and is the only copy now (`docs/deco/reference-go/README.md` says where the old one is in the history); what it has read from a real Deco since is in its own comments.

**Labels used throughout.**

| Label | Meaning |
|---|---|
| **LIVE** | Observed on 2026-11-18 from the Unraid host by an earlier step: TDP replies and the SSH handshake only. No password was sent. |
| **INFERRED** | Reasoned out, not read from code. |
| **OPEN** | Needs a live test. See `open-questions.md`. |

---

## 0. Contradictions between the area reports, resolved against source

| # | Topic | Resolution | Evidence |
|---|---|---|---|
| R1 | NEGOTIATE `role` value | It is `"owner"` / `"user"`. The request-path report's `"ROLE_OWNER"` is wrong: jadx hides the annotation. | `dexcheck/sn6.txt:404-406` (EnumUserRole: ROLE_OWNER → "owner", ROLE_USER → "user"); `q1.java:388` |
| R2 | Enum wire values | They are **confirmed lowercase**. The unifi-openwrt report's "UNRESOLVED / maybe ROLE_MASTER" is superseded. Gson never accepts `name()` when an annotation exists. | sn6.txt:273-287 (EnumConnectionType: `band2_4`, `band2+band5`, …), :288-290 (`online`/`offline`), :375-377 (`master`/`slave`), :378-380, :381-383, :393-403 (EnumOperationMode `AP`, `Router`, …); sn7.txt:602 (`normal`/`strong`); `gson/internal/bind/TypeAdapters.java:189-227` |
| R3 | CRC check on an empty (`total=0`) response | The business-layer report says it is always checked; the request-path report says the e() path skips it. **Both are partly right.** With **one** PUSH (every request up to 8156 bytes), k() sends total=0 to c(): the CRC of `byte[0]` must equal the header crc, so the crc must be 0. With **more than one** PUSH, the first PULL_ACK goes to e(). An 18-byte remainder leaves the body null, so e() calls `d(null)` and returns `byte[0]` with **no** CRC check. | `transaction/a.java:107-110,134-141,157-165,177-186`; `business/v2/o.java:424-430` (body set only if `len>18`) |
| R4 | SSH username | It is `sha1hex(cloudUserName)` when TDP `need_account_digest` is true and TLS is off. The X20s qualify (LIVE). An earlier version of the auth report used the raw name; that was wrong. | `mesh/global/y.java:374-382`; `qi/c.java:470-480`; `dj/a.java:211-221,242-254` |
| R5 | Request timeout | The TMP layer has no per-frame timeout for Deco. The app wraps each whole request in caller timeout + 15 s, which is 45 s by default. | `mesh/context/c.java:848-851`; `tmp/h0.java:319-321`; `apps/network/tmp/i0.java:581` |
| R6 | Extra PULL offsets | The app pulls at `k*8156` for `k = 1..total/8156`, including one surplus PULL at `start==total` when total is an exact multiple. decotmp_v2 used "bytes received so far"; the spec Go follows the app. | `a.java:143-156` |
| R7 | Heartbeat schedule | It is armed on the idle edge, beats immediately, and is cancelled while requests are in flight. The auth report's "every 3 s while connected" is imprecise. | `h0.java:134-142,163-170,245-259` |
| R8 | Which unit is master | **192.168.0.241** (LIVE TDP `role=master`, `device_id == master_device_id`). The device_list `role` field can be trusted now that R2 is settled; still cross-check `device_id == master_device_id`. | TDP LIVE; `TMPDeviceBean.java:103` (role defaults to master when absent) |
| R9 | IP/MAC pairs | .205 = b0:a7:b9:3e:17:00, .232 = b0:a7:b9:3e:15:fc, .241 = b0:a7:b9:3e:16:94. | TDP LIVE |
| R10 | 5 GHz key in WirelessInfo | It is `band5_1`. `band5` exists only as a client connection type. | `WirelessInfoBean.java:12-31`; sn6.txt:278-279 |
| R11 | 0x4008 Set body | **Partial** `{band:{host:{…}}}` for each band present; guest goes in a separate Set. The host object itself is complete: it is the current host with patched keys, as `merge` does. The schemas and unifi reports agree once read together. | `MeshWirelessRepository.java:113-133,243-331,679-680`; `WirelessHostBean.java:120-132` |
| R12 | Client `interface` for guest clients | It is `"guest"`, confirmed. | `ClientDetailActivity.java:518,533` |

---

## 1. Layer stack

```
TDP  UDP <deco>:20002          discovery, owner check, SSH user mode, ports
SSH  TCP <master>:20001        dropbear; password = TP-Link ID password; user = sha1hex(TP-Link ID)
 └ direct-tcpip 127.0.0.1:20002
    TMP v1 frames              4-byte short frames; 16-byte DATA header with serial and CRC32
     └ AppBusiness V2 packet   20-byte header, token ops 1/2/3, transactions, 8156-byte chunks
        └ JSON                 {"config_version":ms,"params":P} → {"error_code":n,"msg":s,"result":R}
```

**What the app wires up for Deco.**

- Business layer: V2, via `mesh/context/c.java:1508-1512` → `business/v2/t.java:17-19` → `new o()`.
- TMP layer: v1, via `c.java:1604-1608` → `tmp/v1/c.b()`.
- These are wired into the client at `apps/network/tmp/n0.java:35-47` → `i0.java:171`.
- There is no version negotiation at any layer. V3 is used only by Tapo and BLE (`apps/network/tapo/f.java:585`; `vf/d.java:4,46`).

**The app targets only the master.** It uses the master's TDP IP and port (`manager/context/a.java:517-519,526-528`). Satellites are reached through the master's opcodes, which take a `device_id`.

---

## 2. TDP discovery (UDP 20002)

### 2.1 Packet format

A 16-byte big-endian header followed by the payload (`com/tplink/tdp/packet/b.java:50-65` write, `:201-211` parse).

| off | size | field | request value |
|---|---|---|---|
| 0 | 1 | version | 2 (`lk/f.java:52-54`) |
| 1 | 1 | reserved | 0 |
| 2 | 2 | opcode | 1 |
| 4 | 2 | payload length | 0 |
| 6 | 1 | flags | `0x21` unicast or `0x11` broadcast (`lk/f.java:38-45`) |
| 7 | 1 | result | 0. A reply must be 0 or 1 (`socket/l.java:157-158`). |
| 8 | 4 | serial | `SecureRandom.nextInt(2^28)` (`b.java:67-69`). The reply echoes it. |
| 12 | 4 | CRC32/IEEE | Computed over header plus payload with bytes 12-15 preset to `0x5A6B7C8D` (`b.java:42-48`) |

- **Reply checks** (`b.java:155-169`):
  - length > 0;
  - CRC is valid;
  - the match key is `serial + version`.
- **Reply body.** The request payload is empty (`codec/d.java:20-25`). The reply body is plaintext JSON `{"result":{…},"error_code":0}` (`codec/b.java:21-34`; `TDPResult.java:9-11`).
- **LIVE:** a v2/op1 unicast got a reply from all three units; v1/op2 got none.

### 2.2 Reply fields that matter

Read from `TDPGenericDevice.java:34-108` and `TDPMeshDevice.java:21-58`.

| field | X20 LIVE value | use |
|---|---|---|
| `ip`, `mac`, `device_id`, `role` | see R8 and R9 | unit identity and master |
| `master_device_id` | 8e6a0e5a031d7063c6f56bbc32e35f6e | the master's device_id |
| `tmp_port` | `[20001]` | SSH port when `tpap` is absent (`TDPMeshDevice.java:100-104`) |
| `tpap` | absent | absent means SSH2, not TLS (`TDPGenericDevice.java:282-300`) |
| `banner_type` / `ssh_banner_type` | absent | 1 would mean a `TPS-` ident (§3.3) |
| `need_account_digest` | true | SSH user = sha1hex (§3.1) |
| `owner` | adb5ef8e821e81d9ba0cc9992cb2ffc9 | `md5hex(cloudUserName)`, or sha256 when `hash_version` ≥ 1 (`TDPGenericDevice.java:246-252,271-275`) |
| `hash_version` | absent | absent means md5 |
| `factory_default` | false | when false, the owner match is required (`TDPMeshDevice.java:123-129`) |
| `device_model`, `hardware_version` | X20, 2.0 | |
| `group_id` | 76c2d2490ead66cd19c9274600cc61e1 | mesh id |
| `channel_2g`, `channel_5g` | 8, 44 | these are String fields in Java; parse them leniently |

- **Firmware version** is not in TDP. It comes from `device_list[].software_ver`.

---

## 3. SSH login

### 3.1 Credentials

These come from `manager/repo/t.java:174-193` (`G()`), the only place an SSH2 transport is built.

**Username.** The Deco override at `mesh/global/y.java:374-382` decides it:

```
user = need_account_digest && !TLS ? hex_lower(SHA1(cloudUserName.getBytes()))   // 40 chars
                                   : cloudUserName
```

- The `need_account_digest` lookup chain is: `X8()` = `mesh/context/c.java:1377-1379` → `qi/c.java:470-480`.
- `dj.a.t` is at `dj/a.java:211-221`, and its hex helper at `:242-254`.

**Password.** `t.a0()` = `TCAccountBean.password`, the plaintext TP-Link ID password (`t.java:509-514`; `TCAccountBean.java:210-212`).

- It is sent as UTF-8 through the standard RFC 4252 `password` method (`TPUserAuthPasswordMethods.java:120-134`).
- Cloud login stores the password unchanged (`x1.java:1059-1061`).

**cloudUserName.** This is the stored string:

- the server's `email` when it equalsIgnoreCase the typed username;
- otherwise the typed username (`x1.java:1052-1058`).

Casing matters for both md5 and sha1. **Pre-check offline:** `md5hex(candidate) == TDP owner`.

**Local access gate.**

- Not factory-default: the app uses SSH only if the owner hash matches (`TDPMeshDevice.java:123-129`; `manager/context/a.java:286-301`).
- A non-owner account would go through cloud/ATA instead (INFERRED). **The wrapper needs the owner TP-Link ID.**

### 3.2 Algorithms and behaviour

**What the app offers** (JSch 0.1.54 as patched by `com/tplink/ssh2/k.java:49-54,86-158`):

- kex: ecdh-sha2-nistp256/384/521, dh-group14-sha256 (`TPDHG256`), dh-group14-sha1, gex, dh-group1-sha1;
- host keys: ssh-rsa, ssh-dss, ecdsa;
- ciphers: aes128-ctr, among others;
- MACs: hmac-sha2-256, among others.

**What the X20 dropbear offers (LIVE):**

- kex: ecdh-sha2-nistp521/384/256, dh-group14-sha256;
- host keys: ecdsa-sha2-nistp521, ssh-rsa;
- ciphers: aes128-ctr, aes256-ctr;
- MACs: hmac-sha2-256/512;
- auth: publickey, password.

**Host keys.** The app accepts any key: `StrictHostKeyChecking=ask` with `promptYesNo()` returning true (`JSch.java:86`; `com/tplink/ssh2/m0.java:42-45`). The wrapper pins the LIVE fingerprints instead (`internal/deco/tmp.go` `PinnedHostKey`).

**Auth retries.**

- `MaxAuthTries=2` (`com/tplink/ssh2/k0.java:128`): the app re-sends the same password once after a plain failure (`TPUserAuthPasswordMethods.java:107,207-211`).
- It aborts immediately if the failure name-list contains `lockedMinute` + `remainAttempts` + `failedAttempts`, or `errorCode` (`:16-17,35-52,204-206`).
- **The wrapper sends exactly one attempt per connection.**

**Keepalive and timeout.**

- No ServerAliveInterval (`ssh2/j.java:159-161`).
- Overall connect timeout is 30 s (`t.java:191`; `manager/context/a.java:417-419`; `tmp/transport/k.java:180-182`).

### 3.3 Client ident

- Default: `SSH-2.0-JSCH-0.1.54` (`jsch/Session.java:88`).
- When TDP `banner_type == 1`: `TPS-2.0-JSCH-0.1.54`, which replaces the whole ident line (`com/tplink/ssh2/k0.java:136-139`; `Session.java:1616-1618`; `t.java:36,183`).
- The X20s have no `banner_type`, so the default applies.

### 3.4 Channel

After auth, the app calls `setPortForwardingL(0,"127.0.0.1",20002)` (`com/tplink/ssh2/k0.java:60-63`; `lk/g.java:42`). On the wire this is one `direct-tcpip` channel:

| field | value |
|---|---|
| host | 127.0.0.1 |
| port | 20002 |
| originator | 127.0.0.1 and the local port (`ChannelDirectTCPIP.java:57-70`) |

The connection is opened lazily, on the first TMP write (`client/w.java:237-255` → `transport/k.java:129-139,180-196`).

**LIVE port checks on .205:** TCP 22 and 20002 are closed; TCP 20001 runs SSH.

---

## 4. TMP v1 frame layer (`tmp/tmp/h0.java`, `tmp/v1/b.java`, `xk/*`)

**Version bytes** are `(1,1)` (`v1/b.java:46-48`). A received frame with another main or sub version fails with -2001 or -2002 (`h0.java:186-192`).

### 4.1 Short frames (4 bytes)

`[1, 1, type, reserved]`, used for types 1-4 and 6 (`v1/b.java:85-100`).

| type | meaning | v1 app behaviour |
|---|---|---|
| 1 / 2 / 3 | assoc request / accept / refuse | **never sent**. v1 `F()` completes immediately (`v1/b.java:80-83`), and the layer is CONNECTED at once (`h0.java:261-267,380-389`). |
| 4 | heartbeat | `[1,1,4,0]`. No serial, because v1 drops the payload for types 4 and 6 (`v1/b.java:95-99`). |
| 6 | bye | `[1,1,6,reason]`. Any received bye tears the layer down (`v1/b.java:102-107`; `h0.java:203-205`). |

**Bye reasons** (`v1/b.java:50-78`; `TMPLayerV1Exception.java:46-56`):

| value | reason |
|---|---|
| 0 | none |
| 2 | heartbeat timeout |
| 3 | client limit |
| 4 | reboot |
| 5 | wireless down |
| 6 | upgrade |
| 7 | user count exceeded |
| 8 | auth changed |
| 16 | kicked out |
| 17 | component changed |

### 4.2 Data frame (type 5)

A 16-byte big-endian header followed by the payload (`h0.java:449-454`; `xk/b.java:51-70`).

| off | size | field |
|---|---|---|
| 0-3 | 4 | `01 01 05 00` |
| 4 | 2 | payload length (u16) |
| 6 | 1 | flags, 0 |
| 7 | 1 | errcode: 0 in requests; non-zero in a reply means a frame-level error |
| 8 | 4 | serial (u32). Each TMP layer has its own `AtomicInteger(1)` (`h0.java:37,158-160`), which `W()` does not reset (`h0.java:460-484`). |
| 12 | 4 | CRC32/IEEE over the whole frame with bytes 12-15 preset to `0x5A6B7C8D` (`h0.java:391-402`; `xk/b.java:13`) |
| 16 | n | payload: exactly one business packet |

- **Reply matching.** A reply is matched to its request **by serial only**; the type is not compared (`h0.java:144-156,172-182`). `takeUntil` ends at the first match.
- **Reply errcode values** (`h0.java:333-363`):

  | errcode | meaning | code |
  |---|---|---|
  | 2 | CONFIG_VERSION | -2012 |
  | 3 | PAYLOAD_LEN | -2013 |
  | 4 | SN | -2014 |
  | 5 | CHECKSUM | -2015 |
  | other non-zero | CONFIG_FAILED | -2011 |

- **Bad reply CRC** fails with -2004 (`h0.java:350-356,614-626`).

### 4.3 Heartbeat

- **Interval** (`t.java:180-182`): 3000 ms, or -1 (off) for factory-default devices.
- **Schedule:** `interval(0, 3000)` starts when the in-flight count drops to 0. The first beat is immediate. It is cancelled when a request starts (`h0.java:134-142,163-170,245-259`).
- **Reply:** the app waits for a type-4 reply with no timeout (`h0.java:111-123,319-321`). INFERRED: the device echoes `[1,1,4,0]`. The device presumably drops idle sessions with bye reason 2 (OPEN: what timeout).

### 4.4 Teardown

1. Free the token (§5.5).
2. Send BYE `[1,1,6,0]` if the layer is CONNECTED. It is fire-and-forget (`h0.java:422-431,505-512`).
3. Close the channel.

---

## 5. AppBusiness V2 layer (`business/v2/o.java`, `u.java`, `transaction/a.java`)

### 5.1 Header (20 bytes, big-endian; `u.java:89-101,173-182`; `util/b.java:12-26`)

| off | size | field | values |
|---|---|---|---|
| 0 | 1 | business type | `0x01` (`wk/a.java:11`) |
| 1 | 1 | business version | `0x02` (`o.java:192-194`) |
| 2 | 2 | opcode | the app opcode, or 1/2/3 for token operations |
| 4 | 1 | operation | 2 = PUSH, 3 = PUSH_ACK, 4 = PULL, 5 = PULL_ACK (`u.java:119-131`) |
| 5 | 1 | status | 0 in requests; the result code in replies (§5.4) |
| 6 | 2 | transaction id | per-layer counter (§5.2) |
| 8 | 4 | crc32 | `java.util.zip.CRC32` of the whole logical payload. 0 for an empty payload and in PULL. |
| 12 | 4 | total | payload length (a signed int in Java). 0 in PULL. |
| 16 | 4 | start | offset of this chunk |
| 20 | ≤8156 | body | (`a.java:16`) |

**Reply validation** (`business/g.java:99-116`; `o.java:414-432`):

| condition | result |
|---|---|
| length < 2 | -3002 |
| byte 0 ≠ 1 | -3000, plus layer reset |
| byte 1 ≠ 2 | -3001, plus layer reset |
| remainder < 18 bytes | -3204 |
| status ≠ 0 | mapped as in §5.4 |

- The **body is null** when the remainder is exactly 18 bytes (`o.java:424-430`).
- The **reply opcode and transaction id are never checked.**

### 5.2 Transaction ids

`AtomicInteger(0)` runs 0, 1, …, 65534, then returns `0xFFFF` and resets to 0 (`o.java:161-166`). Token operations draw from the same counter. `p()` does not reset it.

### 5.3 Transaction state machine (`transaction/a.java`)

**Request side** (`a.java:70-96`):

- An empty payload is sent as **one** PUSH with crc=0, total=0, start=0 and no body.
- Otherwise the payload goes out as `len/8156 + 1` PUSHes. Every PUSH carries the same `crc=CRC32(payload)` and `total=len`, and chunk i has `start=i*8156`.
- When `len` is an exact multiple of 8156, the last PUSH is **empty**, with `start=len`.
- The app pipelines up to 20 packets per layer (`o.java:59,82-110`). Sending sequentially (window = 1) is INFERRED to be acceptable.

**Reply side** (`g()` at `a.java:211-253`):

1. **A reply that is not PULL_ACK** (normally PUSH_ACK) means "keep going". Once every PUSH has a reply, send `PULL start=0` (`op=4`, crc=0, total=0, no body) (`a.java:223-234`).
2. **Shortcut through `k()`** (`a.java:177-186`). If exactly **one** PUSH was sent and the PULL_ACK has `total==0 || len(body)==total`, the payload is assembled directly in `c()`. This applies whether the PULL_ACK answered the PUSH or the PULL.
3. **Otherwise the first PULL_ACK goes to `e()`** (`a.java:143-166`):
   - If `total/8156 > 0`, queue PULLs at `start = k*8156` for `k = 1..total/8156`. This includes a surplus PULL at `start==total` when total is an exact multiple.
   - Otherwise `len(body)` must equal `total` (else -3203), and the body is CRC-checked. A null body gives `byte[0]` with no CRC check (R3).
4. **Reassembly in `c()`** (`a.java:98-141`):
   - Allocate `byte[total]`, taken from the first PULL_ACK.
   - Append each PULL_ACK body.
   - Overflow, or a PULL_ACK `start` that differs from its PULL's `start`, gives -3203.
   - Then `CRC32(byte[total])` must equal the header crc, else -3200. Short data is zero-padded first, so it fails the CRC check.
5. **Device behaviour is OPEN:**
   - Does the device answer the final PUSH with PULL_ACK (step 2) or with PUSH_ACK (step 1)? Both work.
   - A PULL answered by something other than PULL_ACK hangs the app (`o.java:115-118`). Go treats this as a `ProtocolError`.

### 5.4 Status byte (`o.java:286-316`; `AppBusinessV2LayerException.java:62-81`)

| status | code | name |
|---|---|---|
| 0 | 0 | OK |
| 1 / unlisted | -3211 | UNKNOWN |
| 2 | -3212 | BUSINESS_TYPE |
| 3 | -3213 | BUSINESS_VERSION |
| 4 | -3214 | OPERATION |
| 5 | -3215 | FLAGS |
| 6 | -3216 | TRANS_ID |
| 7 | -3217 | TRANS_CRC32 |
| 8 | -3218 | TRANS_TOTAL_BYTES |
| 9 | -3219 | TRANS_START_BYTE |
| 10 | -3220 | TOKEN_EXPIRED |
| 11 | -3221 | TOKEN_ALLOC |
| 12 | -3222 | BUSINESS_FAILED |

- **Codes detected locally:** -3200 (CRC), -3201/-3202 (enqueue), -3203 (length or start), -3204 (short), -3000/-3001/-3002 (prefix).
- **Retry.** `client/f.java:161-171` re-runs the whole request **once**, including the token step. It does so when `TPGeneralNetworkException.e(th)` holds, which covers -3220, -3221 and transport -1202 (`AppBusinessV2LayerException.java:101-103`; `TransportLayerException.java:30-34`). The `cmd.h()` gate defaults to true (`m0.java:86-88`).

### 5.5 Session token

The token travels only as the payload of opcodes 1, 2 and 3 (`o.java:24-31`). **It never appears in normal requests.**

| op | name | request payload | effect |
|---|---|---|---|
| 1 | alloc | none | Reply bytes become the token (`new String(bytes)`, `o.java:384-391`), and it is marked verified. Empty `""` is a valid token. On failure the token is cleared and the TMP layer reset (`o.java:222-225,342-346,392-395`). |
| 2 | verify | token bytes | Used only after a layer reset (the verified flag is cleared). Success marks it verified (`o.java:373-382`). -3220 triggers a re-alloc. Any other error clears the token, resets the layer and propagates (`o.java:337-352`). |
| 3 | free | token bytes | Sent on close if a token exists (`o.java:210-220,254-266,398-406`). |

- **Before every request**, `N()` runs under `Semaphore(1)` (`o.java:196-208,277-284,354-371`):
  - token held and verified → proceed;
  - no token → alloc;
  - token held but not verified → verify.
- **Opcode 0 with a null payload** runs the token step only (`o.java:436`).
- **Reset triggers for `o.p()`** (`o.java:449-458`):
  - transport DISCONNECTED (`client/w.java:172-190`);
  - a received BYE (`v1/b.java:102-107`);
  - a bad business type or version (`g.java:107-115`).
- **What `o.p()` does:** clears `verified` (only if no token step is running), keeps the token, zeroes the in-flight window and resets the TMP layer.
- **Status 10 or 11 on a normal request.** The app retries once **with the same token** (`o.java:441-446`). The Go client drops the token first so the retry re-allocates (INFERRED recovery).

**First bytes on the wire after the channel opens** (TMP serial 1, transaction id 0):

```
TMP  01 01 05 00 0014 00 00 00000001 <crc32>
V2   01 02 0001 02 00 0000 00000000 00000000 00000000        (PUSH, opcode 1 = token alloc)
```

---

## 6. JSON envelope (`apps/network/tmp/bean/AppRequest.java:48-111`)

**Command flags.** Deco commands use `mesh/context/base/a`, created at `base/d.java:133` (Set) and `:145` (Get). It keeps these `m0` defaults (`m0.java:70-96`):

- the request is wrapped in TMPParams;
- the reply is a TMPResult envelope;
- the body is JSON, not TLV;
- retry is allowed.

Get and Set are identical on the wire (`repo/j.java:137-155` → `repo/d.java:279-297`).

**Request** (`TMPParams.java:17-22`), UTF-8:

```json
{"config_version":1763450000000,"params":{ ... }}
```

- `config_version` is always present: `System.currentTimeMillis()` (`AppRequest.java:56`).
- `params` is omitted when null, because serializeNulls is off.
- HTML escaping is off (`k0.java:21-29`; `gson/d.java:187-189`).

**Reply** (`TMPResult.java:17-24`):

```json
{"error_code":0,"msg":"...","result":{ ... }}
```

| reply | meaning |
|---|---|
| empty payload | `TMPResult(0)`: success with no result (`AppRequest.java:110`) |
| `error_code ≠ 0` | `TMPException(opcode, code, msg, raw)` (`i0.java:651-667`) |
| `error_code == 1010` | treated as "no data" by repositories (`repo/d.java:136-139`) |

- `error_code` is a primitive int read by `IntegerCompatTypeAdapter`: numeric strings are accepted, and garbage becomes `Integer.MAX_VALUE` (`k0.java:24-28`).

**Gson read rules** (`k0.java:21-29`; `TypeAdapters.java:189-227,1118-1127`; `JsonObjectCompatTypeAdapterFactory.java:26-36`):

| field type | rule |
|---|---|
| primitive int / long | lenient: a bad value becomes MAX_VALUE |
| boxed Integer / Long | a bad value becomes null |
| String | also accepts a number token |
| enums | only the `@SerializedName` value (or an alternate) or `toString()`; never `name()` |

**Base64 fields** (`bo/Base64TypeAdapter.java:11-28`; `dj/a.java:23-25,48-50`):

- On the wire they are standard base64, NO_WRAP.
- A value that does not match the base64 regex is kept raw.
- `custom_nickname` uses `LocationBase64TypeAdapter`, which never decodes the literal `"basement"`.
- These fields are base64: `ssid`, `password`, `default_ssid`, `default_password`, `custom_nickname`, and the client `name`.

---

## 7. Bring-up sequence (owner account, SSH2)

1. **Discover.** Send TDP unicast to each IP (§2), pick `role=master`, and require `md5hex(cloudUserName) == owner`.
2. **Connect.** SSH to `master:tmp_port[0]` with `user = sha1hex(cloudUserName)` and the plaintext password. Open direct-tcpip to `127.0.0.1:20002`. Send no TMP association.
3. **Allocate a token:** V2 opcode 1, empty PUSH (§5.5).
4. **NEGOTIATE 0x4001** (`q1.java:387-397`; `p.java:480`), body:

   ```json
   {"config_version":<ms>,"params":{"role":"owner","username":"<hex SHA-256(cloudUserName)>"}}
   ```

   - `role` is `"owner"` iff the account owns the network (`q1.java:388`; sn6.txt:404-406).
   - `username` is `wf.d.d` = lowercase hex SHA-256 (`wf/d.java:38-64`).
   - **The app tolerates any TMPException and any V2 error except -3222 here** (`q1.java:721-725,326-332,428-430`).
5. **Optional follow-ups** the app makes (INFERRED to be optional):
   - component fetches, which may run concurrently;
   - AccountModify 0x4511 (conditional);
   - locale 0x4204 `{"lang":…}` (`q1.java:739-757`).

   **The wrapper should skip these.**
6. **Normal requests.** Heartbeats run while idle (§4.3).
7. **Teardown:** free token, then BYE, then close.

**Worked example: Get 0x4009 with no params.**

```
JSON  {"config_version":1763450000000}
V2    01 02 4009 02 00 <tid> <crc32(JSON)> <len(JSON)> 00000000 || JSON          PUSH
TMP   01 01 05 00 <len(V2)> 00 00 <serial> <crc*> || V2
 <-   DATA same serial: V2 PULL_ACK (data) or PUSH_ACK
[->   PULL 01 02 4009 04 00 <tid> 0 0 00000000]  <- PULL_ACK chunks
JSON  {"error_code":0,"result":{"band2_4":{...},"band5_1":{...}}}
```

---

## 8. Opcodes the wrapper needs

**Source of truth.** Opcodes are from `mesh/global/p.java` (name map: `:1294-1296` token verify/free and `TMP_APPV2_OP_COMP_NEGOTIATE`, `:1303-1304` `TMP_APPV2_OP_WIRELESS_SET/GET`). Schemas are from the bean classes. Go types and the opcode constants are in `internal/deco/schemas.go`; a test holds this table to the constants (every `Op...` constant has a row).

- "params null" means the request body is just `{"config_version":…}`.
- `opcodes_annot.txt` is incomplete (it lacks the LED opcodes). Grep `p.java` directly.

| op | p.java | kind | params | result | call site |
|---|---|---|---|---|---|
| 0x4001 | f65921e:480 | negotiate | NegotiationParams | NegotiationResult | q1.java:387-397 |
| 0x400f | f66095s:1002 | Get | null | DeviceListResult | mesh/repository/e0.java:458 |
| 0x4012 | f66131v:1110 | Get | null (app timeout 60 s) | ClientListResult | tpm5/.../client/repository/l0.java:930 |
| 0x4014 | f66155x:1182 | Get | null | ClientSpeedListResult | l0.java:984 |
| 0x4015 | f66167y:1218 | Get | `{mac}` | ClientSpeedBean | l0.java:968 |
| 0x4040 | f66120u0:1077 | Get | null | IotClientListResult | smart/client/repository/v.java:1577 |
| 0x4009 | f66023m:786 | Get | null | WirelessInfoBean | MeshWirelessRepository.java:1617 |
| 0x4008 | f66011l:750 | Set | partial WirelessInfoBean | Boolean, default TRUE | MeshWirelessRepository.java:680 |
| 0x43b0 / 0x43b1 | f66067p7:918 / f66079q7:954 | Get / Set | MLO: `WirelessMloInfo` in `internal/deco/schemas.go` | | not recorded; nothing in this repository sends them |
| 0x4016 | f66179z:1254 | Set | `{device_list:[{device_id}]}` | `{reboot_time:int}` | e0.java:626 (body built at e0.java:149-156) |
| 0x4017 | A:10 | Set | ClientBlockParams (block-list add) | default null | l0.java:1334 |
| 0x4018 | B:22 | Get | null | ClientBlockListResult | l0.java:1607 |
| 0x4019 | C:34 | Set | ClientUnblockParams (block-list remove) | default null | l0.java:1399 |
| 0x4402-0x4407 | R7..W7:222-282 | Set/Get | access-control mode, allow list, client access | | l0.java:1194,1042,1267,1051,1574,1170 |
| 0x4327 | f66069p9:924 | Get | `{device_list:[{device_id}]}` | DeviceEthPortResult | e0.java:449 |
| 0x422f | f66158x2:1191 | Get | `{device_list:[{device_id}]}` | DeviceSpeedListResult | e0.java:493 |
| 0x4317 | G8:91 | Get | `{device_list:[{device_id}]}` (one id) | DeviceResourceInfoResult | e0.java:480 |
| 0x4094 | f66037n1:828 | Get | `{device_id}` | SignalLevelListResult | e0.java:565 |
| 0x401a / 0x401b | D:46 / E:58 | Get / Set | null / LEDBean | LEDBean / TRUE | led/repository/j.java:161,182 |
| 0x42f7 | O8:187 | Get | null | `{device_list:[{device_id,led_category}]}` | j.java:226 |
| 0x42f0 / 0x42f1 / 0x42f2 | x4/y4/z4 | Get/Set/Get | WirelessBandwidthSwitchBean | `{countdown}` / `{status}` | wireless/repository/g.java:493,409,502 |
| 0x4390 / 0x4391 | N6/O6 | Get/Set | `{enable}` | | wireless/repository/s.java:29,46 |
| 0x4098 | K9:140 | Get | null | QsWifiStatusResult (quick setup only) | quicksetup/repository/c.java:65 |
| 0x4038 | f65961h0:600 | not recorded | `AccountModifyParams` `{cloud_account:{email,password}}` (`TMP_APPV2_OP_ACCOUNT_MODIFY`: re-binds the cloud account and rewrites `/etc/shadow`) | | not recorded; nothing in this repository sends it |

### 8.1 NegotiationResult (`bo/negotiation/result/NegotiationResult.java:22-61`)

```
component_list   [{id|component, ver_code:int, lock}]     feature gating (OPEN: which ids the X20 lists)
operation_mode   "Router" (default, :48-49) | "AP" | "Repeater" | "DSL_Bridge" | ...   (sn6.txt:393-403)
working_status   default "well";  easymesh_role "controller"|"agent"
group_data, hardware_info, region, topology_limit, eco_mode_status, eco_mode_advanced_status,
extra_isp, front_modem, device_color, alert_operation_mode_switch
```

**`operation_mode` tells whether the mesh is in AP mode.** This matters for UniFi client correlation.

### 8.2 DeviceListResult (0x400f)

The result is `{device_list:[TMPDeviceBean], non_deco_device_list:[TMPAgentBean], warnings:[{msg}]}`.

**Base fields** (`TMPDeviceBaseBean.java:26-75`):

| key | type and notes |
|---|---|
| `device_id`, `device_model`, `hw_id`, `oem_id`, `software_ver`, `ip`, `mac`, `parent_device_id` | strings. **The MAC format is OPEN.** |
| `connection_type` | [`band2_4`\|`band5`\|`band5_1`\|`band5_2`\|`band6`\|`band6_2`\|`wired`\|`plc`\|`zigbee`\|`bluetooth`\|`band2+band5`\|…] |
| `custom_nickname` | LocationBase64 |
| `nickname` | enum, default `custom` |
| `easymesh_role` | `controller` \| `agent` |
| `signal_level`, `signal_strength` | `{band2_4,band5,band5_1,band5_2,band6,band6_2: String}` |
| `inet_status` | `online` \| `offline`, **default online** |
| `support_easy_mesh`, `eth_port_info_support` | booleans |

**TMPDeviceBean adds** (`TMPDeviceBean.java:26-128`):

| key | type and notes |
|---|---|
| `role` | `master` \| `slave`, **default master** (:103) |
| `master_device_id` | string |
| `hardware_ver` | string |
| `runtime`, `online_time` | Integer; INFERRED seconds |
| `group_status` | `connected` \| `disconnected`, default connected |
| `is_wired` | boolean |
| `topology` | `{auto, backhaul_mode:wifi\|plc, device_id, plc_signal, support_backhaul}` |
| `tx_rate`, `rx_rate` | Integer |
| `last_online_timestamp` | Long |
| `resource_support`, `resource_interval` | Boolean / Integer |
| `inet_error_msg` | enum |
| `inet_connection_type` | default `ewan` |
| `set_gateway_support`, `enable_gateway_feature` | default true |
| `default_ssid`, `default_password` | b64 |
| `combo_port`, `eth_bkhl_ports`, `fixed_wan_port`, `port_count`, `speed_get_support`, `zigbee_role`, `detail{device_id,isp_error_code}` | other fields |

**Defaults apply whenever a key is absent:** the class has no explicit constructor.

### 8.3 ClientListResult (0x4012)

The result is `{client_list:[ClientBean], is_ipv6_client_priority_support, priority_count_max, speed_limit_count_max}`.

**ClientBean** (`ClientBean.java:19-96`):

| key | type and notes |
|---|---|
| `mac`, `ip` | strings |
| `name` | b64 |
| `online` | Boolean |
| `interface` | `main` \| `guest` \| `iot` \| `mlo` |
| `client_type` | entertainment \| iot_device \| laptop \| other \| pc \| phone \| printer \| tablet |
| `access_time` | Long; INFERRED unix seconds |
| `online_time`, `last_online_time` | Integer |
| `linked_device_info` | see LinkedDeviceBean below |
| `custom_client_type` | String; replaces `client_type` when `client_fing` is negotiated (`l0.java:717-722`) |
| `client_mesh`, `enable_priority`, `enable_isolation`, `has_set_client_type`, `first_connected`, `extra_realtime_status`, `remain_time`, `speed_limit`, `link_priority`, `owner_id`, `space_id`, `brand`, `model`, `system_version`, `time_period`, `user_set_name_type` | other fields |

ClientBean has no speed fields.

**Live (fw 1.3.0 Build 20250912, AP mode):** the first 0x4012 of a session answered after 62 s with 69,242 bytes: 192 entries, every one `online:false`, no `ip`, `access_time`, `online_time` or `last_online_time`; 10 entries still carried `linked_device_info` (`connection_type`, `device_id`, `signal_level` only) and `client_mesh`. MACs are uppercase with dashes (`8E-56-D7-04-BB-8F`). The app would show this as 0 online, 192 offline (`ClientBean.java:287-289`). udeco therefore reads presence from 0x4014/0x4040 and uses 0x4012 only as a slow enrichment (design §3.2).

**IotClientListResult** (0x4040, `IotClientListResult.java:13-23`) is `{iot_client_list:[BaseIotDeviceBean], iot_count_per_cate_max, scan_status: scanning|idle, scan_wait_time}`. BaseIotDeviceBean (`BaseIotDeviceBean.java:18-80`) has `iot_client_id`, `name`/`type_name` (b64), `inet_status` (online|offline|reset; online is `IotClientBean.s1()`), `module`, `category`, `subcategory`, `bind_status`, `detail` (module-specific JSON), `linked_device_info`, `link_priority`, `interface`, `access_time`, `online_time`, `last_online_time`, `space_id`, `speed_limit`, and others. It has no top-level `mac` or `ip`; udeco reads them from `detail` (INFERRED). These are smart-home devices; the Wi-Fi clients of the IoT SSID are 0x4012 entries with `interface:"iot"`.

**LinkedDeviceBean** (`linked_device_info`):

| key | type and notes |
|---|---|
| `device_id` | the Deco the client is attached to |
| `connection_type` | [enum]; the first entry is the client's link key |
| `signal_level`, `signal_strength`, `tx_rate_list`, `rx_rate_list` | `{<link key>: int}`, keyed by the same link keys, e.g. `band5`, `band2+band5` |
| `bandwidth` | String |
| `encryption_mode`, `mimo`, `wireless_ver` | other fields |

**Speeds:**

- 0x4014 returns `{client_list_speed:[{mac, up_speed:int, down_speed:int, in_hnat:bool}]}`.
- 0x4015 takes `{mac}` and returns one such entry.
- Units are **kbps** (`ClientDetailActivity.java:912-921` → `FlowUnitUtils.java:296-304`; `strings.xml:1772`).

### 8.4 WirelessInfoBean (0x4009 / 0x4008)

**Bands** (`WirelessInfoBean.java:12-31`):

- Top-level keys: `band2_4`, `band5_1`, `band5_2`, `band60`, `band6`, `band6_2`, `config_spec`.
- INFERRED: the X20 returns `band2_4` and `band5_1`.

**Each band** (`WirelessBandBean.java:13-36`) contains:

- `host`, `guest`, `iot`, `radio{channel:String, enable:bool, htmode, hwmode}`;
- `backhaul{channel:int}`, `amazon_ffs{enable}`, `owe_support`, `unsupported_device_list`.

**Encryption modes:** `none`, `owe`, `wpa2`, `wpa2+wpa`, `wpa3`, `wpa3+wpa2`.

**host** (`WirelessHostBean.java:15-39`): `enable`, `ssid`(b64), `password`(b64), `encryption_mode`, `enable_hide_ssid`, `enable_wpa3`, `is_separate`, `has_set`, `show_combine_guide`.

**guest** (`WirelessGuestBean.java:16-70`): `enable`, `ssid`, `password`, `encryption_mode`, `enable_wpa3`, `client_isolation`, `host_isolation`, `access_duration`, `remain_time`, `bandwidth_limit{downstream_bandwidth,enable,upstream_bandwidth}`, `need_set_vlan`, `vlan_id`, `is_separate`, `has_set_guest_network`, `show_combine_guide`.

**config_spec:** `{ssid, password, password_strength:"normal"|"strong", password_requisite{…}, password_valid_regx}`.

**Set rules** (`MeshWirelessRepository.java:113-133,243-331,679-680`):

- Send `{<band>:{host:{…}}}` for every band present in the Get, and nothing else.
- The host object is the current host with the patched keys, as `merge` does.
- Each band keeps its own `enable`.
- `band60` reuses `band5_1`'s host.
- Guest changes go in a separate Set, `{<band>:{guest:{…}}}`.
- **Never send** `config_spec`, `backhaul`, `radio`, `iot`, `amazon_ffs`, `owe_support` or `unsupported_device_list`.
- The app always writes the **same SSID and password to every band**. Per-band SSIDs are OPEN.

**Example Set:**

```json
{"config_version":1763450000000,"params":{
  "band2_4":{"host":{"enable":true,"ssid":"TmV3U1NJRA==","password":"TmV3UGFzc3dvcmQ=","encryption_mode":"wpa2","enable_hide_ssid":false,"enable_wpa3":false}},
  "band5_1":{"host":{"enable":true,"ssid":"TmV3U1NJRA==","password":"TmV3UGFzc3dvcmQ=","encryption_mode":"wpa2","enable_hide_ssid":false,"enable_wpa3":false}}}}
```

### 8.5 Client actions

| op | body | notes |
|---|---|---|
| 0x4017 block | `{"client_list":[{"mac":…,"name":"<b64>","client_type":…}]}` | `ClientBlockBean.java:12-20` |
| 0x4019 unblock | `{"client_list":["<mac>",…]}` | `ClientUnblockParams.java:11-12` |
| 0x4018 list | returns `{client_list:[ClientBlockBean], max_count}` | |
| 0x4404 / 0x4405 | allow-list add / remove | Used when `access_control_mode == "white_list"` (`AccessControlModeBean.java:12-25`). |
| kick | none | No disconnect opcode was found. |

### 8.6 Reboot, ports, LED

- **0x4016** reboot body: `{"device_list":[{"device_id":"…"}]}` (`DeviceIdListParams.java:11-12`; `DeviceIdParams.java:9-10`).
- **0x4327** ports: `{device_list:[{device_id, port_info:[{port, port_speed, bit_error_rate, ports_status_info:[{status:well|unplugged|no_internet|dial_failed, type:wan|lan|eth_bkhl|iptv|voip}]}]}]}`.
- **LEDBean** (`LEDBean.java:15-45`): `{enable, enable_night_mode, led_individual_control, schedule:[{device_id, enable, …}], time_begin, time_end}`. The simple toggle is `{"enable":false}` (`led/repository/j.java:221-223`).

### 8.7 Not available

No opcode was found for any of these (INFERRED from grep of `p.java` usage):

- per-radio tx power;
- per-unit current channel (`radio` and `0x42f0` are network-wide);
- real BSSIDs;
- client kick;
- per-station retries.

---

## 9. Go code (`internal/deco`, package `deco`)

The protocol layers of this spec, by file. The package also holds what the daemon builds on them (`mesh.go`, `live.go`, `collect.go`, `wlan.go`; see `design.md`).

| file | contents |
|---|---|
| `internal/deco/discovery.go` | `EncodeTDP`/`DecodeTDP`/`DiscoverDeco`, `DecoInfo.OwnerMatches`, `SSHUsername`, `SSHPort`, `UsesTLS`, `TPSBanner` |
| `internal/deco/tmp.go` | `DecoSSHConfig`, `DialTMP`, `PinnedHostKey`; TMP v1 `EncodeDataFrame`, `ReadFrame`, and `FrameConn` (serial demux, idle-edge heartbeat, BYE handling) |
| `internal/deco/business.go` | V2 `Transact` (mirrors `a.java`, including R3), `Session` (token state machine, retry), `EncodeRequest`/`DecodeResult`, `NegotiationParams` (role `owner`/`user`), and `Client` (`Connect`, `Call`/`Get`/`Set`, lazy redial, `Close`) |
| `internal/deco/schemas.go` | the opcodes and all beans in §8, lenient scalar types, `BuildHostSet`/`BuildGuestSet` |
| `internal/deco/emulator_test.go` | in-process device emulator covering both ack styles, multi-chunk replies and requests, the empty-response CRC rule (R3), empty-token handling, heartbeat echo, negotiate tolerance, and the TDP/username vectors |

**Verified:** the emulator tests run with the repository's `go vet ./...` and `go test ./...`.

**Not verified by these tests:** behaviour against a real Deco (`open-questions.md`).
