# Open questions for the live test, ranked by risk

**Ranking.** Risk is the damage a wrong assumption would do, multiplied by how unsure we are.

**Test rules.**
- Every test uses the owner TP-Link ID and talks only to the master 192.168.0.241.
- Make **one SSH login per test run**. The lockout thresholds are unknown.
- The first run is `udeco -print`, which is read-only.

## Tier 1: blockers. If any of these is wrong, nothing works.

### 1. Exact `cloudUserName` string
- **Why it matters:** SSH user = `sha1hex(cloudUserName)` (`mesh/global/y.java:374-382`), and TDP owner = `md5hex(cloudUserName)` (`TDPGenericDevice.java:246-252`). Both hash the stored string. The app stores the server-returned e-mail when it equalsIgnoreCase the typed one (`x1.java:1052-1058`), so casing matters.
- **Test (offline, no device contact):** check that `md5(candidate) == adb5ef8e821e81d9ba0cc9992cb2ffc9`. Try the casing variants offline before any login.
- **Risk:** high. A wrong guess wastes a login and counts toward lockout.

### 2. SSH password login on .241:20001
- **Why it matters:** the auth method is read from code (P§3.1), but it has never been tried. We also don't know whether dropbear checks the password locally or against the cloud. That decides whether the wrapper keeps working when the internet is down.
- **Lockout:** the tokens (`lockedMinute`, `remainAttempts`, `failedAttempts`, `errorCode`) arrive in the USERAUTH_FAILURE name-list, which x/crypto/ssh hides. If the first login fails, **stop and capture with a raw client**. Do not retry.
- **Risk:** high, because of the account lockout.

### 3. Device accepts the client ident and window=1
- **What we send:** ident `SSH-2.0-JSCH-0.1.54`, and sequential sends (the app pipelines up to 20 packets, `o.java:59,82-110`).
- **Expected:** both fine (INFERRED).
- **Risk:** medium.

### 4. First exchange: token alloc
- **Question:** does the reply to `PUSH opcode=1` arrive as a direct PULL_ACK or as PUSH_ACK followed by PULL? Is the token ASCII?
- **Coverage:** the Go code handles both reply styles (`a.java:211-253`).
- **Risk:** low to medium. It is mainly confirmation.

### 5. NEGOTIATE `{"role":"owner","username":sha256hex}`
- **Source:** the role spelling comes from dex (`sn6.txt:404-406`). The jadx view suggested `"ROLE_OWNER"`, which is wrong.
- **Coverage:** the app tolerates negotiate errors other than -3222, and so does the Go code. A NEGOTIATE result is also read like Gson would (numbers in String fields, `"true"` in Boolean ones), and a field of any other unexpected type is kept as `negotiation_err` instead of failing the login.
- **Also record:** `operation_mode` (`AP` vs `Router`) and `component_list`.
- **Risk:** medium. If the device rejects or ignores it, later opcodes may also be refused.

## Tier 2: correctness of what UniFi shows

### 6. Session contention with the phone app
- **Question:** do our persistent session and the phone app coexist? Watch for BYE reason 3 (CLIENT_LIMIT), 7 (USER_COUNT_EXCEED) or 16 (KICK_OUT) (`v1/b.java:50-78`).
- **Also measure:** how long an idle session survives with heartbeats, whether the device echoes `[1,1,4,0]`, and the device-side heartbeat timeout (bye reason 2).
- **Fallback:** connect per poll, which costs one SSH login each time.

### 7. Operation mode
- **Question:** is the mesh in AP mode? `operation_mode`, from NEGOTIATE or a capture, answers this.
- **Why it matters:** in Router mode, Deco clients sit behind NAT and will not correlate with UniFi clients.
- **Risk:** high for usefulness, low for safety.

### 8. MAC string format
- **Question:** what format do `device_list[].mac` and `client_list[].mac` use? Colons or dashes, and which case?
- **Why it matters:** this affects block bodies, `ClientMacParams` and ARP keys.
- **Mitigation:** the design normalises reads. For writes, echo the exact string the device returned.

### 9. Units
- **Questions:** what are the units of `runtime` and `online_time` (assumed seconds), `access_time` (assumed unix seconds), `signal_strength` (assumed dBm) and `signal_level` (assumed bars)?
- **Also unknown:** `tx_rate_list` and `rx_rate_list` (assumed Mbps), `port_speed` (assumed Mbps) and `reboot_time` (assumed seconds).
- **Known:** client up/down speeds are kbps (`FlowUnitUtils.java:296-304`).

### 10. `linked_device_info` on X20 firmware
- **Question:** is it present, keyed by the Deco `device_id`, with lowercase link keys as in `sn6.txt:273-287`?
- **Why it matters:** without it, clients cannot be assigned to an AP.

### 11. 0x4012 needs no params
- **Question:** does 0x4012 work with null params, and does it list the clients of every unit through the master?
- **Basis:** the app sends null params (`l0.java:930`). The second part is INFERRED.

### 12. Controller behaviour (UniFi Network 11.1.47)
- **Question:** does it accept three devices reporting the same `ip` with different `sshd_port`? Does `U7PG2` or `UAL6` adopt and render correctly?
- **Untested upstream:** Network 11.x has not been tested at all.

## Tier 3: write paths. `apply:false` until these are answered.

### 13. Partial 0x4008 body
- **Question:** is a partial body accepted? It holds only `{band:{host:{full current host + patch}}}`.
- **Also measure:** how long the backhaul drops, and how long the satellites take to return to device_list. That sets the verify window (3 min proposed).
- **Risk:** high. A bad Set could take the Wi-Fi down. Rollback needs the master reachable over wired Ethernet from Unraid (INFERRED: the master is wired to the UCG).

### 14. Set result shape
- **Question:** what does the result of 0x4008, 0x4017, 0x4019 and 0x401b look like: absent, `true`, or an object?
- **Mitigation:** the code keeps it raw and treats `error_code==0` as success.

### 15. WPA3 semantics
- **Question:** does `enable_wpa3` mean WPA2/WPA3 transition mode or WPA3-only? Are per-band SSIDs accepted?
- **Basis:** the app never sends per-band SSIDs.

### 16. Block-list availability
- **Question:** does the X20 support the block list (0x4017/0x4019), the allow list (0x4402-0x4405), or both? This depends on `component_list`.

### 17. Reboot through the master
- **Question:** does 0x4016 accept a satellite's `device_id` when sent to the master?

### 18. Token lifetime
- **Question:** how long does a token live? Is it bound to the SSH channel? Does status 10 ever occur mid-session?
- **Current behaviour:** the Go code re-allocates once. The app instead retries with the same token.

### 19. Surplus PULL
- **Question:** how does the device answer the surplus PULL at `start==total` for exact multiples of 8156?
- **Risk:** low. It needs a reply of 8156×k bytes.

### 20. Optional bring-up calls
- **Question:** are the follow-up calls the app makes (0x4511, 0x4204, component fetches) unnecessary for a third-party client?
- **Assumption:** yes (INFERRED).
