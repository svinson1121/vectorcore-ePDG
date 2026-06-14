# VoWiFi ↔ VoLTE Handover

VectorCore ePDG supports both directions of access-network handover between Wi-Fi (VoWiFi) and LTE (VoLTE). Each direction is detected and handled independently.

---

## VoWiFi → VoLTE (UE moves from Wi-Fi to LTE)

When a UE on an active VoWiFi call moves to LTE coverage, the EPC migrates the IMS session to the LTE path. The PGW signals this to the ePDG by sending a **Delete Bearer Request** (or Delete Session Request) with GTPv2-C Cause = 10 (Access changed from Non-3GPP to 3GPP, TS 29.274 Table 8.4-1).

### What the ePDG does

1. **Detects handover cause** — `handleDeleteBearerRequest` in `internal/s2b/client.go` parses the Cause IE. Cause 10 (and fallback Cause 8, Reactivation Requested) sets `DeleteBearerEvent.IsHandover = true`.
2. **Tears down the IKE SA** — `handlePGWDelete` in `cmd/epdg/main.go` tears down XFRM + GTP-U + S2b state.
3. **Sends SWm STR with correct cause** — STR is sent with `Termination-Cause = 8 (DIAMETER_USER_MOVED)` on handover, vs. `Termination-Cause = 1 (DIAMETER_LOGOUT)` on a normal UE-initiated or DPD-timeout detach. Using the wrong cause risks the AAA deregistering the subscriber from non-3GPP access prematurely.

### Teardown sequence

```
PGW  →  ePDG  Delete Bearer Request (EBI=5, Cause=10)
ePDG →  PGW   Delete Bearer Response (Cause=16 Request Accepted)
ePDG →  AAA   STR (Termination-Cause=8 DIAMETER_USER_MOVED)
              [XFRM SA removed, GTP-U bearers removed, IKE SA deleted]
```

### Log indicators

```
"handover signal on bearer": IsHandover=true, ebi=5
"IKE SA torn down": reason="ike_delete_by_ue"
"SWm STR sent": cause=8
```

---

## VoLTE → VoWiFi (UE moves from LTE to Wi-Fi)

When a UE on an active VoLTE call moves to Wi-Fi coverage, it initiates a new IKEv2 session to the ePDG but signals that it wants to **preserve its existing PDN connection** rather than create a new one. The ePDG must detect this and instruct the PGW to hand over the session.

### How the UE signals handover intent (3GPP TS 24.302 §8.2.3)

The UE includes its currently-assigned LTE IP address as the value of `INTERNAL_IP4_ADDRESS` in the IKE_AUTH CFG_REQUEST. A non-zero value in this attribute indicates a handover attach.

### What the ePDG does

1. **Detects handover in IKE_AUTH round 1** — `handleAuthRound1` in `internal/ikev2/auth.go` reads the `Value` field of the `INTERNAL_IP4_ADDRESS` attribute. If the value is a non-zero IPv4 address, `sa.handoverIP` is set.
2. **Sets HI bit in S2b Create Session Request** — When `sa.handoverIP` is non-nil, `CreateSessionRequest.Handover = true` is passed to the S2b client, which appends an **Indication IE** (type 77, TS 29.274 §8.12) with the **HI bit set** (octet 3, bit 1 = `0x02`). The PGW recognises this and hands over the existing PDN connection, assigning the same IP address.
3. **Validates the returned PAA** — If the PGW assigns a different IP than the UE requested, a WARN is logged. The session continues with the PGW-assigned address.

### Attach sequence

```
UE   →  ePDG  IKE_AUTH CFG_REQUEST (INTERNAL_IP4_ADDRESS=<LTE IP>)
              [EAP-AKA exchange]
ePDG →  PGW   Create Session Request (Indication IE: HI=1)
PGW  →  ePDG  Create Session Response (PAA=<same LTE IP>)
ePDG →  UE    IKE_AUTH final (CFG_REPLY: INTERNAL_IP4_ADDRESS=<PAA>)
```

### Log indicators

```
"IKE_AUTH round1: VoLTE→VoWiFi handover detected": requested_paa=<IP>
"S2b Create Session Request sent": handover=true
"IKE_AUTH final: S2b session created": handover=true, paa=<IP>
```

If the PGW returns a different address:
```
"IKE_AUTH final: handover PAA mismatch — PGW assigned different address": requested=<A>, assigned=<B>
```

---

## STR Termination-Cause Reference

| Scenario | Termination-Cause | Correct |
|----------|-------------------|---------|
| UE sends IKE DELETE | 1 (LOGOUT) | ✓ |
| DPD timeout (silent disconnect) | 1 (LOGOUT) | ✓ |
| PGW Delete — VoWiFi→VoLTE handover | 8 (USER_MOVED) | ✓ |
| PGW Delete — network-side full detach | 1 (LOGOUT) | ✓ |

---

## References

- 3GPP TS 23.402 §8.6 — Handover from Untrusted Non-3GPP to 3GPP
- 3GPP TS 24.302 §8.2.3 — UE-initiated handover attach procedure
- 3GPP TS 29.273 §6.2.2.1 — SWm STR/STA, Termination-Cause values
- 3GPP TS 29.274 §8.4 — Cause IE (value 10: Access changed from Non-3GPP to 3GPP)
- 3GPP TS 29.274 §8.12 — Indication IE (HI bit: octet 3, bit 1)
