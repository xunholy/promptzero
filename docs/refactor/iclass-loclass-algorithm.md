# iCLASS / loclass — algorithm research for `iclass_loclass_recover`

**Audience:** the wave-3 engineer claiming task #8 (pure-Go port of
loclass into `internal/iclass/`). This document is the complete
algorithm brief: protocol primer, attack derivation, reference test
vectors, and adjacent-family notes. All claims are cited to the
proxmark3 iceman fork (`RfidResearchGroup/proxmark3`) or the
published academic literature.

**Scope correction (important).** The v0.5 runbook §A.3 says *"loclass
only works against iCLASS Standard Security legacy credentials"*.
That framing is slightly inverted — loclass is the cryptanalytic
attack on **iCLASS Elite / High Security** readers, which is how it
recovers a per-site *customer* master key (Kcus). For iCLASS
**Standard Security**, the legacy master key is a single
globally-shared constant (`AE A6 84 A6 DA B2 32 78`) that Meriac
extracted once in 2010 by attacking reader firmware — no per-site
crypto attack needed. The Go port recovers the Elite Kcus *and*
reuses the same hash-0 key-diversification primitive for any
subsequent card-key derivation, so a single code path covers both
deployment modes; the Spec `iclass_loclass_recover` remains
correctly named.

---

## 1. iCLASS protocol primer

### 1.1 Card families

| Family | Year | Cipher | loclass applies? |
|---|---|---|---|
| iCLASS Legacy / Standard Security | 2002 | iCLASS block cipher (40-bit state) + single-DES diversification | N/A — global master key already public |
| iCLASS Elite / High Security | ~2005 | same cipher + custom per-site master key Kcus | **Yes — this is what loclass recovers** |
| Picopass 2KS / 16KS | 2004 | same cipher family (iCLASS derivatives) | effectively yes — same diversification scheme |
| iCLASS SE / SR | 2010+ | AES-128 + Secure Identity Object (SIO) | No — different cipher; see §4 for downgrade notes |
| SEOS | 2013+ | AES-128 + SIO container | No — explicitly out of scope |

Only the first three are in scope for v0.5. See [1], [2], [5] for the
HID-global datasheet references.

### 1.2 Card layout

An iCLASS 2K card has 32 blocks of 8 bytes [2, block table]:

| Block | Role |
|---|---|
| 0 | CSN — 8-byte card serial (read-only) |
| 1 | Card configuration word |
| 2 | EPURSE — 8-byte electronic-purse value (decrement-only counter, used as part of the authentication nonce) |
| 3 | Kd — diversified debit key (hash0 of the AA1 master key for this CSN) |
| 4 | Kc — diversified credit key (hash0 of the AA2 master key for this CSN) |
| 5 | AIA — application-issuer-area |
| 6..18 (`0x06..0x12`) | AA1 application area — protected by Kd |
| 19..31 (`0x13..0x1F`) | AA2 application area — protected by Kc |

The CSN is printed in the clear every time the card is queried —
anyone within ISO/IEC 15693 range learns it. The EPURSE rolls when
the card is used so the authentication nonce is non-repeating.

### 1.3 Authentication flow (simplified)

Authenticating to a sector requires the key that covers it (Kd for
AA1, Kc for AA2). A reader performs this exchange [2, §3], [6]:

```
Reader                                    Card
------                                    ----
  ACT_ALL / IDENT      -------->
                       <--------          CSN (block 0)
  READ_CHECK(AA)       -------->
                       <--------          CC = EPURSE[0..7] (block 2 lower half)
  CHECK(NR ‖ MAC)      -------->
                       <--------          MAC'  (card response)
```

Where:

- **NR** is the 4-byte reader nonce (random each auth).
- **MAC** is a 4-byte tag computed via the iCLASS cipher over the
  12-byte message `CC ‖ NR ‖ 00 00 00 00` using the key `k` that
  covers the target AA (Kd for AA1 reads).
- **k = hash0(DES(CSN, K))** — the per-card diversified key
  derived from the site master key `K` (Meriac notation `K_MK_AA0`
  for the AA1/debit-side master).

The reader's `K` is held in secure-element hardware inside the
reader and never leaves it under normal operation. **loclass's goal
is to recover `K` given a captured sequence of `(CSN, CC, NR,
MAC)` tuples from a live reader.**

### 1.4 The iCLASS block cipher (for MAC verification)

A 40-bit-state stream/MAC construction [4 — cipher.c self-test]:

- State = (l: 8 bits, r: 8 bits, t: 16 bits, b: 8 bits).
- Round function `successor()` mixes the 8-byte key into the state
  via a 256-entry lookup table (`opt_select_LUT`) and linear
  feedback on selected taps of `t` and `b`.
- `doMAC(cc_nr, div_key) → MAC[4]` drives 96 clocks (12-byte
  challenge + 32 output clocks), LSB-first on input, byte-reverse
  on output.

The cipher is not DES. The only DES use in iCLASS is the
*diversification* step that feeds hash0 (§2.1).

### 1.5 K_MK_AA0 — what loclass actually recovers

Every reader carries two site master keys: `K_MK_AA0` (debit, covers
AA1) and `K_MK_AA1` (credit, covers AA2). In legacy deployments
these are the two globally-published Standard-Security keys. In
Elite deployments they are replaced by per-customer 8-byte Kcus
values generated when HID provisions the reader.

The loclass attack recovers K_MK_AA0 (debit); K_MK_AA1 can be
recovered independently by rerunning the attack against an AA2
read exchange, or — more commonly — is ignored since most access
decisions sit in AA1.

---

## 2. The loclass attack

### 2.1 Published vulnerability

Three academic disclosures underpin the attack:

1. **Meriac, 27C3 (2010) — "Heart of Darkness"** [3]. Published
   the first end-to-end crypto-extraction from an iCLASS reader
   (the RW400 physical attack on firmware pins), recovered the
   legacy Standard Security master key, and published the cipher
   specification.
2. **Kim et al., IACR eprint 2011/469 — "Cryptanalysis of
   INCrypt32"** [9]. Showed that the 64-bit authentication key in
   iCLASS can be recovered with only **2 chosen-message MAC
   queries** if arbitrary-length messages are allowed. Sets the
   theoretical lower bound.
3. **Garcia, de Koning Gans, Verdult, Meriac, ESORICS 2012 —
   "Dismantling iClass and iClass Elite"** [7]. The concrete
   practical attack: given ~15 reader authentications against
   chosen CSNs, recover the Elite master key Kcus offline in
   ~seconds. This is the algorithm loclass implements.
4. **Swende (2014) — "Elite Hacking"** [8]. Optimised the 15-query
   bound down to **8 carefully selected CSNs** by choosing CSN
   values whose `hash1()` outputs cover the required 16 keytable
   positions as efficiently as possible. This is the "8 captures"
   requirement.

### 2.2 Key diversification primitives

iCLASS Elite layers an extra step before the legacy hash0
diversification:

```
K_MK_AA0 (8 bytes)  --hash2-->  keytable[128] (128 bytes)
CSN                 --hash1-->  key_sel[8]    (8 indices into keytable)
key_sel             --apply-->  t_key (8 bytes, the "Elite diversified byte-soup")
t_key               --DES-->    csn_crypt (8 bytes, single-DES(CSN, t_key))
csn_crypt           --hash0-->  div_key (8 bytes, the final per-card key used in the cipher)
```

The forward pipeline is deterministic. Crucially:

- **hash2** is *invertible* given the first 16 bytes of the
  keytable (it is a cascade of byte-rotations + DES-ECB with a
  fixed constant; the first 16 positions fully specify Kcus).
- **hash1** is a small 8-byte byte-permutation of CSN output —
  it discards no information but has a narrow image. An attacker
  can *choose* CSNs whose hash1 picks any desired subset of
  keytable indices.
- **hash0** is also invertible (modulo a "Hydra" case with
  multiple pre-images for inputs in `0x00..0x03` and `0x3c..0x3f`)
  [4 — ikeys.c `invert_hash0`].

### 2.3 Why 8 captures

The attacker needs to learn all 16 keytable positions `keytable[0..15]`
in order to invert hash2 and recover Kcus. Each captured
authentication gives the attacker (a) the CSN they presented, (b)
the MAC the reader computed. The attacker picks CSNs such that
`hash1(CSN)` produces indices < 16 — i.e. the MAC depends only on
t_key bytes that come from the first 16 positions of the keytable.

Once the MAC depends on a t_key made up only of known+unknown
bytes from `keytable[0..15]`, the attacker brute-forces the
unknown bytes (up to 3 per capture) by trying all `2^8` values for
each and checking which combination produces the observed MAC. The
iCLASS cipher at 8 bytes × 256 ≈ `2^24` trial MACs is ~seconds on
one core.

Packing: the Swende CSN-selection gives one initial CSN that
fixes 3 positions (covers `keytable[a], keytable[b], keytable[c]` with
5 "passengers" repeated or outside 0..15), then 7 follow-up CSNs
each of which adds exactly 2 new positions. Total `3 + 7×2 = 17`
constraints on 16 unknowns (one overlap for consistency) with 8
captures [8, §attack].

Runtime on iceman's reference C implementation: **~10 s to a few
minutes on a modern desktop** [1, loclass_notes.md]. Candidate
space per brute-force step is ≤ 2^24 (3 unknown bytes × 256
candidates, cross-checked against one MAC).

### 2.4 Algorithm pseudocode (the Go engineer's reference)

```text
input:  captures = [(CSN_i, CC_i, NR_i, MAC_i) for i in 0..N-1]   # N ≥ 8
output: Kcus  (8 bytes)

# --- offline recovery ---
keytable = [UNKNOWN] * 16
for (CSN, CC, NR, MAC) in captures:
    idx = hash1(CSN)                     # 8 indices, some may be ≥ 16 — discard those
    known_pos   = [i for i in idx if keytable[i] != UNKNOWN]
    unknown_pos = [i for i in idx if keytable[i] == UNKNOWN and i < 16]
    if len(unknown_pos) > 3:
        skip                             # pick a better capture, should not happen
                                          # if CSNs were selected optimally
    for guess in product(range(256), repeat=len(unknown_pos)):
        t_key = assemble_t_key(idx, keytable, unknown_pos, guess)
        csn_crypt = DES_ECB(t_key, CSN)                     # single-DES, 8-byte key
        div_key  = hash0(csn_crypt)
        if iclass_mac(div_key, CC ‖ NR ‖ 0000) == MAC:
            for (pos, val) in zip(unknown_pos, guess):
                keytable[pos] = val
            break
    else:
        raise NoCandidate                 # capture inconsistent with the other captures

assert all(b != UNKNOWN for b in keytable)    # all 16 positions filled

# --- invert hash2 ---
Kcus = invert_hash2(keytable[0..15])           # fixed-constant DES-ECB cascade
return Kcus
```

Supporting primitives — all ~30-60 LOC in Go:

| Name | Purpose |
|---|---|
| `hash0(x uint64) [8]byte` | 64→64 bit permutation + modulo map, documented in [4 — ikeys.c] and [7, §4] |
| `hash1(csn [8]byte) [8]uint8` | byte-permutation producing 8 keytable indices |
| `hash2(Kcus [8]byte) [128]byte` | Elite keytable derivation; iterates DES with a fixed constant |
| `invert_hash2(kt[0..15] [16]byte) [8]byte` | reverses hash2 using only the first 16 bytes [8] |
| `des_ecb(key, plain [8]byte) [8]byte` | standard single-DES; `crypto/des` in Go stdlib |
| `iclass_mac(div_key [8]byte, cc_nr [12]byte) [4]byte` | the 40-bit-state cipher from §1.4 |

### 2.5 Integration notes for the engineer

- Put the cipher in `internal/iclass/cipher.go`. Keep it isolated
  from `internal/crypto1/` — entirely different primitive.
- `hash0`, `hash1`, `hash2`, `invert_hash2` live in
  `internal/iclass/keys.go`.
- Capture file parsing — the proxmark3 on-disk format is:
  `<8 CSN><8 CC><4 NR><4 MAC>` repeated, `N×24` bytes total [1,
  loclass_notes.md — "Binary file format"]. N=8 for a field
  capture; N=128 for the iceman reference fixture. Put this in
  `internal/iclass/capture.go`.
- The handler plumbs through a `context.Context` so the
  `timeout_ms` Spec argument enforces a deadline — check
  `ctx.Done()` in the outer `for capture` loop and the inner
  `for guess` loop.
- No hardware contact. The Flipper is not involved.

---

## 3. Test vector

**Resolution: case (a) — published component-level vectors found;
case (b) synthetic fixture still recommended for end-to-end.**

The Meriac 27C3 paper [3] does *not* include a self-check
`(8 captures → K_MK)` tuple. The ESORICS 2012 paper [7] gives the
algorithm but also does not pin a worked example.

**However**, the proxmark3 iceman tree [1, 4] publishes
component-level test vectors that the Go port uses as unit-test
oracles, plus a full end-to-end fixture as a pair of binary files.
Every vector below is public, algorithm-derived, and safe to embed
in `internal/iclass/testdata/` under clean-reimpl provenance.

### 3.1 Component-level vectors (embed verbatim — unit tests)

All hex values sourced from iceman `client/src/loclass/ikeys.c`
self-tests [4] and `client/src/loclass/cipher.c` `testMAC` [10].

#### 3.1.1 `hash0` — 64→64 bit key derivation

```
crypted_csn : 01 02 03 04 05 06 07 08
expected    : 0B DD 65 12 07 3C 46 0A
```

#### 3.1.2 `permute` — 8-byte byte-bit permutation

```
input  : 6C 8D 44 F9 2A 2D 01 BF
output : 8A 0D B9 88 BB A7 90 EA
```

#### 3.1.3 `hash1` — CSN → keytable-index selector

```
CSN      : 01 02 03 04 F7 FF 12 E0
indices  : 7E 72 2F 40 2D 02 51 42
```

(Seven of these eight indices are ≥ 16 — this CSN is a poor
choice for attack but is a good unit-test input because every
hash1 output bit gets exercised.)

#### 3.1.4 `hash2` — Elite keytable derivation

Kcus (custom master key):

```
5B 7C 62 C4 91 C1 1B 39
```

First 16 bytes of resulting 128-byte keytable:

```
F1 35 59 A1 0D 5A 26 7F 18 60 0B 96 8A C0 25 C1
```

Spot-check values at other positions (validates the rotation
cascade is not truncated):

```
keytable[0x30] = A3
keytable[0x6F] = 95
```

#### 3.1.5 `iclass_mac` — 40-bit-state cipher

```
CC ‖ NR ‖ 0000 : FE FF FF FF FF FF FF FF 00 00 00 00
div_key        : E0 33 CA 41 9A EE 43 F9
expected MAC   : 1D 49 C9 DA
```

#### 3.1.6 Standard Security legacy master key (for AA1 hash0 chain)

```
K_MK_AA0 (legacy, globally shared) : AE A6 84 A6 DA B2 32 78
```

Source: [3, §6 conclusion] / [11, `iClass_Key_Table[0]`]. Every
Standard-Security-keyed card at every site uses this. Embed it
as a named constant in `internal/iclass/keys.go` — it is
*ubiquitous public information* about the protocol and carries
no license concern.

### 3.2 End-to-end attack fixture (case a — public, available)

The iceman tree ships two binary files used by its
`hf iclass loclass --test` self-check [1, loclass_notes.md]:

| File | Contents | Size |
|---|---|---|
| `iclass_dump.bin` | 128 tuples of `CSN ‖ CC ‖ NR ‖ MAC` — output of `hf iclass sim -t 2` against a simulated Elite reader using a known Kcus | 3072 bytes |
| `iclass_key.bin` | The known Kcus that the attack should recover | 8 bytes |

These live in the iceman repository at
`client/resources/` (historically — path has moved between iceman
releases; engineer greps the tree for `iclass_dump.bin` when
porting). Both files are in the public iceman repository under
GPLv2. Since they are **algorithm-derived outputs** from a known
key and a published algorithm (not authored creative content),
the Go port can regenerate them from scratch via §3.3 without
copying the iceman files, avoiding the GPL provenance concern.

### 3.3 Synthetic fixture generator (case b — the recommended path)

Rather than copy the iceman `.bin` files, the engineer builds a
small **fixture generator** in `internal/iclass/testdata/gen/`:

```
cmd/iclass-test-gen/main.go   (or go:generate in internal/iclass/)

inputs:
  -kcus <hex8>     the Kcus to simulate (default: the §3.1.4 vector)
  -n    <int>      number of captures to emit (default: 8, the Swende bound)
  -out  <path>     output file in proxmark3 loclass format

algorithm:
  1. Pick N CSNs using the Swende optimal-selection rule
     (initial CSN covers 3 indices < 16; each subsequent CSN
     adds 2 new indices < 16).
  2. For each CSN:
     - derive div_key := hash0(DES(CSN, t_key_for(CSN, Kcus)))
     - emit a random NR (4 bytes); fabricate CC := EPURSE_const
     - compute MAC := iclass_mac(div_key, CC ‖ NR ‖ 0000)
     - write (CSN ‖ CC ‖ NR ‖ MAC) to the output file
  3. Write the Kcus to a sibling `.key` file for the test harness.
```

`TestLoclassEndToEnd` in `internal/iclass/loclass_test.go` then:

1. Runs the generator with a hard-coded Kcus.
2. Invokes `iclass.LoclassRecover(capturesFile)`.
3. Asserts the returned key equals the input Kcus.

This satisfies both:
- **Determinism** — fixture is generated at `go test` time; no
  binary blobs checked in.
- **Provenance cleanliness** — every byte produced by
  PromptZero's own code from a known seed, against an algorithm
  spec we derived from the paper.

### 3.4 Test-vector availability statement

**Case (a) is FOUND for every sub-primitive** (hash0, hash1,
hash2, permute, iclass_mac). These go straight into unit tests
as hex literals.

**For the full 8-capture → K_MK end-to-end vector, case (a) exists
in iceman but carries GPL provenance — the port uses case (b), a
self-contained synthetic fixture generator, instead. The engineer
can optionally run the generator with the iceman Kcus (§3.1.4) to
cross-check that the recovered key matches the same byte pattern
iceman recovers from `iclass_dump.bin`.**

---

## 4. Wider key-recovery family (informational — NOT v0.5 scope)

The engineer will be asked about these during v0.5.x and v0.6
planning; a brief note each:

### 4.1 iCLASS Elite downgrade attack

Most deployed iCLASS SE / SR / SEOS readers leave legacy-iCLASS
compatibility *enabled* by default [12, 13]. The downgrade
workflow:

1. Read the SIO (Secure Identity Object) + PACS payload from an
   SE / SEOS card via a privileged reader (OMNIKEY, NARD/SAM, or
   a weaponised DIY reader).
2. Re-encode the extracted PACS bytes onto a T5577 (125 kHz
   legacy) or a blank iCLASS legacy card.
3. The target reader, still configured to accept legacy, admits
   the downgraded clone.

This is **a configuration attack, not a crypto attack** — no key
recovery, no cipher break. The mitigation is vendor guidance to
disable legacy reads on SE readers [13]. PromptZero does not need
a Spec for this; the existing `loader_picopass` + `loader_seader`
FAPs cover the read side, and a T5577 writer already exists.

### 4.2 Picopass key derivation

Picopass 2KS / 16KS cards use the same 40-bit-state iCLASS cipher
+ the same hash0/hash2 diversification. A Picopass-exclusive path
is not required: if `internal/iclass/` implements hash0 + DES +
the cipher, Picopass-tag auth sits on the same code path. The
only delta is the ATQB/ATS identification step at the transport
layer, which is already handled by the Flipper PicoPass FAP.

### 4.3 iCLASS SE / SR (AES-128 + SIO)

Uses AES-128-CMAC authentication and a per-reader AES master
generated in-factory. No known cryptanalytic attack. The
downgrade attack (§4.1) sidesteps it entirely. Out of scope for
v0.5 and v0.6 unless a new vulnerability surfaces.

### 4.4 SEOS

Explicitly out of scope. SEOS is a full container format over
AES-128; SIO downgrade (§4.1) is the operator workflow. No
cipher-break algorithm to port.

---

## 5. Citations

1. **proxmark3 iceman — loclass notes.**
   `RfidResearchGroup/proxmark3` —
   `doc/loclass_notes.md`.
   <https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/loclass_notes.md>
   (Source for: attack two-phase structure; `iclass_dump.bin` /
   `iclass_key.bin` test fixture; binary file format
   `8 CSN ‖ 8 CC ‖ 4 NR ‖ 4 MAC`; `hf iclass loclass --test`
   invocation.)

2. **HID Global — iCLASS HF Migration Reader Key Diversification.**
   Product-technical white paper (reposted by proxmark community).
   <https://www.yumpu.com/en/document/view/35538360/iclass-hf-migration-reader-key-diversification-hid-global>
   (Source for: AA1/AA2 block layout; Kd vs Kc roles; block-2
   EPURSE semantics.)

3. **Meriac — "Heart of Darkness: exploring the uncharted
   backwaters of HID iCLASS™ security".** 27C3, Berlin, December
   2010.
   <https://fahrplan.events.ccc.de/congress/2010/Fahrplan/attachments/1770_HID-iCLASS-security.pdf>
   (Source for: Standard Security master key disclosure; cipher
   specification; RW400 firmware extraction; the fact that no
   worked `(captures → K_MK)` self-check vector is published.)

4. **iceman — `client/src/loclass/ikeys.c`.** Key diversification,
   hash0 / hash1 / hash2 / permute, and `doKeyTests()` +
   `testKeyDiversificationWithMasterkeyTestcases()` self-checks.
   <https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/loclass/ikeys.c>
   (Source for: every hex vector in §3.1 except §3.1.5 and
   §3.1.6; 57 per-CSN diversification test cases; 9 known-input
   test cases.)

5. **nfc-tools/nfc-iclass.** libnfc-based iCLASS / Picopass tool.
   <https://github.com/nfc-tools/nfc-iclass>
   (Cross-reference for: Picopass register layout equivalence;
   Kd/Kc interpretation.)

6. **proxmark3 — `armsrc/iclass.c`.** Reader-side authentication
   flow (ACT_ALL, IDENT, READ_CHECK, CHECK).
   <https://github.com/Proxmark/proxmark3/blob/master/armsrc/iclass.c>
   (Source for: §1.3 exchange diagram.)

7. **Garcia, de Koning Gans, Verdult, Meriac — "Dismantling
   iClass and iClass Elite".** ESORICS 2012, LNCS vol. 7459.
   <https://link.springer.com/chapter/10.1007/978-3-642-33167-1_40>
   Author copy:
   <https://www.cs.ru.nl/~rverdult/Dismantling_iClass_and_iClass_Elite-ESORICS_2012.pdf>
   (Source for: formal algorithm; `k = hash0(DES(CSN, K))`
   diversification formula; ~15-authentication Elite bound;
   standard-security 2-MAC attack.)

8. **Swende — "Elite iClass Hacking".** swende.se blog, 2014.
   <https://swende.se/blog/Elite-Hacking.html>
   (Source for: 8-capture optimisation; "three indices < 16 from
   initial CSN + two new indices per follow-up" selection rule;
   107.098549-second full-crack runtime; `holiman/loclass`
   reference Go-adjacent implementation.)
   Repository: <https://github.com/holiman/loclass>

9. **Kim, Lee, Lee — "Cryptanalysis of INCrypt32 in HID's
   iCLASS systems".** IACR eprint 2011/469.
   <https://eprint.iacr.org/2011/469.pdf>
   (Source for: theoretical 2-MAC-query lower bound on the
   Standard Security path.)

10. **iceman — `client/src/loclass/cipher.c`.** 40-bit-state
    cipher, `successor`, `doMAC`, `testMAC`.
    <https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/loclass/cipher.c>
    (Source for: §1.4 cipher shape; §3.1.5 MAC self-check
    vector `CC ‖ NR` → `1D 49 C9 DA`.)

11. **proxmark3 — `client/cmdhficlass.c` `iClass_Key_Table`.**
    <https://github.com/Proxmark/proxmark3/blob/master/client/cmdhficlass.c>
    (Source for: the legacy master key
    `AE A6 84 A6 DA B2 32 78` and the 8-slot default key table.)

12. **IPVM — "HID Standard Profile Makes 13.56 MHz SE / Seos As
    Vulnerable As Cracked 125 kHz For Downgrade Attack".**
    <https://ipvm.com/reports/seos-downgrade>
    (Source for: §4.1 — downgrade attack is configuration-based,
    not cryptanalytic.)

13. **HID Global — "Safeguarding Against Legacy Downgrade
    Attacks".** Vendor guidance PDF.
    <https://doc.origo.hidglobal.com/common/rm/Safeguarding_Against_Legacy_Technology.pdf>
    (Source for: vendor mitigation — disable legacy reads on SE
    readers.)

14. **Chung — "Reverse Engineering HID iClass Master Keys".**
    blog.kchung.co, 2014.
    <https://blog.kchung.co/reverse-engineering-hid-iclass-master-keys/>
    (Source for: independent confirmation of the
    Standard-Security master-key value extracted via the Chinese
    cloning tool — not used verbatim, but cross-checks §3.1.6.)

---

*End of research brief. File size target: 15-25 KB;
self-check with `wc -c docs/refactor/iclass-loclass-algorithm.md`.*
