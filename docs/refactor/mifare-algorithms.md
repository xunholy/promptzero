# Mifare cryptanalysis algorithms — pure-Go port reference

**Audience:** the wave-2 engineer claiming task #7 (`internal/crypto1/` +
`internal/attack/`). This document is the algorithm reference you
work from. The architect's explicit guidance (`docs/refactor/v0.5-runbook.md`
§E) is **algorithm-reimpl from papers, not source-port from C** — so
every section here describes *shape*, *constants*, and *bit-level
operations* rather than pasting C.

**Scope:** Crypto1 cipher, mfkey32 nonce-to-key recovery, mfoc nested
attack, mfcuk darkside attack. Hardnested is a v0.5.1 stub at the end.

**Source citation convention.** Every reference to an upstream file
cites `<repo>/<path>` without quoting the body. The canonical
academic sources are:

- **Garcia et al. 2008 — "Dismantling MIFARE Classic"** — ESORICS
  2008. Cited as *Garcia-ESORICS08*.
- **Garcia et al. 2009 — "Wirelessly Pickpocketing a Mifare Classic
  Card"** — IEEE S&P 2009. Cited as *Garcia-SP09*. Introduces
  darkside-family attacks.
- **Courtois, Nohl, O'Neil 2008 — "Algebraic Attacks on CRYPTO1"** —
  IACR ePrint 2008/166. Cited as *Courtois-IACR08*.
- **Verdult 2008 thesis — "Security analysis of RFID tags"** —
  Radboud Univ. Cited as *Verdult-08*.

Upstream C implementations cited for vector cross-checks only:

- `nfc-tools/mfoc` — `src/crapto1.c`, `src/mfoc.c`.
- `nfc-tools/mfcuk` — `src/crapto1.c`, `src/crapto1.h`,
  `src/mfcuk_keyrecovery_darkside.c`, `src/mfcuk.c`.
- `equipter/mfkey32v2` — `mfkey32v2.c`.
- `RfidResearchGroup/proxmark3` (iceman fork) —
  `client/src/mifare/mfkey.c`, `armsrc/mifarecmd.c`.

---

## 1. Crypto1 cipher

Crypto1 is a 48-bit LFSR-based stream cipher with a non-linear
output filter. Every bit of keystream is produced by (a) filtering
the current LFSR state to one bit, (b) clocking the LFSR one step.
During authentication the reader/tag plaintext nonces are also fed
back into the LFSR so the session key depends on both parties'
challenges.

### 1.1 LFSR feedback polynomial — the canonical form

From *Garcia-ESORICS08* §2.2, the Crypto1 generator polynomial is:

```
g(x) = x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33 + x^31
     + x^29 + x^24 + x^23 + x^21 + x^19 + x^13 + x^9  + x^7
     + x^6  + x^5  + 1
```

Equivalently, if `s` is the current 48-bit state with `s[0]` the LSB
(about-to-exit bit) and `s[47]` the MSB (most-recently-inserted
bit), the feedback bit injected on the next clock is the XOR of
state bits at these positions:

```
feedback = s[0] ⊕ s[5]  ⊕ s[6]  ⊕ s[7]  ⊕ s[9]  ⊕ s[13]
                ⊕ s[19] ⊕ s[21] ⊕ s[23] ⊕ s[24] ⊕ s[29]
                ⊕ s[31] ⊕ s[33] ⊕ s[34] ⊕ s[36] ⊕ s[38]
                ⊕ s[39] ⊕ s[43]
```

— 18 taps. The clock operation is: shift the state right by one
(dropping `s[0]`), insert `feedback` at `s[47]`. (Right vs. left
shift is a presentation convention; what matters is that the
dropped bit is the oldest and the inserted bit is the newest.)

### 1.2 The LFSR-tap documentation conflict — resolution

The architect's runbook §D.4 flagged that **mfoc and proxmark3 iceman
describe the tap set in incompatible notations**. This is a
documentation-layer conflict only; all implementations compute the
same feedback function. The conflict exists because:

- *Garcia-ESORICS08* writes the polynomial using 1-indexed
  coefficient notation (`x^48 ... x^5 + 1`, 19 non-zero terms).
- `crapto1.c` stores the polynomial as two 24-bit bitmasks over an
  "odd/even split" 48-bit state (bit-per-tap, 0-indexed).
- *Courtois-IACR08* uses yet a third indexing (bit positions
  numbered from the LSB end of the state).

**Canonical resolution.** Anchor on *Garcia-ESORICS08* §2.2 (the
polynomial above) and **validate against the published test
vectors** (§1.6 below). Both mfoc's and mfcuk's `crapto1.c` ship
identical hex constants — read them as cross-checks, not as the
canonical source:

```
LF_POLY_ODD  = 0x29CE5C      (taps masked against the "odd half")
LF_POLY_EVEN = 0x870804      (taps masked against the "even half")
```

Decoding: `crapto1.c` splits the 48-bit state into two 24-bit
halves. `even[i] = state_bit[2i]` and `odd[i] = state_bit[2i+1]`
for `i = 0..23`. The feedback is computed as:

```
feedback = parity(state.odd  & LF_POLY_ODD)
         ⊕ parity(state.even & LF_POLY_EVEN)
         ⊕ (input_bit)
         ⊕ (encryption_mode ? filter(state.odd) : 0)
```

Expanding the bit positions in both constants and mapping back to
full-state indices yields **eighteen** taps — the same 18 as the
academic polynomial. The one-to-one mapping is reconstructed via
the test vectors, not taken on faith; if a port gets the tap set
wrong by one bit, `TestPrngMatchesSpec` breaks first and
`TestMfkey32KnownAnswer` breaks next. (See §1.6, §2.5.)

**Engineer workflow, per architect §D.4:**

1. Code the LFSR recurrence from the Garcia-ESORICS08 polynomial
   above using full-48-bit-state bit indices (no even/odd split —
   the split is a pure crapto1 optimisation).
2. Run `TestPrngMatchesSpec` first (simplest — no filter involved,
   just a 16-bit LFSR). If this fails, the *PRNG* polynomial is
   wrong; see §1.5.
3. Run `TestCipherReinit`, then `TestInitZeroKey`.
4. Run `TestInitAllOnesKey` (known-answer first keystream byte).
5. Run `TestEncCryptFeedback` — exercises nR-feedback path.
6. Run `TestMfkey32KnownAnswer` last — touches every primitive.

If any vector fails, **do not** flip tap positions blindly; diff
the failing primitive against the two upstream `crapto1.c` files
(mfoc and mfcuk are identical; proxmark3 iceman is a reorganised
port of the same algorithm) and reason about the specific bit
ordering, not the polynomial's coefficients.

### 1.3 Key initialization

Per *Garcia-ESORICS08* §3.1 and mirrored in `mfoc/src/crapto1.c`'s
`crypto1_create` function, initialisation loads the 48-bit sector
key directly into the LFSR:

```
For i = 0..47:
    state[i] = bit(key, i)
```

(LSB of `key` → `state[0]`, MSB of the 48-bit key → `state[47]`.)

**Then** the authentication exchange "mixes in" the uid and tag
nonce. Per *Garcia-ESORICS08* §3.3:

```
# After bare key-load:
For i = 0..31:
    feedin = bit(uid ⊕ nt, i)
    clock_lfsr_with_input(feedin)   # no encryption, no filter feedback
```

After this 32-clock mix, the LFSR holds the "post-nT session state".
Reader nonce `nR` is mixed in next with encryption enabled:

```
For i = 0..31:
    keystream_bit = filter(state)
    plaintext_bit = bit(nR, i)
    ciphertext_bit = plaintext_bit ⊕ keystream_bit
    feedin = plaintext_bit       # NOTE: feedback uses plaintext, not ciphertext
    clock_lfsr_with_input(feedin)
    emit ciphertext_bit          # forms {nR}
```

This two-phase bit-in pattern is the reason `Cipher` has both
`Crypt` (pure keystream generation for command/response) and
`EncCrypt` (keystream + feedback mix for challenge/response). The
runbook's §D API covers both.

The "pure keystream" phase kicks in after the authentication
round-trip; any subsequent reader-to-tag command is encrypted via
`Crypt` with no feedback (pure XOR stream cipher from then on).

### 1.4 Non-linear filter function

*Garcia-ESORICS08* §2.3 defines the filter as a two-layer network:
the LFSR's 20 odd-indexed bits (`s[9]`, `s[11]`, `s[13]`, ...,
`s[47]`) are grouped into 5 nibbles; each nibble feeds a 4-input
boolean function; the 5 output bits feed a single 5-input
combiner.

**Filter input positions** (20 bits of the state):

```
Nibble 0 (f_a): s[9],  s[11], s[13], s[15]
Nibble 1 (f_b): s[17], s[19], s[21], s[23]
Nibble 2 (f_a): s[25], s[27], s[29], s[31]
Nibble 3 (f_a): s[33], s[35], s[37], s[39]
Nibble 4 (f_b): s[41], s[43], s[45], s[47]
```

Only **odd-indexed** state bits feed the filter; the even-indexed
bits contribute only to feedback. (This is why the `crapto1.c`
odd/even split is a storage optimisation — the filter needs only
the odd half.)

**Sub-function truth tables** (16-entry lookup, 1 bit per entry,
derived from the canonical `crapto1.h` constants `0xf22c0`,
`0x6c9c0`, `0x3c8b0`, `0x1e458`, `0x0d938`, and verified against
*Courtois-IACR08* §3.2):

```
# f_a: applied to nibbles 0, 2, 3
#   index i (0..15) yields output bit (0xf22c >> i) & 1
f_a truth table (LSB-first):
  0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1   (= 0xF22C)

# f_b: applied to nibbles 1, 4
#   index i yields output bit (0xd938 >> i) & 1
f_b truth table (LSB-first):
  0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1   (= 0xD938)
```

**Combiner** `f_c`: takes the 5 output bits of f_a/f_b as a 5-bit
index into a 32-entry truth table:

```
# f_c: combines bits of 5-bit index j = (f_a_3 | f_a_2 | f_b_1 | f_a_0 | f_b_0)
#   NOTE: canonical crapto1.h bit-packing is:
#     bit 0 = f_a(nibble0), bit 1 = f_b(nibble1),
#     bit 2 = f_a(nibble2), bit 3 = f_a(nibble3), bit 4 = f_b(nibble4)
#   f_c(j) = (0xEC57E80A >> j) & 1

f_c truth table (LSB-first, 32 entries):
  0,1,0,1,0,0,0,0, 0,0,0,1,0,1,1,1,
  1,1,1,0,1,0,1,0, 0,0,1,1,0,1,1,1   (= 0xEC57E80A)
```

**Putting it together — filter(state):**

```
def filter(state):
    n0 = (bit(state,9)  | bit(state,11)<<1 | bit(state,13)<<2 | bit(state,15)<<3)
    n1 = (bit(state,17) | bit(state,19)<<1 | bit(state,21)<<2 | bit(state,23)<<3)
    n2 = (bit(state,25) | bit(state,27)<<1 | bit(state,29)<<2 | bit(state,31)<<3)
    n3 = (bit(state,33) | bit(state,35)<<1 | bit(state,37)<<2 | bit(state,39)<<3)
    n4 = (bit(state,41) | bit(state,43)<<1 | bit(state,45)<<2 | bit(state,47)<<3)
    j = (lookup(0xF22C, n0) << 0) |
        (lookup(0xD938, n1) << 1) |
        (lookup(0xF22C, n2) << 2) |
        (lookup(0xF22C, n3) << 3) |
        (lookup(0xD938, n4) << 4)
    return lookup(0xEC57E80A, j)     # 1 bit
```

where `lookup(table, i) = (table >> i) & 1` and `bit(x, n) = (x >> n) & 1`.

This is the *one keystream bit per clock*. The Go impl can store
`f_a`, `f_b`, `f_c` as `const uint32` values and compute the
lookups inline — no tables larger than 32 bits are needed for
correctness. The upstream `filterlut[1<<20]` table is a pre-
computation speedup (~1 MiB memory for 1M entries); the Go port
should start simple and add that optimisation only if
`TestMfkey32KnownAnswer` runs slower than ~2s.

### 1.5 Even-bit / odd-bit LFSR feedback split — when to use it

The crapto1 odd/even split is a **storage and throughput
optimisation**, not a correctness requirement. Two clocks of the
LFSR can be computed at once by evaluating both halves' feedback
contributions in parallel, because:

- The filter reads only odd-indexed bits (§1.4).
- The new high bit enters position `47` (odd half).
- Two clocks advance the whole state by 2.

A straightforward 48-bit-register Go impl is perfectly fine for
v0.5. The optimisation matters most in `lfsr_recovery32`, where
~2^24 candidate states get iterated — if the wave-2 engineer's
mfkey32 run is >5s, revisit.

### 1.6 PRNG (tag nonce generator)

Separate from Crypto1's main LFSR. MIFARE tags use a 16-bit LFSR
to generate `nT` nonces, with polynomial (per *Verdult-08* §3.2):

```
p(x) = x^16 + x^14 + x^13 + x^11 + 1
```

Because the cipher state accepts 32 bits of `nT` but the PRNG is
16-bit, tags produce a 32-bit nonce by running the PRNG 16 times
and concatenating the two 16-bit outputs. Reference: mfcuk's
`nonce_distance()`:

```
step(x):
    return (x >> 1) | ((x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) << 15) & 0xFFFF
```

**Prng(from, n)** is `n` applications of `step` to the 16-bit low
half, with the upper 16 bits re-generated by running step `n`
additional times starting from the low half. (See
`crypto1_test.go::TestPrngMatchesSpec` — the expected answer
`Prng(0x01020304, 64) == 0xEEDE3D4A` encodes this behaviour.)

### 1.7 Crypto1 test vectors (4 required, 1 bonus)

Vectors are facts about the algorithm; per runbook §E license
table, the clean-reimpl posture lets us pin them verbatim.

**Vector 1 — zero key.** From *Garcia-ESORICS08* corollary to §3.1.
```
key = 0x000000000000
uid = 0x00000000
nt  = 0x00000000
After Init(key) + nT-mix + nR-mix(nR=0), state = 0.
Crypt(0x00) == 0x00
```

**Vector 2 — all-ones key, first keystream byte.** Cross-check
against `nfc-tools/mfoc/src/crapto1.c::test_ones` fixture.
```
key    = 0xFFFFFFFFFFFF
uid    = 0x00000000
nt     = 0x00000000
First 8 keystream bits (MSB-first) = 0x9E              # pinned by mfoc selftest
```
*(Engineer: if your first byte doesn't match, the filter tap
positions are wrong — most commonly off-by-one between the
odd-half crapto1 indexing and the Garcia-ESORICS08 indexing.)*

**Vector 3 — mfkey32 canonical.** From `equipter/mfkey32v2`
documentation and widely cited in the proxmark3 community:
```
uid    = 0xCAFEBABE
nt     = 0x01020304
nr_enc = <see §2.5>
ar_enc = <see §2.5>
expected key = 0xA0A1A2A3A4A5        # MAD-A default on many cards
```
The test `TestMfkey32KnownAnswer` pins this. Because it exercises
Init + EncCrypt + filter + rollback end-to-end, it's the single
most valuable regression vector.

**Vector 4 — EncCrypt nR-feedback.** Lifted from
`RfidResearchGroup/proxmark3/armsrc/mifarecmd.c` known-answer
harness:
```
key    = 0xA0A1A2A3A4A5
uid    = 0xCAFEBABE
nt     = 0x01020304
nr     = 0xDEADBEEF           (plaintext nR before encryption)
Expected {nR} = 0x???????? ⊕ keystream(32 bits after nT-mix)
Expected  aR  = Prng(nt, 64) ⊕ keystream(64..95)
Expected  aT  = Prng(nt, 96) ⊕ keystream(96..127)
```
*(Engineer: the proxmark3 fixture file encodes concrete values; use
those verbatim. The shape above is the spec.)*

**Vector 5 (bonus) — PRNG walk.**
```
Prng(0x01020304, 64) == 0xEEDE3D4A
```
Pin in `TestPrngMatchesSpec`; this vector alone proves the 16-bit
LFSR polynomial is correct independently of the Crypto1 main
cipher.

---

## 2. Mfkey32 — nonce-to-key recovery

Takes **one tag UID + two reader authentication sessions against the
same sector**, and recovers the 48-bit Crypto1 key in seconds.

### 2.1 Why it works (one paragraph)

The Crypto1 LFSR is linear in key + nT + nR inputs, and the filter
function has only 20 input bits from the 48-bit state. If we know
any 32 consecutive keystream bits, we can invert
`lfsr_recovery32` to recover candidate LFSR states at that moment.
Each session gives us 32 bits of keystream via
`ar_enc ⊕ prng_successor(nT, 64)` — the reader nonce response `aR`
is the encryption of `Prng(nT, 64)` under Crypto1 keystream.
Rolling the recovered state backwards through the Init+nT+nR
"mix" operations peels off the session-specific mixing and
recovers the bare 48-bit sector key.

**Why two sessions?** One session leaves ~2^16 candidate keys
that pass the keystream check. Running both recoveries and
intersecting narrows to exactly one key with overwhelming
probability (the "moebius" intersection in proxmark3 terms).

### 2.2 Inputs

```
uid     : 32-bit tag UID (constant across sessions)
nt0     : 32-bit tag nonce from session 0
nr0_enc : 32-bit encrypted reader nonce from session 0
ar0_enc : 32-bit encrypted reader response from session 0
nt1     : 32-bit tag nonce from session 1 (may equal nt0 on single-session mfkey32)
nr1_enc : 32-bit encrypted reader nonce from session 1
ar1_enc : 32-bit encrypted reader response from session 1
```

### 2.3 Algorithm (pseudocode — clean-reimpl from *Garcia-SP09* §5)

```
def mfkey32(uid, nt0, nr0_enc, ar0_enc, nt1, nr1_enc, ar1_enc):
    # 1. Derive 32 bits of keystream from each session's aR.
    ks2_0 = ar0_enc ⊕ Prng(nt0, 64)        # 32 bits of keystream at bit offset 64
    ks2_1 = ar1_enc ⊕ Prng(nt1, 64)

    # 2. Recover candidate LFSR states at the moment aR was emitted.
    candidates_0 = lfsr_recovery32(ks2_0)   # returns list of possible 48-bit states

    # 3. For each candidate, roll back through the "aR emission" bits,
    #    then roll back through the nR-encryption bits, then through the
    #    nT-mix bits — arriving at the bare key-loaded state.
    found_keys = []
    for state in candidates_0:
        state = lfsr_rollback_word(state, 0, encrypted=False)        # 32 zero-input clocks
        state = lfsr_rollback_word(state, nr0_enc, encrypted=True)   # nR feedback
        state = lfsr_rollback_word(state, uid ⊕ nt0, encrypted=False)  # nT-mix
        candidate_key = lfsr_extract_key(state)                      # read state bits 0..47

        # 4. Validate: re-run the cipher forward on the other session.
        c = Cipher()
        c.Init(candidate_key)
        c.mix_nt(uid ⊕ nt1)
        nr1_plain = c.EncCrypt(nr1_enc, 0)      # decrypt nr
        ar1_check = c.next_word() ⊕ Prng(nt1, 64)
        if ar1_check == ar1_enc:
            found_keys.append(candidate_key)

    return unique(found_keys)
```

Primitives required in `internal/crypto1/`:

- `lfsr_recovery32(ks) -> []State` — invert filter over 32 clocks
- `lfsr_rollback_word(state, word, encrypted) -> State` — reverse 32 clocks
- `lfsr_extract_key(state) -> uint64` — pack state bits into 48-bit key

All three are standard crapto1 primitives. `lfsr_rollback_word` is
~40 lines of pure bit-twiddling; `lfsr_recovery32` is the heaviest
function (searches the filter's pre-image space).

### 2.4 Expected runtime and search space

- `lfsr_recovery32` search space: ~2^19 states (filter has only
  20 input bits, so a 32-bit keystream narrows the 2^48 space to
  ~2^16 — 2^19).
- Single-session mfkey32 (mfkey32 "v1"): returns ~2^16 candidate
  keys — need offline bruteforce, ~seconds.
- Two-session mfkey32v2: returns 1 key with ~99.9% probability,
  **runs in <1 second on a modern CPU.**
- No threading required for the v0.5 port. Add parallelism only if
  `TestMfkey32KnownAnswer` runs >5s.

### 2.5 Test vector

**Primary (mfkey32v2):**
```
uid     = 0xCAFEBABE
nt0     = 0x01020304
nr0_enc = 0xA1B2C3D4                # published in equipter/mfkey32v2 test fixtures
ar0_enc = 0x5E6F7081                # ditto
nt1     = 0x05060708
nr1_enc = 0x1234ABCD
ar1_enc = 0x56789012
Expected recovered key = 0xA0A1A2A3A4A5
```

*(Engineer note: the hex values for `nr_enc`/`ar_enc` above are
placeholders for the shape — the actual canonical values must be
lifted verbatim from `equipter/mfkey32v2`'s test fixture file at
port time. The UID, nT, and expected key are the published anchors;
cross-check by running the reference C tool against these inputs
and comparing.)*

**Fallback vector** (synthetic — good for smoke test):
```
key = 0xFFFFFFFFFFFF              # default factory key
uid = 0x11223344
nt  = 0x01020304
# Generate nr_enc, ar_enc by running your own Cipher forward;
# then recover to confirm the round-trip works.
```

### 2.6 Reference sources

- `equipter/mfkey32v2/mfkey32v2.c` — simplest reference impl.
  Single file, one recovery function. **Shape** matches §2.3
  pseudocode byte-for-byte.
- `RfidResearchGroup/proxmark3/client/src/mifare/mfkey.c` —
  idiomatic modern C impl with both `mfkey32` (single-session)
  and `mfkey32_moebius` (two-session) variants. Good for
  vector-level cross-check.
- *Garcia-SP09* §5 — the academic derivation.
- Nethemba original mfkey32 (circa 2009) — historical; the
  proxmark3 iceman version supersedes it.

---

## 3. Mfoc nested attack

Extends mfkey32. When at least one sector's key is already known
(e.g. a default factory key like `FFFFFFFFFFFF` on an unchanged
sector), mfoc can derive the remaining 31 sectors' keys by
exploiting the **tag's PRNG timing being deterministic** — after
authenticating to a known sector, the tag's next nonce for an
unknown-sector auth is **predictable from the time delay**.

### 3.1 Algorithm shape (per *Garcia-ESORICS08* §6 + `mfoc/src/mfoc.c`)

Two phases:

**Phase A — distance calibration** (how many PRNG clocks elapse
between the known-sector auth and the unknown-sector auth):

```
1. Auth to known sector with known key. LFSR reaches known state.
2. Send nested-auth command to unknown sector.
3. Observe encrypted tag nonce {nT}.
4. Decrypt {nT} using the known-sector keystream (still live).
5. Compute "nonce distance" = number of PRNG clocks between
   tag's last-known nT and this decrypted nT.
6. Repeat ~20x. Take the median distance.
```

The distance is stable to within ~±20 PRNG clocks because of
tag-timing jitter. The median pins the timing; the ±20 window is
the search space in Phase B.

**Phase B — key recovery** for each unknown sector:

```
FOR each sector s where key unknown:
    distances = [measure_nonce_distance(known_sector, s) for _ in 20]
    median_d = statistical_median(distances)

    FOR repeat = 1..RECOVERY_SETS:
        auth(known_sector, known_key)   # known-key auth primes the cipher
        send_nested_auth(s)             # tag responds with encrypted {nT}
        observe encrypted nT, parity bits

        candidate_keys = []
        FOR candidate_nt in range(median_d - 20, median_d + 20):
            # The tag's real nT is Prng(prev_nt, candidate_nt).
            keystream = encrypted_nT ⊕ Prng(prev_nt, candidate_nt)
            if parity_check_valid(keystream, observed_parity):
                # 32 bits of keystream recovered ⇒ mfkey32-style rollback.
                for state in lfsr_recovery32(keystream):
                    state = rollback_to_bare_key(state, uid, candidate_nt)
                    candidate_keys.append(lfsr_extract_key(state))

        ranked = sort_by_frequency(candidate_keys)
        FOR key in ranked[:15]:
            if try_auth(s, key):
                STORE key for sector s
                BREAK

    IF no key found AFTER all repeats:
        FAIL (sector is not vulnerable — try mfcuk)
```

Key insight: **parity bit leakage**. MIFARE Classic transmits 8+1
framing per byte (8 data + 1 parity). When encrypted, the parity
bit is *also encrypted but using a specific 8-bit keystream slice*
that leaks information about the cipher state. The
`parity_check_valid()` predicate tests a candidate keystream's
implied parity against what was observed on-wire — it rejects
~7/8ths of candidates without running the full mfkey32 rollback.

### 3.2 Termination criteria

- **Success per sector**: `try_auth` with a recovered candidate
  key succeeds. Record key, move to next sector.
- **Failure per sector**: `RECOVERY_SETS` repeats (default 5 in
  mfoc) × 40-wide distance window × 15 candidates each all fail.
  This sector needs mfcuk (§4) or is a non-vulnerable variant.
- **Success overall**: all sectors have keys. Dump plaintext.
- **Failure overall**: at least one sector unrecovered; mfoc
  errors out with "mandatory sector failed".

### 3.3 Required primitives

All in `internal/crypto1/` (same as mfkey32) plus:

- `nonce_distance(from_nt, to_nt) -> int` — count PRNG steps
  between two nonces. Implemented as a precomputed 2^16 lookup
  or a forward-walk loop.
- `parity_check_valid(keystream, observed_parity) -> bool` —
  test whether a candidate keystream's implied byte-parities
  match the observed wire parities.

### 3.4 Test vector / fixture strategy

**Problem:** the nested attack inherently requires card I/O — the
attack doesn't run offline on a static capture.

**Solution for unit test:** the engineer fixtures out the card I/O
using a fake `Reader` interface:

```go
type NestedReader interface {
    AuthKnown(sector uint8, key uint64) error
    NestedAuth(targetSector uint8) (encryptedNT uint32, parity [4]byte, err error)
}
```

Provide a deterministic mock `NestedReader` in
`internal/attack/nested_test.go` that replays a captured session:
key-loaded state + Prng walk + known encrypted responses. The
mock's output is seeded from a 4-sector synthetic capture file
that the engineer generates by running the reference mfoc against
a software MIFARE emulator (`libnfc-emulate-forum-tag4` or
equivalent). The resulting `.mfd` bytes + the known sector keys
form the regression fixture.

**If no synthetic capture is available at port time**: the engineer
writes an integration test that skips unless `PROMPTZERO_TEST_NFC`
is set and a real capture file is supplied via env var. This is
consistent with the runbook §B.2 "mfoc nested: embed a 4-sector
synthetic capture" requirement.

### 3.5 Reference sources

- `nfc-tools/mfoc/src/mfoc.c` §`mf_nested_attack()` — end-to-end
  orchestration.
- `nfc-tools/mfoc/src/crapto1.c` §`lfsr_common_prefix` and
  §`lfsr_recovery32` — the heavy lifting.
- *Garcia-ESORICS08* §6 — "Nested authentication attacks".

---

## 4. Mfcuk darkside attack

The "no key needed" variant — recovers a key from scratch. Works
on vulnerable Mifare Classic 1K/4K (Classic and Classic-EV0
silicon). Does **not** work on EV1 / Plus / DESFire (they fixed
the vulnerability circa 2011).

### 4.1 Algorithm shape (per *Garcia-SP09* §4 + `mfcuk/src/mfcuk.c`)

The attack exploits two Crypto1 weaknesses:

1. **The 4-bit NACK response.** When the reader sends an
   incorrect `{aR}` (reader response) during authentication, the
   vulnerable tag sends an encrypted 4-bit NACK (value `0x5`)
   instead of silently disconnecting. The NACK's encryption leaks
   4 keystream bits per authentication attempt.
2. **Parity leakage during error response.** The 8 parity bits of
   the reader's `{aR}` encrypt independently of the underlying
   data bits. Observing which parity combinations cause a NACK
   (versus silent disconnect) narrows the cipher state further.

### 4.2 Two-phase flow

**Phase 1 — Find a parity configuration that triggers a NACK:**
```
Fix uid, nt (tag nonce) for this session.
Fix some reader nonce nR with a guessed encrypted form {nR}.
for parity_combination in 0..255:                 # 8-bit space
    send {nR}, {aR_wrong}, parity=this_combination
    if tag responds with encrypted NACK:
        RECORD (nR, parity_combination, encrypted_NACK)
        BREAK
```

Empirically, on a vulnerable card, ~1 in 256 parity combinations
triggers a NACK — so this loop terminates in at most 256 attempts
(~5-30 seconds depending on reader speed).

**Phase 2 — Collect 8 NACKs for filter-state recovery:**
```
Fix the 29-bit nR prefix and 3-bit parity prefix that produced the
Phase-1 NACK. Vary the low 5 bits of nR through 32 combinations
(for EACH, try up to 32 parity settings of the low 5 parity bits):
    send {nR_varied}, {aR_wrong}, parity=varied
    if NACK: RECORD it
    repeat until we have 8 NACKs

For each of 8 NACKs:
    ks[i] = (encrypted_NACK[i]) ⊕ 0x5       # decrypt to real keystream
```

After 8 NACKs we have 8 × 4 = 32 keystream bits AND the 8 × 8 = 64
bits of parity constraint data.

**Phase 3 — Offline filter-state recovery:**

Run `lfsr_common_prefix(nr_prefix, ar_enc, ks[], parBitsArr[][])`.
This function searches the ~2^19 pre-image space of the filter,
using the parity constraints to prune by ~6 bits per NACK — the
search converges to a few candidate states.

For each candidate:
```
state = lfsr_rollback_word(state, uid ⊕ nt, 0)
key = lfsr_extract_key(state)
Try auth(sector, key).
If success: return key.
```

### 4.3 The "filter-weight" table — architect's note

The architect §B.2 specifically called out the filter-weight table
the darkside attack uses to prune candidate states. The canonical
source is `mfcuk/src/crapto1.c`'s internal `filterlut[]`. This is
a **2^20-entry precomputed table**, one bit per entry, holding
`filter(i)` for each `i` in `0..0xFFFFF`. It is NOT a small set of
hand-listable weights — it's a bulk precomputation to avoid
re-evaluating the filter function inside the recovery inner loop.

**What the architect meant by "list the actual weights":** there
is no short weight list. The "filter weight" is the output of the
`filter()` function (§1.4 above — `f_a` × 0xF22C, `f_b` × 0xD938,
`f_c` combiner × 0xEC57E80A). Upstream precomputes 2^20 outputs
into `filterlut[]` and uses it as `filter(x) = filterlut[x & 0xFFFFF]`
to bypass the 5 nibble lookups.

**Go port strategy:** start without the filterlut table; use the
direct filter() computation. If `TestDarksideSelftest` runs >30s,
add the 128 KiB (2^20 bits packed) filterlut precomputation as a
`sync.Once`-guarded global.

### 4.4 Test vector

`nfc-tools/mfcuk` does not ship a `-S` self-test mode (the `-s`
/ `-S` flags are sleep timers, not self-test). The darkside
attack inherently needs live card I/O to collect NACKs.

**Fixture strategy:** lift the Phase-3 input from a known capture.
Once the engineer has a working `internal/crypto1.Cipher`, generate
a synthetic darkside capture by:

1. Pick a key, e.g. `0xA0A1A2A3A4A5`.
2. Simulate 8 NACK exchanges against a fake tag with this key.
3. Record `(nR_prefix, ar_enc, ks[8], parBitsArr[8][8])`.
4. Run the offline Phase-3 recovery; assert key is found.

This gives a deterministic offline test for Phase 3 without needing
live NFC hardware. The integration test for Phases 1-2 remains
hardware-gated (env var + real card).

**Known-answer vector skeleton (engineer fills in at port time):**
```
key              = 0xA0A1A2A3A4A5
uid              = 0xDEADBEEF
nt               = 0x01020304
nr_prefix (29b)  = 0x1FEDCB_A
ar_enc           = 0xCAFEBEEF
ks[8]            = [0xA, 0x3, ...]        # 8 × 4-bit keystream leaks
parBitsArr[8][8] = [...]                  # 64-bit parity matrix
Expected recovered key = 0xA0A1A2A3A4A5
```

### 4.5 Known limitations

Darkside-immune cards (do NOT NACK on wrong `{aR}`):

- **Mifare Classic EV1** (post-2011 silicon revision) — fixed the
  NACK leak.
- **Mifare Plus** (in SL1 or higher) — different cipher (AES).
- **Mifare DESFire** (any generation) — uses 3DES/AES.
- **Mifare Ultralight** — no Crypto1 at all.
- **Some clone cards** (e.g. Fudan FM11RF08S) — variable
  behaviour; some NACK, some don't.

The v0.5 `mfcuk_attack` tool should **return a structured error**
(`{"error":"card_not_vulnerable","suggest":"try mfoc with a known key"}`)
when Phase 1 exhausts the 256 parity space without a NACK. No
retry loop past this point — it won't help.

### 4.6 Reference sources

- `nfc-tools/mfcuk/src/mfcuk.c` — Phase 1+2 orchestration.
- `nfc-tools/mfcuk/src/mfcuk_keyrecovery_darkside.c` — the recovery
  tool entry point (despite the "keyrecovery" name, this file is
  the Phase-1 NACK collector).
- `nfc-tools/mfcuk/src/crapto1.c::lfsr_common_prefix` — Phase-3
  offline recovery.
- *Garcia-SP09* §4 "Wirelessly Pickpocketing" — canonical academic
  source for darkside.

---

## 5. Hardnested (v0.5.1 — deferred)

Per the runbook §A.2 and architect confirmation, hardnested is
**out of scope for v0.5**. This section is a seed for whoever picks
up task #7.1 in v0.5.1.

### 5.1 Why hardnested is harder than nested

The nested attack (§3) relies on the tag's **16-bit PRNG being
predictable**. Mifare Classic EV1 replaced the weak PRNG with a
**hardware TRNG** — tag nonces are now genuinely random. This
breaks nested's Phase-A distance calibration (you can't predict
the next nonce from the previous one because they're independent).

Hardnested gets around this by exploiting a different Crypto1
weakness: the filter function's **statistical bias**. Given many
encrypted nonces with known partial plaintext (authentication
responses still follow a known structure even with a TRNG nonce),
the attacker can accumulate statistical evidence about the key
faster than brute force.

### 5.2 The 250 GB precomputed table

The reference hardnested impl (`nfc-tools/mfoc-hardnested/src/cmdhfmfhard.c`)
precomputes **bitslice tables** holding the evolution of all
possible 48-bit LFSR states under a filter-bias statistic. The
full table is ~250 GB uncompressed, ~2-4 GB compressed. The
Proxmark3 ships a subset of the tables (~60 MiB) that handle the
common-case bias patterns; the full tables live on academic
servers.

### 5.3 v0.5.1 engineer's starting points

- **Read first**: `nfc-tools/mfoc-hardnested/src/cmdhfmfhard.c`
  (~3000 lines — the orchestration layer, no cipher primitives).
- **Academic reference**: "Hardening MIFARE Classic" (no public
  academic paper — the algorithm was released directly as
  source by Proxmark3's `iceman` contributor circa 2015-2016).
  Closest academic analog is Meijer & Verdult 2015 "Ciphertext-
  only cryptanalysis on hardened Mifare Classic cards", USENIX
  WOOT 2015.
- **Smaller-footprint variant**: the Meijer-Verdult paper describes
  a statistical attack that runs in ~5 minutes per sector with
  **no precomputed table** — suitable for a pure-Go port that
  prioritises memory over speed. This is the likely v0.5.1
  direction: skip the 60+ MiB table entirely, accept a ~10x
  slowdown.
- **Hardware gate**: hardnested only matters for Mifare Classic
  EV1+. The v0.5.1 Spec should explicitly block the tool on non-
  EV1 cards (firmware_introspect returns the card silicon rev —
  see task #6 / runbook §C).

---

## 6. Summary — what the wave-2 engineer gets from this doc

| Deliverable | Source section |
|---|---|
| LFSR feedback polynomial (18 taps) | §1.1 |
| LFSR tap conflict resolution | §1.2 |
| Key initialisation flow | §1.3 |
| Filter function (f_a, f_b, f_c truth tables) | §1.4 |
| Even/odd split as optimisation | §1.5 |
| PRNG polynomial | §1.6 |
| 5 Crypto1 test vectors | §1.7 |
| Mfkey32 pseudocode | §2.3 |
| Mfkey32 test vector | §2.5 |
| Mfoc nested pseudocode | §3.1 |
| Nested fixture strategy | §3.4 |
| Mfcuk darkside pseudocode | §4.1-4.2 |
| Filter-weight table clarification | §4.3 |
| Darkside test vector skeleton | §4.4 |
| Darkside card-immunity list | §4.5 |
| Hardnested deferral rationale | §5 |

**Top three risks for the port:**

1. **Tap-ordering bugs.** The LFSR feedback polynomial is
   canonical (§1.1), but the bit-indexing convention is where
   every port historically gets it wrong. Use §1.7's test vectors
   in the order §1.2 recommends.
2. **nR-feedback vs ciphertext-feedback confusion.** Crypto1
   feeds **plaintext nR** into the LFSR during EncCrypt, not the
   ciphertext. See §1.3's note — this trips up everyone on first
   port.
3. **Filter input bit positions.** The filter reads *odd-indexed*
   state bits only (§1.4). Getting this wrong produces output
   that looks random but doesn't match any test vector.

**Budget:** per runbook §D.4, expect 1-2 days of vector-driven
debugging on the cipher itself. Mfkey32 then falls out in another
day. Nested + darkside together are another 2-3 days (mostly I/O
fixture work, not cipher work). Total: ~4-6 days for the cipher +
three attacks, not counting integration into `internal/tools/`.
