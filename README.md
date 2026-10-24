# IdentityChain

Privacy-preserving identity proofs built from scratch: Pedersen commitments,
Schnorr proofs of knowledge, and Merkle selective disclosure.

The problem this solves: a service needs to know one fact about you — that you
are over 18, that your country is on a list, that your account is in good
standing — and today the usual answer is to hand over the whole document. This
library lets you prove a single attribute while revealing nothing else, and
lets the verifier check the proof against a commitment it already holds.

## What is implemented

**A Schnorr group** (`P`, `Q` in `proofs.py`). Rather than depend on a curve
library, the group is a subgroup of `Z_p*` of prime order `q`, where
`p = 2q + 1` and both are prime. The pair was found by searching upward from
`2^255` and verified with Miller-Rabin over 40 random bases. Prime-order means
no small-subgroup attacks and no cofactor arithmetic to get wrong.

**Pedersen commitments** — `C = g^m · h^r mod p`. Hiding because `r` is
uniform, binding because finding two openings means solving a discrete log.
The two generators are derived by hashing a seed and squaring, which lands them
in the order-`q` subgroup without anyone knowing their relative discrete log.

**Schnorr proofs of knowledge** — proves you know `(m, r)` opening a
commitment, without revealing either. Made non-interactive with Fiat-Shamir,
and the challenge binds a caller-supplied context string, so a proof made for
one purpose cannot be replayed for another.

**Merkle selective disclosure** — commit to a set of named attributes, then
reveal one with a path proving it was in the committed set. Leaves are
domain-separated from internal nodes (`0x00` vs `0x01` prefix), which blocks
the second-preimage attack where an internal node is presented as a leaf.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Run the tests

```bash
python -m pytest -q
```

## Use it

```python
from identitychain import AttributeSet, Params, commit, prove_opening, verify_proof

params = Params.generate(b"my-application-seed-32-bytes-ok!")

# Commit to a value and prove you know the opening.
c = commit(params, 21_000_000)          # e.g. a salary, in minor units
proof = prove_opening(params, c, 21_000_000, c.blinding, context=b"payroll")
assert verify_proof(params, c, proof, context=b"payroll")

# Selective disclosure: reveal one attribute, hide the rest.
attrs = AttributeSet.build([
    ("name", b"alice"),
    ("country", b"PK"),
    ("salary", b"21000000"),
])
leaf, index, path = attrs.disclose("country")
assert attrs.verify_disclosure("country", b"PK", index, path)
# The path contains hashes only — `salary` never leaves the client.
```

## Design notes

**Why a Schnorr group instead of an elliptic curve.** The algebra is simple
enough to check by hand, and the whole thing runs on Python integers with no
dependencies. The trade-off is size: a 257-bit group gives roughly 128-bit
security, where an equivalent curve would be 32 bytes. For a reference
implementation that is the right trade.

**Why the challenge binds a context string.** Without it, a proof that you
know the opening of commitment `C` is valid anywhere `C` appears. Binding
`b"payroll"` means the same proof cannot be replayed against a different
verifier or a different purpose.

**Why odd levels are promoted rather than duplicated.** Duplicating the last
node when a level has an odd count is the classic Merkle ambiguity that let
CVE-2012-2459 forge roots. Here the odd node carries up unchanged, and the
proof records a `promote` step so the verifier follows the same index
arithmetic.

## Bugs found while building this

Two, both caught by tests rather than by reading:

1. **The hard-coded prime was not a safe prime.** The first version used a
   constant that looked plausible but was not `2q + 1` with both factors
   prime, so the subgroup had composite order and the security argument did
   not hold. The test asserting `pow(g, Q, P) == 1` failed. Replaced with a
   genuinely generated and independently verified safe prime.

2. **Merkle proofs failed for odd leaf counts.** The prover promoted the last
   node of an odd level, but the verifier had no way to know a promotion had
   happened, so it tried to combine a node that was never combined. Fixed by
   recording an explicit `promote` step in the path. The test loops over 1–8
   leaves precisely because the bug only appears at odd counts.

## Layout

```
identitychain/
  proofs.py   group, commitments, Schnorr proofs, Merkle trees
tests/
  test_proofs.py
```

## Licence

MIT. See `LICENSE`.

## Author

Konain Sultan Khan (KK) — https://github.com/kkcyber2
LinkedIn: _add your profile URL here_
