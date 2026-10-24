"""Pedersen commitments, Schnorr proofs and Merkle selective disclosure.

Everything here is built on a prime-order group. Rather than pull in a curve
library, the group is a Schnorr group: a subgroup of Z_p* of prime order q,
where p = 2q + 1 and both are prime. That gives a group where the discrete log
is believed hard and where the algebra is simple enough to verify by hand.

The three pieces:

  * **Pedersen commitment** — `C = g^m * h^r`. Hiding (r is uniform) and
    binding (finding two openings means solving a discrete log).
  * **Schnorr proof of knowledge** — proves you know the opening without
    revealing it, made non-interactive with Fiat-Shamir.
  * **Merkle selective disclosure** — commit to a set of attributes, then
    reveal one attribute with a proof it was in the committed set, without
    revealing the others.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# A 257-bit Schnorr group. p = 2q + 1 with both prime, so the order-q
# subgroup of Z_p* has prime order and the discrete log is believed hard.
# The pair was found by searching upward from 2^255 for a safe prime and
# verified with Miller-Rabin over 40 random bases.
P = 0x1000000000000000000000000000000000000000000000000000000000003832F
Q = 0x800000000000000000000000000000000000000000000000000000000001C197


class ProofError(Exception):
    """Raised when a proof cannot be produced or fails to verify."""


def _hash_to_int(*parts: bytes) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return int.from_bytes(h.digest(), "big")


def _hash_to_group(seed: bytes, index: int) -> int:
    """Derive a group element from a seed and an index.

    The element is `H(seed||index)^2 mod p`, which lands in the order-q
    subgroup because squaring maps into it. Nobody knows the discrete log of
    the result relative to any other element, which is what the commitment
    scheme needs.
    """
    x = _hash_to_int(seed, index.to_bytes(4, "big")) % P
    if x == 0:
        x = 2
    return pow(x, 2, P)


@dataclass(frozen=True)
class Params:
    """Public parameters: two independent generators."""

    g: int
    h: int

    @classmethod
    def generate(cls, seed: Optional[bytes] = None) -> "Params":
        if seed is None:
            seed = os.urandom(32)
        if len(seed) != 32:
            raise ProofError("seed must be 32 bytes")
        g = _hash_to_group(seed, 0)
        h = _hash_to_group(seed, 1)
        if g == h:
            raise ProofError("generators collided; use a different seed")
        return cls(g=g, h=h)


def _mod_inverse(a: int, m: int) -> int:
    if a % m == 0:
        raise ProofError("no inverse exists")
    return pow(a, -1, m)


@dataclass
class Commitment:
    value: int
    blinding: int

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(64, "big")


def commit(params: Params, message: int, blinding: Optional[int] = None) -> Commitment:
    """Commit to an integer message."""
    if not isinstance(message, int) or message < 0:
        raise ProofError("message must be a non-negative integer")
    if message >= Q:
        raise ProofError("message must be smaller than the group order")
    if blinding is None:
        blinding = int.from_bytes(os.urandom(32), "big") % Q
    if not 0 <= blinding < Q:
        raise ProofError("blinding factor out of range")
    value = (pow(params.g, message, P) * pow(params.h, blinding, P)) % P
    return Commitment(value=value, blinding=blinding)


def verify_opening(params: Params, c: Commitment, message: int, blinding: int) -> bool:
    """Check that a commitment opens to the claimed message."""
    if not 0 <= message < Q or not 0 <= blinding < Q:
        return False
    expected = (pow(params.g, message, P) * pow(params.h, blinding, P)) % P
    return expected == c.value


@dataclass
class SchnorrProof:
    """Non-interactive proof of knowledge of a commitment opening."""

    t: int
    s_m: int
    s_r: int

    def to_bytes(self) -> bytes:
        return (
            self.t.to_bytes(64, "big")
            + self.s_m.to_bytes(64, "big")
            + self.s_r.to_bytes(64, "big")
        )


def prove_opening(
    params: Params,
    c: Commitment,
    message: int,
    blinding: int,
    context: bytes = b"",
    nonce: Optional[Tuple[int, int]] = None,
) -> SchnorrProof:
    """Prove knowledge of (message, blinding) opening `c`.

    This is a Schnorr proof over two exponents at once: the prover commits to
    two random values, the challenge binds the commitment and the context, and
    the responses are the random values plus challenge times the secrets.
    """
    if not verify_opening(params, c, message, blinding):
        raise ProofError("the opening does not match the commitment")
    if nonce is None:
        k_m = int.from_bytes(os.urandom(32), "big") % Q
        k_r = int.from_bytes(os.urandom(32), "big") % Q
    else:
        k_m, k_r = nonce
        if not (0 <= k_m < Q and 0 <= k_r < Q):
            raise ProofError("nonce out of range")
    t = (pow(params.g, k_m, P) * pow(params.h, k_r, P)) % P
    e = _hash_to_int(
        b"identitychain/v1/schnorr",
        params.g.to_bytes(64, "big"),
        params.h.to_bytes(64, "big"),
        c.value.to_bytes(64, "big"),
        t.to_bytes(64, "big"),
        context,
    ) % Q
    s_m = (k_m + e * message) % Q
    s_r = (k_r + e * blinding) % Q
    return SchnorrProof(t=t, s_m=s_m, s_r=s_r)


def verify_proof(
    params: Params,
    c: Commitment,
    proof: SchnorrProof,
    context: bytes = b"",
) -> bool:
    """Verify a Schnorr proof without learning the opening."""
    if not (0 < proof.t < P):
        return False
    if not (0 <= proof.s_m < Q and 0 <= proof.s_r < Q):
        return False
    e = _hash_to_int(
        b"identitychain/v1/schnorr",
        params.g.to_bytes(64, "big"),
        params.h.to_bytes(64, "big"),
        c.value.to_bytes(64, "big"),
        proof.t.to_bytes(64, "big"),
        context,
    ) % Q
    left = (pow(params.g, proof.s_m, P) * pow(params.h, proof.s_r, P)) % P
    right = (proof.t * pow(c.value, e, P)) % P
    return left == right


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass
class MerkleTree:
    """A Merkle tree over attribute commitments.

    Leaves are domain-separated from internal nodes, which stops a
    second-preimage attack where an attacker presents an internal node as if
    it were a leaf.
    """

    leaves: List[bytes]
    levels: List[List[bytes]]

    @classmethod
    def build(cls, items: Sequence[bytes]) -> "MerkleTree":
        if not items:
            raise ProofError("cannot build a tree with no leaves")
        leaves = [_leaf_hash(i) for i in items]
        levels = [leaves]
        current = leaves
        while len(current) > 1:
            nxt: List[bytes] = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    nxt.append(_node_hash(current[i], current[i + 1]))
                else:
                    # Odd node is promoted unchanged rather than duplicated,
                    # which avoids the CVE-2012-2459 style ambiguity.
                    nxt.append(current[i])
            levels.append(nxt)
            current = nxt
        return cls(leaves=leaves, levels=levels)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, bytes]]:
        """Sibling path for a leaf, as (side, hash) pairs."""
        if not 0 <= index < len(self.leaves):
            raise ProofError("leaf index out of range")
        path: List[Tuple[str, bytes]] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    path.append(("right", level[idx + 1]))
                else:
                    # Odd level: the last node is promoted unchanged. Record
                    # the step so the verifier can follow the same index
                    # arithmetic without knowing the level sizes.
                    path.append(("promote", b""))
            else:
                path.append(("left", level[idx - 1]))
            idx //= 2
        return path

    def verify(self, item: bytes, index: int, path: List[Tuple[str, bytes]]) -> bool:
        """Recompute the root from one leaf and its path."""
        if not 0 <= index < len(self.leaves):
            return False
        node = _leaf_hash(item)
        idx = index
        for side, sibling in path:
            if side == "right":
                if idx % 2 != 0:
                    return False
                node = _node_hash(node, sibling)
            elif side == "left":
                if idx % 2 != 1:
                    return False
                node = _node_hash(sibling, node)
            elif side == "promote":
                if idx % 2 != 0:
                    return False
                # The node carries up unchanged; nothing to combine.
            else:
                return False
            idx //= 2
        return node == self.root


@dataclass
class AttributeSet:
    """A set of named attributes committed as a Merkle tree."""

    names: List[str]
    values: List[bytes]
    tree: MerkleTree

    @classmethod
    def build(cls, attributes: Sequence[Tuple[str, bytes]]) -> "AttributeSet":
        if not attributes:
            raise ProofError("attribute set must not be empty")
        names = [a[0] for a in attributes]
        if len(set(names)) != len(names):
            raise ProofError("attribute names must be unique")
        values = [a[1] for a in attributes]
        leaves = [n.encode("utf-8") + b"=" + v for n, v in attributes]
        return cls(names=names, values=values, tree=MerkleTree.build(leaves))

    @property
    def root(self) -> bytes:
        return self.tree.root

    def disclose(self, name: str) -> Tuple[bytes, int, List[Tuple[str, bytes]]]:
        """Reveal one attribute plus the path proving it was committed."""
        if name not in self.names:
            raise ProofError("no such attribute: %s" % name)
        idx = self.names.index(name)
        leaf = name.encode("utf-8") + b"=" + self.values[idx]
        return leaf, idx, self.tree.proof(idx)

    def verify_disclosure(
        self,
        name: str,
        value: bytes,
        index: int,
        path: List[Tuple[str, bytes]],
    ) -> bool:
        """Check a disclosure against this set's root."""
        leaf = name.encode("utf-8") + b"=" + value
        return self.tree.verify(leaf, index, path)
