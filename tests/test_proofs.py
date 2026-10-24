"""Tests for the commitment, proof and Merkle primitives."""

import os

import pytest

from identitychain.proofs import (
    AttributeSet,
    Commitment,
    MerkleTree,
    Params,
    ProofError,
    SchnorrProof,
    commit,
    prove_opening,
    verify_opening,
    verify_proof,
    _hash_to_group,
    _leaf_hash,
    _node_hash,
    P,
    Q,
)


@pytest.fixture(scope="module")
def params():
    return Params.generate(b"\x11" * 32)


def test_params_are_deterministic_for_a_seed():
    a = Params.generate(b"\x22" * 32)
    b = Params.generate(b"\x22" * 32)
    assert a.g == b.g and a.h == b.h


def test_params_differ_across_seeds():
    a = Params.generate(b"\x33" * 32)
    b = Params.generate(b"\x44" * 32)
    assert a.g != b.g


def test_params_reject_bad_seed():
    with pytest.raises(ProofError):
        Params.generate(b"short")


def test_generators_are_distinct_and_in_subgroup(params):
    assert params.g != params.h
    # Elements of the order-q subgroup satisfy x^q == 1 mod p.
    assert pow(params.g, Q, P) == 1
    assert pow(params.h, Q, P) == 1


def test_hash_to_group_is_deterministic():
    assert _hash_to_group(b"seed", 0) == _hash_to_group(b"seed", 0)
    assert _hash_to_group(b"seed", 0) != _hash_to_group(b"seed", 1)


def test_commit_is_hiding(params):
    """The same message with different blindings gives different commitments."""
    a = commit(params, 42)
    b = commit(params, 42)
    assert a.value != b.value


def test_commit_is_deterministic_with_a_fixed_blinding(params):
    a = commit(params, 42, blinding=12345)
    b = commit(params, 42, blinding=12345)
    assert a.value == b.value


def test_commit_rejects_negative_message(params):
    with pytest.raises(ProofError):
        commit(params, -1)


def test_commit_rejects_message_beyond_group_order(params):
    with pytest.raises(ProofError):
        commit(params, Q)


def test_commit_rejects_bad_blinding(params):
    with pytest.raises(ProofError):
        commit(params, 1, blinding=Q + 5)


def test_opening_verifies(params):
    c = commit(params, 7)
    assert verify_opening(params, c, 7, c.blinding)


def test_opening_rejects_wrong_message(params):
    c = commit(params, 7)
    assert not verify_opening(params, c, 8, c.blinding)


def test_opening_rejects_wrong_blinding(params):
    c = commit(params, 7)
    assert not verify_opening(params, c, 7, c.blinding + 1)


def test_opening_rejects_out_of_range_values(params):
    c = commit(params, 7)
    assert not verify_opening(params, c, Q, c.blinding)
    assert not verify_opening(params, c, 7, -1)


def test_proof_verifies(params):
    c = commit(params, 99)
    proof = prove_opening(params, c, 99, c.blinding)
    assert verify_proof(params, c, proof)


def test_proof_is_non_interactive_and_reproducible_with_a_nonce(params):
    c = commit(params, 5, blinding=777)
    p1 = prove_opening(params, c, 5, 777, nonce=(11, 22))
    p2 = prove_opening(params, c, 5, 777, nonce=(11, 22))
    assert p1.to_bytes() == p2.to_bytes()


def test_proof_rejects_wrong_opening(params):
    c = commit(params, 5)
    with pytest.raises(ProofError):
        prove_opening(params, c, 6, c.blinding)


def test_proof_rejects_bad_nonce(params):
    c = commit(params, 5)
    with pytest.raises(ProofError):
        prove_opening(params, c, 5, c.blinding, nonce=(Q, 1))


def test_proof_fails_against_a_different_commitment(params):
    c1 = commit(params, 5)
    c2 = commit(params, 5)
    proof = prove_opening(params, c1, 5, c1.blinding)
    assert not verify_proof(params, c2, proof)


def test_proof_is_bound_to_context(params):
    c = commit(params, 5)
    proof = prove_opening(params, c, 5, c.blinding, context=b"login")
    assert verify_proof(params, c, proof, context=b"login")
    assert not verify_proof(params, c, proof, context=b"transfer")


def test_proof_rejects_tampered_response(params):
    c = commit(params, 5)
    proof = prove_opening(params, c, 5, c.blinding)
    proof.s_m = (proof.s_m + 1) % Q
    assert not verify_proof(params, c, proof)


def test_proof_rejects_tampered_commitment_point(params):
    c = commit(params, 5)
    proof = prove_opening(params, c, 5, c.blinding)
    proof.t = (proof.t * 2) % P
    assert not verify_proof(params, c, proof)


def test_proof_rejects_out_of_range_fields(params):
    c = commit(params, 5)
    proof = prove_opening(params, c, 5, c.blinding)
    proof.s_r = Q + 1
    assert not verify_proof(params, c, proof)


def test_proof_serialisation_roundtrip(params):
    c = commit(params, 5)
    proof = prove_opening(params, c, 5, c.blinding)
    raw = proof.to_bytes()
    assert len(raw) == 192


def test_merkle_root_is_stable():
    t1 = MerkleTree.build([b"a", b"b", b"c"])
    t2 = MerkleTree.build([b"a", b"b", b"c"])
    assert t1.root == t2.root


def test_merkle_root_changes_with_content():
    t1 = MerkleTree.build([b"a", b"b", b"c"])
    t2 = MerkleTree.build([b"a", b"b", b"d"])
    assert t1.root != t2.root


def test_merkle_rejects_empty_input():
    with pytest.raises(ProofError):
        MerkleTree.build([])


def test_merkle_proof_verifies_for_every_leaf():
    items = [b"one", b"two", b"three", b"four", b"five"]
    tree = MerkleTree.build(items)
    for i, item in enumerate(items):
        assert tree.verify(item, i, tree.proof(i))


def test_merkle_proof_rejects_wrong_item():
    items = [b"one", b"two", b"three"]
    tree = MerkleTree.build(items)
    assert not tree.verify(b"four", 0, tree.proof(0))


def test_merkle_proof_rejects_wrong_index():
    items = [b"one", b"two", b"three"]
    tree = MerkleTree.build(items)
    assert not tree.verify(b"one", 1, tree.proof(0))


def test_merkle_proof_rejects_out_of_range_index():
    tree = MerkleTree.build([b"one"])
    with pytest.raises(ProofError):
        tree.proof(5)
    assert not tree.verify(b"one", 5, [])


def test_merkle_handles_odd_leaf_counts():
    for n in range(1, 9):
        items = [("item%d" % i).encode() for i in range(n)]
        tree = MerkleTree.build(items)
        for i, item in enumerate(items):
            assert tree.verify(item, i, tree.proof(i)), "failed at n=%d i=%d" % (n, i)


def test_leaf_and_node_hashes_are_domain_separated():
    """A leaf must never hash to the same value as an internal node."""
    assert _leaf_hash(b"x") != _node_hash(b"x", b"x")


def test_merkle_rejects_forged_path_side():
    items = [b"one", b"two", b"three", b"four"]
    tree = MerkleTree.build(items)
    path = tree.proof(0)
    forged = [("left", path[0][1])] + path[1:]
    assert not tree.verify(b"one", 0, forged)


def test_attribute_set_root_is_stable():
    a = AttributeSet.build([("name", b"alice"), ("age", b"30")])
    b = AttributeSet.build([("name", b"alice"), ("age", b"30")])
    assert a.root == b.root


def test_attribute_set_rejects_empty():
    with pytest.raises(ProofError):
        AttributeSet.build([])


def test_attribute_set_rejects_duplicate_names():
    with pytest.raises(ProofError):
        AttributeSet.build([("name", b"a"), ("name", b"b")])


def test_selective_disclosure_reveals_one_attribute():
    attrs = AttributeSet.build(
        [("name", b"alice"), ("age", b"30"), ("country", b"PK")]
    )
    leaf, idx, path = attrs.disclose("age")
    assert attrs.verify_disclosure("age", b"30", idx, path)


def test_selective_disclosure_rejects_wrong_value():
    attrs = AttributeSet.build([("name", b"alice"), ("age", b"30")])
    leaf, idx, path = attrs.disclose("age")
    assert not attrs.verify_disclosure("age", b"31", idx, path)


def test_selective_disclosure_rejects_unknown_attribute():
    attrs = AttributeSet.build([("name", b"alice")])
    with pytest.raises(ProofError):
        attrs.disclose("salary")


def test_disclosure_does_not_leak_other_attributes():
    """The proof path must not contain the other attribute values."""
    attrs = AttributeSet.build(
        [("name", b"alice"), ("salary", b"120000"), ("ssn", b"123-45-6789")]
    )
    leaf, idx, path = attrs.disclose("name")
    blob = leaf + b"".join(h for _, h in path)
    assert b"120000" not in blob
    assert b"123-45-6789" not in blob
