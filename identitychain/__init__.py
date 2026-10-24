"""IdentityChain — privacy-preserving identity proofs."""

from .proofs import (
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
)

__version__ = "1.0.0"

__all__ = [
    "AttributeSet",
    "Commitment",
    "MerkleTree",
    "Params",
    "ProofError",
    "SchnorrProof",
    "commit",
    "prove_opening",
    "verify_opening",
    "verify_proof",
]
