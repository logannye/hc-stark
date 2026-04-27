"""TinyZKP — Python client for ZK-STARK proof generation and verification."""

from tinyzkp.client import (
    HcClient,
    HcClient as TinyZKP,
    HcClientError,
    HcClientSync,
    HcClientSync as TinyZKPSync,
    ProofBytes,
    ProveJobStatus,
    TemplateSummary,
    VerifyResult,
)

__version__ = "0.1.1"

__all__ = [
    "TinyZKP",
    "TinyZKPSync",
    "HcClient",
    "HcClientSync",
    "HcClientError",
    "ProofBytes",
    "ProveJobStatus",
    "TemplateSummary",
    "VerifyResult",
    "__version__",
]
