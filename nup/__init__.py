"""NUP v2: a package format for decrypted Nintendo Switch 1/2 dumps.

The container is a bare HFS0 partition; ``meta.nup``, its first entry,
carries versioning, grouping and integrity.  See SPEC.md for the format.
"""

from .errors import NupError, VerificationError
from .layout import Kind, Flags, TlvType, SPEC_ISSUES, truncated_digest

__all__ = [
    "NupError",
    "VerificationError",
    "Kind",
    "Flags",
    "TlvType",
    "SPEC_ISSUES",
    "truncated_digest",
]

__version__ = "2.0.0"
