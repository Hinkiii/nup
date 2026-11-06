"""Fail-closed exceptions for malformed or nonconforming NUP data."""


class NupError(Exception):
    """Malformed, nonconforming, or ambiguous NUP data."""


class VerificationError(NupError):
    """A hash chain or structural rule failed verification."""
