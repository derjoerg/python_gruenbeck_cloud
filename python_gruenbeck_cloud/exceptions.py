"""Exceptions for Gruenbeck-cloud."""

class GruenbeckError(Exception):
    """Generic Gruenbeck-cloud exception."""

class GruenbeckConnectionError(GruenbeckError):
    """Gruenbeck connection exception."""

class GruenbeckConnectionTimeoutError(GruenbeckConnectionError):
    """Gruenbeck connection Timeout exception."""
