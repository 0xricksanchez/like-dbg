"""Typed error hierarchy. Every error may carry an actionable remedy."""

from __future__ import annotations


class LikeDbgError(Exception):
    """Base class for all LIKE-DBG errors.

    `remedy` implements the "what's wrong + how to fix" diagnostics shape: when set, it is
    appended to the rendered message.
    """

    def __init__(self, message: str, *, remedy: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy

    def __str__(self) -> str:
        if self.remedy is not None:
            return f"{self.message}\n  → fix: {self.remedy}"
        return self.message


class ConfigError(LikeDbgError):
    """Invalid or unparseable configuration."""


class DownloadError(LikeDbgError):
    """Failure to download a kernel archive."""


class UnpackError(LikeDbgError):
    """Failure to unpack a kernel archive."""


class BuildError(LikeDbgError):
    """Failure during kernel build."""


class RootfsError(LikeDbgError):
    """Failure building the root filesystem."""


class HostCapabilityError(LikeDbgError):
    """Host lacks a capability that an explicit request requires."""


class ContainerError(LikeDbgError):
    """Failure interacting with the container runtime."""


class CacheError(LikeDbgError):
    """Failure resolving, reusing, or migrating a cached Kernel Build / rootfs."""


class SessionError(LikeDbgError):
    """Failure driving the tmux session."""
