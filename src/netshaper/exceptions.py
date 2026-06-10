"""
NetShaper — exception hierarchy for library code.

Replaces sys.exit() calls in library modules with typed exceptions.
Allows CLI layer to catch and handle errors with appropriate exit codes.
"""


class NetShaperError(Exception):
    """Base exception for all NetShaper errors."""
    pass


class SystemCheckError(NetShaperError):
    """Raised when system prerequisites are not met."""
    pass


class DiscoveryError(NetShaperError):
    """Raised when network discovery fails."""
    pass


class InitializationError(NetShaperError):
    """Raised when NetShaper initialization fails."""
    pass


class PrivilegeError(NetShaperError):
    """Raised when insufficient privileges."""
    pass


class InterfaceError(NetShaperError):
    """Raised when network interface is invalid or unavailable."""
    pass
