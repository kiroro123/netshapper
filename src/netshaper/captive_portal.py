#!/usr/bin/env python3
"""Compatibility shim for the historical `netshaper.captive_portal` entrypoint.

This module intentionally delegates to the maintained `netshaper.fake_server3`
engine. It preserves the original console entrypoint while emitting a
deprecation-style notice so downstream callers migrate to the consolidated
implementation.
"""

import sys
import warnings

try:
    # Import the maintained combined engine and call its main() directly.
    from . import fake_server3 as _engine
except Exception:
    # Allow `python -m netshaper.captive_portal` to surface the original
    # import error in development checkouts.
    raise


def main() -> None:
    """Delegate to `netshaper.fake_server3.main()` with a short warning."""
    warnings.warn(
        "'netshaper.captive_portal' is deprecated; delegating to 'fake_server3'.",
        DeprecationWarning,
        stacklevel=2,
    )
    # Pass through control to the consolidated implementation. This keeps the
    # legacy console script working while centralizing maintenance.
    return _engine.main()


if __name__ == "__main__":
    sys.exit(main())
