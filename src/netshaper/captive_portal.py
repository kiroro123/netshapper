#!/usr/bin/env python3
"""Module entrypoint for the NetShaper offensive DNS + portal engine.

The packaged console command is `netshaper-portal`; this module points
`python -m netshaper.captive_portal` at the same maintained engine.
"""

import sys

try:
    from . import portal as _engine
except Exception:
    # Allow `python -m netshaper.captive_portal` to surface the original
    # import error in development checkouts.
    raise


def main() -> None:
    """Delegate to the maintained offensive DNS + portal engine."""
    return _engine.main()


if __name__ == "__main__":
    sys.exit(main())
