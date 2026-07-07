#!/usr/bin/env python3
"""NetShaper offensive DNS + captive portal entrypoint."""

import sys

from . import fake_server3 as _engine


def main() -> None:
    """Run the maintained offensive DNS + captive portal engine."""
    return _engine.main()


if __name__ == "__main__":
    sys.exit(main())
