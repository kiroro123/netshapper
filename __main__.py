"""
NetShaper — Package entry point.
"""
import os
import sys

package_dir = os.path.dirname(os.path.abspath(__file__))
package_parent = os.path.dirname(package_dir)
if package_parent not in sys.path:
    sys.path.insert(0, package_parent)

from netshaper.ui import cli

if __name__ == "__main__":
    cli.main()
