"""
WHAT:   Lets the package run as "python -m tracekeep".
WHY:    No install step needed: run it straight from the project folder.
"""

import sys

from tracekeep.cli import main

sys.exit(main())
