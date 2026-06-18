"""Launch the Ursa Major C2 server.

Alias for `python -m major.server`.
"""

import runpy

if __name__ == "__main__":
    runpy.run_module("major.server", run_name="__main__")
