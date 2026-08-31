"""Module entry point for environments where console scripts are not on PATH.

On Windows, ``py -m mcp_auditor`` is the reliable equivalent of ``mcp-audit``.
Both routes call the exact same Click application.
"""

from .cli import main


if __name__ == "__main__":
    main()
