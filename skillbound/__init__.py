"""skillbound: static scope checker for agent skills.

Cross-checks what a skill's SKILL.md *promises* (its boundary claims)
against what its bundled files can actually *do* (network egress, file
writes, deletes, secret access, installs/exec, config edits).

Stdlib only, offline, no model calls.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
