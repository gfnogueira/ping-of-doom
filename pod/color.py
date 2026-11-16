"""Tiny ANSI helper. Colors only when stdout is a terminal. NO_COLOR turns them off."""
import os
import sys

CODES = {
    "bold": "1", "dim": "2", "red": "1;31", "green": "1;32", "yellow": "1;33",
    "cyan": "1;36", "magenta": "1;35",
}


def enabled():
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ or "FORCE_COLOR" in os.environ


def paint(text, color):
    """color is a name from CODES or a 256 color number."""
    if not enabled():
        return text
    code = CODES.get(color, f"38;5;{color}")
    return f"\033[{code}m{text}\033[0m"
