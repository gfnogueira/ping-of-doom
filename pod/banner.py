"""Prints the project banner."""
import os
import sys

from .color import paint

FONT = {
    "P": ["████ ", "█   █", "████ ", "█    ", "█    "],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "G": [" ███ ", "█    ", "█  ██", "█   █", " ███ "],
    "O": [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    "F": ["█████", "█    ", "████ ", "█    ", "█    "],
    "D": ["████ ", "█   █", "█   █", "█   █", "████ "],
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    " ": ["   "] * 5,
}
# red at the top, yellow at the bottom
ROW_COLORS = [160, 196, 202, 208, 220]
TITLE = "PING OF DOOM"


def render():
    rows = ["  ".join(FONT[ch][r] for ch in TITLE) for r in range(5)]
    lines = [paint(row, ROW_COLORS[i]) for i, row in enumerate(rows)]
    lines.append("")
    lines.append(paint("Doom over ICMP echo, plus a detector that catches it", "yellow"))
    lines.append(paint("by gfnogueira", "cyan") + paint("  github.com/gfnogueira/ping-of-doom", "dim"))
    return "\n".join(lines)


def show():
    print()
    print(render())
    print()


MIN_ROWS_BELOW = 12  # keep this many rows for output under a pinned banner


def pin():
    """Draws the banner at the top and confines scrolling to the rows below it.

    Falls back to a plain banner when stdout is not a terminal or it is too short.
    """
    header = "\n" + render() + "\n" + paint("-" * 60, "dim")
    height = header.count("\n") + 1
    try:
        rows = os.get_terminal_size().lines
    except OSError:
        rows = 0
    if not sys.stdout.isatty() or rows < height + MIN_ROWS_BELOW:
        show()
        return
    sys.stdout.write(f"\033[2J\033[H{header}\n\033[{height + 1};{rows}r\033[{height + 1};1H")
    sys.stdout.flush()


def unpin():
    """Restores normal scrolling and leaves the banner on screen."""
    if sys.stdout.isatty():
        rows = os.get_terminal_size().lines
        sys.stdout.write(f"\033[r\033[{rows};1H\n")
        sys.stdout.flush()


if __name__ == "__main__":
    {"--pin": pin, "--unpin": unpin}.get(sys.argv[1] if len(sys.argv) > 1 else "", show)()
