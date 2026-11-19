"""Auto-type — simulate keyboard input for credentials.

Phase 4: Types username/password into focused application.
Sequence: {username}{TAB}{password}{ENTER}
Delay between keystrokes prevents detection issues.
"""

from __future__ import annotations

import platform
import re
import subprocess
import time


DEFAULT_SEQUENCE = "{username}\t{password}\n"
KEYSTROKE_DELAY = 0.02  # 20ms between keystrokes


def autotype(
    fields: dict[str, str],
    sequence: str = DEFAULT_SEQUENCE,
    delay: float = KEYSTROKE_DELAY,
    initial_delay: float = 0.5,
) -> bool:
    """Type credentials into the currently focused window.

    Args:
        fields: Dict of field values (e.g., {'username': 'admin', 'password': 'secret'})
        sequence: Template string with {field_name}, \\t for Tab, \\n for Enter
        delay: Delay between keystrokes in seconds
        initial_delay: Wait before starting to type (switch window time)

    Returns:
        True if autotype succeeded.
    """
    # Build the full text to type
    text = sequence
    for key, value in fields.items():
        text = text.replace("{" + key + "}", value)

    # Remove unreplaced placeholders
    text = re.sub(r"\{[^}]+\}", "", text)

    time.sleep(initial_delay)

    system = platform.system()

    if system == "Windows":
        return _autotype_windows(text, delay)
    elif system == "Darwin":
        return _autotype_macos(text, delay)
    elif system == "Linux":
        return _autotype_linux(text, delay)

    return False


def _autotype_windows(text: str, delay: float) -> bool:
    """Windows auto-type using SendInput via ctypes."""
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32

        INPUT_KEYBOARD = 1
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002
        VK_TAB = 0x09
        VK_RETURN = 0x0D

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
            ]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("ki", KEYBDINPUT)]
            _fields_ = [
                ("type", wintypes.DWORD),
                ("_input", _INPUT),
            ]

        for char in text:
            if char == "\t":
                _send_vk(user32, INPUT, KEYBDINPUT, INPUT_KEYBOARD, VK_TAB, KEYEVENTF_KEYUP)
            elif char == "\n":
                _send_vk(user32, INPUT, KEYBDINPUT, INPUT_KEYBOARD, VK_RETURN, KEYEVENTF_KEYUP)
            else:
                # Unicode character
                inp = INPUT()
                inp.type = INPUT_KEYBOARD
                inp._input.ki.wVk = 0
                inp._input.ki.wScan = ord(char)
                inp._input.ki.dwFlags = KEYEVENTF_UNICODE
                user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

                inp._input.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
                user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

            time.sleep(delay)

        return True
    except Exception:
        return False


def _send_vk(user32, INPUT, KEYBDINPUT, INPUT_KEYBOARD, vk, KEYEVENTF_KEYUP):
    """Send a virtual key press + release."""
    import ctypes
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    inp._input.ki.wVk = vk
    inp._input.ki.wScan = 0
    inp._input.ki.dwFlags = 0
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

    inp._input.ki.dwFlags = KEYEVENTF_KEYUP
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def _autotype_macos(text: str, delay: float) -> bool:
    """macOS auto-type using osascript."""
    try:
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        escaped = escaped.replace("\t", "\\t").replace("\n", "\\n")
        script = f'tell application "System Events" to keystroke "{escaped}"'
        # Script via stdin: argv is visible to every local user (ps).
        subprocess.run(["osascript", "-"], input=script.encode("utf-8"), check=True, timeout=10)
        return True
    except Exception:
        return False


def _autotype_linux(text: str, delay: float) -> bool:
    """Linux auto-type using xdotool."""
    try:
        # Split on Tab and Enter, type each segment with xdotool key presses between
        for part in re.split(r"(\t|\n)", text):
            if part == "\t":
                subprocess.run(["xdotool", "key", "Tab"], check=True, timeout=5)
            elif part == "\n":
                subprocess.run(["xdotool", "key", "Return"], check=True, timeout=5)
            elif part:
                # Text via stdin: argv is visible to every local user (ps).
                subprocess.run(
                    ["xdotool", "type", "--delay", str(int(delay * 1000)), "--file", "-"],
                    input=part.encode("utf-8"), check=True, timeout=10,
                )
        return True
    except Exception:
        return False
