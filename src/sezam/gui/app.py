"""GUI application entry point.

Spec 7.1: Systray + Ctrl+Alt+V global hotkey to bring up vault window.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .styles import GLOBAL_STYLE

logger = logging.getLogger(__name__)


class _HotkeySignalBridge(QObject):
    """Bridge between hotkey thread and Qt main thread via signal."""
    activated = Signal()


def _register_global_hotkey_win32(bridge: _HotkeySignalBridge) -> None:
    """Register Ctrl+Alt+V global hotkey on Windows using Win32 API.

    Runs in a background thread since GetMessage is blocking.
    """
    import ctypes
    import ctypes.wintypes

    MOD_CONTROL = 0x0002
    MOD_ALT = 0x0001
    VK_V = 0x56
    HOTKEY_ID = 1
    WM_HOTKEY = 0x0312

    def _hotkey_thread():
        try:
            user32 = ctypes.windll.user32
            result = user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_ALT, VK_V)
            if not result:
                logger.warning("Failed to register global hotkey Ctrl+Alt+V (already registered?)")
                return

            logger.info("Global hotkey Ctrl+Alt+V registered")
            msg = ctypes.wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID:
                    bridge.activated.emit()
        except Exception as e:
            logger.debug("Win32 hotkey thread error: %s", e)

    thread = threading.Thread(target=_hotkey_thread, daemon=True)
    thread.start()


def _register_global_hotkey_pynput(bridge: _HotkeySignalBridge) -> None:
    """Register Ctrl+Alt+V global hotkey using pynput (Linux/macOS)."""
    from pynput import keyboard

    COMBO = {keyboard.Key.ctrl_l, keyboard.Key.alt_l, keyboard.KeyCode.from_char('v')}
    current_keys = set()

    def on_press(key):
        current_keys.add(key)
        if COMBO.issubset(current_keys):
            bridge.activated.emit()

    def on_release(key):
        current_keys.discard(key)

    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.daemon = True
    listener.start()
    logger.info("Global hotkey Ctrl+Alt+V registered (pynput)")


def register_global_hotkey(window: MainWindow) -> None:
    """Register system-wide Ctrl+Alt+V hotkey to show/focus the main window.

    Platform support:
      - Windows: ctypes win32 RegisterHotKey
      - Linux/macOS: pynput keyboard listener
      - Fallback: silently skip if platform not supported
    """
    bridge = _HotkeySignalBridge()
    bridge.activated.connect(window.show_and_activate)
    # Keep reference alive
    window._hotkey_bridge = bridge

    try:
        if sys.platform == "win32":
            _register_global_hotkey_win32(bridge)
        else:
            _register_global_hotkey_pynput(bridge)
    except ImportError:
        logger.debug("Global hotkey not available (missing dependency)")
    except Exception as e:
        logger.debug("Global hotkey registration failed: %s", e)


def run_gui():
    """Launch Sezam desktop application."""
    vault_path = Path(os.environ.get("SEZAM_VAULT", Path.home() / ".sezam"))

    app = QApplication(sys.argv)
    app.setApplicationName("Sezam")
    app.setOrganizationName("Sezam")
    app.setQuitOnLastWindowClosed(False)
    app.setStyleSheet(GLOBAL_STYLE)

    window = MainWindow(vault_path)
    window.check_or_create_vault()

    # Only show if vault was actually unlocked (user didn't cancel)
    if not window._vault or not window._vault.is_unlocked:
        sys.exit(0)

    window.show()

    # Register global hotkey Ctrl+Alt+V (spec 7.1)
    register_global_hotkey(window)

    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
