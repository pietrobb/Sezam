"""Internationalization for Sezam.

Supported languages:
  sk - Slovak
  en - English
  de - German
  cs - Czech
  pl - Polish
  hu - Hungarian
  ru - Russian
  zh - Chinese (Simplified)
  ja - Japanese
  fr - French
  es - Spanish
  pt-BR - Portuguese (Brazil)
  pt - Portuguese (Portugal)
"""

from __future__ import annotations

import locale
import os

_current_lang: str = "en"
_strings: dict[str, str] = {}

SUPPORTED_LANGUAGES = {
    "sk": "Slovensky",
    "en": "English",
    "de": "Deutsch",
    "cs": "Cesky",
    "pl": "Polski",
    "hu": "Magyar",
    "ru": "Pyccku\u0439",
    "zh": "\u4e2d\u6587",
    "ja": "\u65e5\u672c\u8a9e",
    "fr": "Fran\u00e7ais",
    "es": "Espa\u00f1ol",
    "pt-BR": "Portugu\u00eas (Brasil)",
    "pt": "Portugu\u00eas",
}


def set_language(lang: str) -> None:
    """Set the active language and load its strings."""
    global _current_lang, _strings
    if lang not in SUPPORTED_LANGUAGES:
        lang = "en"
    _current_lang = lang
    from . import strings
    _strings = getattr(strings, f"STRINGS_{lang.replace('-', '_')}", strings.STRINGS_en)


def get_language() -> str:
    return _current_lang


def t(key: str) -> str:
    """Translate a string key. Falls back to English, then to the key itself."""
    val = _strings.get(key)
    if val is not None:
        return val
    # Fallback to English
    from . import strings
    val = strings.STRINGS_en.get(key)
    if val is not None:
        return val
    return key


def detect_system_language() -> str:
    """Detect system language, return best match from supported."""
    env_lang = os.environ.get("SEZAM_LANG")
    if env_lang and env_lang in SUPPORTED_LANGUAGES:
        return env_lang

    try:
        sys_locale = locale.getdefaultlocale()[0] or ""
    except Exception:
        sys_locale = ""

    # Try exact match (e.g. pt_BR -> pt-BR)
    normalized = sys_locale.replace("_", "-")
    if normalized in SUPPORTED_LANGUAGES:
        return normalized

    # Try language prefix (e.g. sk_SK -> sk)
    prefix = sys_locale.split("_")[0].split("-")[0].lower()
    if prefix in SUPPORTED_LANGUAGES:
        return prefix

    return "en"


# Auto-detect on import
set_language(detect_system_language())
