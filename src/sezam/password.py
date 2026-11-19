"""Password generator.

Generates cryptographically random passwords with configurable length and character sets.
"""

from __future__ import annotations

import math
import os
import re
import string


# Character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"

# Ambiguous characters (optionally excluded)
AMBIGUOUS = "0OIl1|"


def generate_password(
    length: int = 20,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a cryptographically random password.

    Args:
        length: Password length (default 20).
        uppercase: Include uppercase letters.
        lowercase: Include lowercase letters.
        digits: Include digits.
        symbols: Include symbols.
        exclude_ambiguous: Exclude ambiguous characters (0, O, I, l, 1, |).

    Returns:
        Generated password string.
    """
    charset = ""
    required: list[str] = []

    if lowercase:
        charset += LOWERCASE
        required.append(LOWERCASE)
    if uppercase:
        charset += UPPERCASE
        required.append(UPPERCASE)
    if digits:
        charset += DIGITS
        required.append(DIGITS)
    if symbols:
        charset += SYMBOLS
        required.append(SYMBOLS)

    if not charset:
        raise ValueError("At least one character set must be enabled")

    if exclude_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS)
        required = [
            "".join(c for c in r if c not in AMBIGUOUS) for r in required
        ]
        required = [r for r in required if r]

    if length < len(required):
        length = len(required)

    # Generate password ensuring at least one char from each required set
    while True:
        pwd = _random_string(charset, length)
        # Verify all required character sets are represented
        if all(any(c in req for c in pwd) for req in required):
            return pwd


def generate_passphrase(
    word_count: int = 8,
    separator: str = "-",
    wordlist: list[str] | None = None,
) -> str:
    """Generate a random passphrase from a wordlist.

    Args:
        word_count: Number of words (default 8: ~64 bits with the built-in list).
        separator: Word separator (default '-').
        wordlist: Custom wordlist (default: EFF short wordlist subset).

    Returns:
        Generated passphrase string.
    """
    if wordlist is None:
        wordlist = _DEFAULT_WORDLIST

    words = []
    for _ in range(word_count):
        idx = int.from_bytes(os.urandom(4), "big") % len(wordlist)
        words.append(wordlist[idx])

    return separator.join(words)


def estimate_strength(password: str) -> dict:
    """Estimate password strength.

    Returns dict with: score (0-4), entropy_bits, feedback.
    """
    charset_size = 0
    if any(c in LOWERCASE for c in password):
        charset_size += 26
    if any(c in UPPERCASE for c in password):
        charset_size += 26
    if any(c in DIGITS for c in password):
        charset_size += 10
    if any(c in SYMBOLS for c in password):
        charset_size += len(SYMBOLS)

    entropy = len(password) * math.log2(max(charset_size, 1)) if charset_size else 0
    # A passphrase is a handful of dictionary picks, not len(text) random
    # letters: 5 words of our list are ~40 bits, not ~140.
    words = [w for w in re.split(r"[^A-Za-z]+", password.lower()) if w]
    if len(words) >= 2 and all(w in _WORDSET for w in words):
        entropy = min(entropy, len(words) * math.log2(len(_DEFAULT_WORDLIST)))

    if entropy >= 80:
        score, label = 4, "Very Strong"
    elif entropy >= 60:
        score, label = 3, "Strong"
    elif entropy >= 40:
        score, label = 2, "Moderate"
    elif entropy >= 20:
        score, label = 1, "Weak"
    else:
        score, label = 0, "Very Weak"

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy, 1),
        "length": len(password),
    }


def _random_string(charset: str, length: int) -> str:
    """Generate a random string from charset using os.urandom."""
    result = []
    for _ in range(length):
        idx = int.from_bytes(os.urandom(4), "big") % len(charset)
        result.append(charset[idx])
    return "".join(result)


# Minimal default wordlist (for passphrase generation)
_DEFAULT_WORDLIST = [
    "able", "acid", "aged", "also", "area", "army", "away", "baby", "back", "ball",
    "band", "bank", "base", "bath", "bear", "beat", "been", "bell", "belt", "best",
    "bill", "bird", "bite", "blow", "blue", "boat", "body", "bomb", "bond", "bone",
    "book", "boot", "born", "boss", "both", "burn", "bush", "busy", "call", "calm",
    "came", "camp", "card", "care", "case", "cash", "cast", "cave", "cell", "chat",
    "chip", "city", "club", "coal", "coat", "code", "cold", "come", "cook", "cool",
    "cope", "copy", "core", "cost", "crew", "crop", "dark", "data", "date", "dawn",
    "dead", "deal", "dear", "debt", "deep", "deny", "desk", "diet", "dirt", "dish",
    "disk", "does", "done", "door", "dose", "down", "draw", "drew", "drop", "drug",
    "drum", "dual", "duke", "dump", "dust", "duty", "each", "earn", "ease", "east",
    "easy", "edge", "else", "even", "ever", "evil", "exam", "exit", "face", "fact",
    "fail", "fair", "fall", "fame", "farm", "fast", "fate", "fear", "feed", "feel",
    "fell", "file", "fill", "film", "find", "fine", "fire", "firm", "fish", "five",
    "flat", "flew", "flow", "folk", "food", "foot", "ford", "form", "fort", "four",
    "free", "from", "fuel", "full", "fund", "gain", "game", "gang", "gate", "gave",
    "gear", "gene", "gift", "girl", "give", "glad", "goal", "goes", "gold", "golf",
    "gone", "good", "grab", "gray", "grew", "grey", "grip", "grow", "gulf", "guru",
    "hair", "half", "hall", "hand", "hang", "hard", "harm", "hate", "have", "head",
    "hear", "heat", "held", "hell", "help", "here", "hero", "high", "hill", "hint",
    "hire", "hold", "hole", "holy", "home", "hope", "host", "hour", "huge", "hung",
    "hunt", "hurt", "idea", "inch", "into", "iron", "item", "jack", "jane", "jean",
    "john", "join", "joke", "jump", "june", "jury", "just", "keen", "keep", "kent",
    "kept", "kick", "kill", "kind", "king", "knee", "knew", "knit", "know", "lack",
    "lady", "laid", "lake", "land", "lane", "last", "late", "lead", "left", "lend",
    "less", "life", "lift", "like", "limb", "line", "link", "list", "live", "load",
    "loan", "lock", "lone", "long", "look", "lord", "lose", "loss", "lost", "love",
]
_WORDSET = frozenset(_DEFAULT_WORDLIST)
