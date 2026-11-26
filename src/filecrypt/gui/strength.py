"""A small, dependency-free password strength estimate for the strength meter.

This is a guide for people choosing a password, not a security guarantee. It
estimates how many guesses an attacker would need by looking at length and
character variety, and then discounts what attackers try first: common
passwords, repeated characters, keyboard runs and sequences like ``1234``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")

# Bits of estimated entropy needed for each score (0..4).
_THRESHOLDS = (28, 40, 60, 80)

# A short list of passwords attackers always try first. Matching is done on
# the lower-cased password with digits and symbols stripped from the ends.
_COMMON = frozenset("""
password passw0rd letmein welcome qwerty qwertyuiop asdf asdfgh asdfghjkl
zxcvbn iloveyou admin administrator login master monkey dragon football
baseball sunshine princess shadow superman batman trustno1 abc abcdef
abcdefg secret changeme default guest hello freedom whatever starwars
computer internet michael jennifer jordan hunter killer pokemon cheese
summer winter autumn spring flower orange banana chocolate password1
""".split())

_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1qaz2wsx3edc", "qazwsxedc",
)


@dataclass(frozen=True)
class Strength:
    score: int          # 0 (very weak) .. 4 (very strong)
    bits: float         # rough entropy estimate
    label: str
    hints: List[str]


def _pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[ !-/:-@\[-`{-~]", pw):
        pool += 33
    if any(ord(c) > 127 for c in pw):
        pool += 100
    return max(pool, 1)


def _predictable_chars(pw: str) -> int:
    """Count characters that are part of a repeat or a sequence of 3 or more."""
    low = pw.lower()
    flagged = [False] * len(low)
    # runs of the same character: "aaaa"
    for m in re.finditer(r"(.)\1{2,}", low):
        for i in range(m.start() + 1, m.end()):
            flagged[i] = True
    # forward or backward sequences: "abcd", "4321", "qwer"
    for seq in _SEQUENCES:
        for s in (seq, seq[::-1]):
            for length in range(len(s), 2, -1):
                for start in range(len(s) - length + 1):
                    part = s[start:start + length]
                    i = low.find(part)
                    while i != -1:
                        for j in range(i + 1, i + length):
                            flagged[j] = True
                        i = low.find(part, i + 1)
    # repeated chunks: "abcabcabc", "hellohello"
    m = re.fullmatch(r"(.{2,}?)\1+", low)
    if m:
        for i in range(len(m.group(1)), len(low)):
            flagged[i] = True
    return sum(flagged)


def estimate(password: str) -> Strength:
    """Estimate the strength of ``password``."""
    if not password:
        return Strength(0, 0.0, LABELS[0], ["Type a password."])

    hints: List[str] = []
    core = re.sub(r"^[\W\d_]+|[\W\d_]+$", "", password.lower())
    if password.lower() in _COMMON or core in _COMMON:
        return Strength(0, 0.0, LABELS[0], ["This is one of the first passwords attackers try."])

    pool = _pool_size(password)
    predictable = _predictable_chars(password)
    effective = len(password) - predictable + min(predictable, 2) * 0.5
    bits = effective * math.log2(pool)

    # Several words separated by spaces or dashes are a good passphrase even
    # in lower case; credit about 11 bits per word (a 2000-word vocabulary).
    words = [w for w in re.split(r"[\s\-_.,]+", password) if len(w) >= 3]
    if len(words) >= 3:
        bits = max(bits, len(words) * 11 + (len(password) - sum(map(len, words))) * 1.0)

    score = sum(bits >= t for t in _THRESHOLDS)
    if len(password) < 12:
        score = min(score, 1 if len(password) < 8 else 2)
        hints.append("Use at least 12 characters.")
    if predictable > len(password) // 3:
        hints.append("Avoid repeats and sequences like 1234 or qwerty.")
    if score < 3 and len(words) < 3:
        hints.append("A few random words, like “copper lantern violet harbor”, are strong and easy to remember.")
    return Strength(score, round(bits, 1), LABELS[score], hints)
