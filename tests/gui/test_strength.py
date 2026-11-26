"""The password strength estimate behind the meter (no Qt needed)."""

import pytest

from filecrypt.gui.strength import LABELS, estimate


@pytest.mark.parametrize("pw", ["", "password", "Password1!", "qwertyuiop", "123456789012",
                                "aaaaaaaaaaaaaaaa", "abcdefghijklmnop", "Summer2024!"])
def test_weak_passwords_score_low(pw):
    assert estimate(pw).score <= 1


@pytest.mark.parametrize("pw", ["copper lantern violet harbor", "xK9#mQ2$vL7@pR4!",
                                "correct-horse-battery-staple"])
def test_strong_passwords_score_high(pw):
    assert estimate(pw).score >= 3


def test_short_passwords_capped_and_hinted():
    s = estimate("xK9#mQ2$")
    assert s.score <= 2
    assert any("12 characters" in h for h in s.hints)
    assert estimate("xK9#mQ").score <= 1


def test_longer_is_stronger():
    assert estimate("tulip").bits < estimate("tulip river").bits < estimate("tulip river 7Qz!").bits


def test_label_matches_score():
    for pw in ["", "abc", "j8Fk2pLq", "copper lantern violet harbor"]:
        s = estimate(pw)
        assert s.label == LABELS[s.score]


def test_repeated_chunks_are_penalised():
    assert estimate("hellohellohello").score < estimate("hellojumpwindow").score
