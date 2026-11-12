"""DNS name signals: very long labels, random-looking labels (entropy) and
look-alikes of well-known names (edit distance).
"""

import math

from scoring.config import (ENTROPY_MIN_LENGTH, ENTROPY_THRESHOLD,
    LONG_LABEL_LENGTH, LOOKALIKE_MAX_DISTANCE, WEIGHT_LOOKALIKE,
    WEIGHT_ODD_DNS_LABEL)


def entropy(text):
    """Shannon entropy in bits per character. Empty text gives 0.0."""
    if text == "":
        return 0.0
    total = len(text)
    result = 0.0
    for character in set(text):
        share = text.count(character) / total
        result -= share * math.log2(share)
    return result


def levenshtein(a, b):
    """Fewest single-character edits (insert, delete, replace) from a to b."""
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current.append(min(previous[j] + 1,
                               current[j - 1] + 1,
                               previous[j - 1] + cost))
        previous = current
    return previous[len(b)]


def dns_signals(name, well_known):
    """A very long or high-entropy label, and a lookalike of a well-known
    name. The lookalike check compares the last two labels and ignores real
    well-known names and their subdomains.
    """
    signals = []
    labels = name.split(".")

    for label in labels:
        if len(label) >= LONG_LABEL_LENGTH:
            signals.append((WEIGHT_ODD_DNS_LABEL,
                            "very long label (%d characters)" % len(label)))
            break
        if len(label) >= ENTROPY_MIN_LENGTH and entropy(label) >= ENTROPY_THRESHOLD:
            signals.append((WEIGHT_ODD_DNS_LABEL,
                            "high-entropy label (%s)" % label))
            break

    genuine = any(name == known or name.endswith("." + known)
                  for known in well_known)
    if not genuine:
        registered = ".".join(labels[-2:])
        for known in well_known:
            if levenshtein(registered, known) <= LOOKALIKE_MAX_DISTANCE:
                signals.append((WEIGHT_LOOKALIKE,
                                "looks like %s" % known))
                break
    return signals
