"""Balanced-delimiter scanning for JavaScript/TypeScript source.

Shared by the extractor and the call graph so both agree on where a call,
an object literal, or a function body ends. Getting this wrong is subtle and
silent: an apostrophe inside a `// doesn't` comment reads as an unterminated
string, and the scan swallows the rest of the file. String and comment state
is therefore tracked here once, rather than approximated in two places.
"""

from __future__ import annotations


def balanced_delimited(text: str, start: int, opener: str, closer: str) -> str:
    """Return one balanced JS/TS delimited span, aware of strings/comments."""
    if start < 0 or start >= len(text) or text[start] != opener:
        return ""
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return ""
