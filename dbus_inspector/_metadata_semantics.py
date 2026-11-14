"""Read-only explanations of D-Bus introspection metadata; no bus operations."""

from __future__ import annotations

_BASIC_TYPES = {
    "y": "Byte", "b": "Boolean", "n": "16-bit signed integer",
    "q": "16-bit unsigned integer", "i": "32-bit signed integer",
    "u": "32-bit unsigned integer", "x": "64-bit signed integer",
    "t": "64-bit unsigned integer", "d": "Double-precision float",
    "s": "String", "o": "Object path", "g": "Type signature",
    "h": "UNIX file descriptor", "v": "Variant",
}


def explain_signature(signature: str) -> str:
    """Explain a complete D-Bus type sequence without discarding raw notation.

    Non-conforming/unsupported signatures are explicitly marked unrecognised.
    The original signature remains visible in the caller's Metadata Details.
    """
    text = str(signature or "")
    if not text or text == "—":
        return "None"
    if len(text) > 255:
        return "Unrecognised type signature"
    pos = 0

    def parse_type(depth: int = 0, in_array: bool = False) -> str:
        nonlocal pos
        if depth > 32 or pos >= len(text):
            raise ValueError("incomplete signature")
        char = text[pos]
        pos += 1
        if char in _BASIC_TYPES:
            return _BASIC_TYPES[char]
        if char == "a":
            return f"Array of {parse_type(depth + 1, True)}"
        if char == "(":
            parts = []
            while pos < len(text) and text[pos] != ")":
                parts.append(parse_type(depth + 1))
            if not parts or pos == len(text):
                raise ValueError("incomplete struct")
            pos += 1
            return "Structure (" + ", ".join(parts) + ")"
        if char == "{":
            if not in_array or pos >= len(text) or text[pos] not in "ybnqiuxtdsog":
                raise ValueError("invalid dictionary key")
            key = parse_type(depth + 1)
            val = parse_type(depth + 1)
            if pos >= len(text) or text[pos] != "}":
                raise ValueError("incomplete dictionary entry")
            pos += 1
            return f"Dictionary ({key} to {val})"
        raise ValueError("unknown type code")

    try:
        decoded = []
        while pos < len(text):
            decoded.append(parse_type())
        return ", ".join(decoded)
    except ValueError:
        return "Unrecognised type signature"


def signature_detail(signature: str) -> str:
    """Show raw notation beside its decoded meaning; never replace evidence."""
    text = str(signature or "")
    if not text or text == "—":
        return "None"
    return f"{text} — {explain_signature(text)}"


def annotation_explanation(name: str, value: str) -> str:
    """Interpret only known standard annotations with well-defined values."""
    name = str(name or "")
    value = str(value or "")
    if name == "org.freedesktop.DBus.Deprecated":
        return {"true": "Declared deprecated", "false": "Declared not deprecated"}.get(value, "")
    if name == "org.freedesktop.DBus.Method.NoReply":
        return {"true": "Caller does not expect a method reply", "false": "Method reply expected"}.get(value, "")
    if name == "org.freedesktop.DBus.Property.EmitsChangedSignal":
        return {
            "true": "Declares PropertiesChanged with the new value on changes",
            "false": "Does not declare change notifications",
            "invalidates": "PropertiesChanged signals invalidation rather than a new value",
            "const": "Declared constant during the object's lifetime",
        }.get(value, "")
    return ""
