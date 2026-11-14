#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Direct, read-only D-Bus acquisition for LinSpectacles D-Bus Inspector.

The transport uses libsystemd sd-bus directly.  It intentionally exposes only
bus-manager inventory calls, Introspect, and a single explicit Properties.Get.
It never invokes arbitrary application methods, Properties.Set, GetAll,
StartServiceByName, BecomeMonitor, or service activation controls.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from pathlib import Path
from typing import Any
from datetime import datetime
from xml.etree import ElementTree as ET

BUS_SERVICE = b"org.freedesktop.DBus"
BUS_PATH = b"/org/freedesktop/DBus"
BUS_IFACE = b"org.freedesktop.DBus"
INTROSPECT_IFACE = b"org.freedesktop.DBus.Introspectable"
PROPERTIES_IFACE = b"org.freedesktop.DBus.Properties"
MAX_INTROSPECTION_XML = 4 * 1024 * 1024
MAX_RENDER_CHARS = 20_000
MAX_RENDER_ITEMS = 1_000
MAX_RENDER_DEPTH = 8


class DBusInspectorError(RuntimeError):
    def __init__(self, message: str, *, name: str = "", code: int | None = None):
        super().__init__(message)
        self.name = name
        self.code = code

    @property
    def vanished(self) -> bool:
        marker = f"{self.name} {self}".lower()
        return any(token in marker for token in (
            "namehasnoowner", "serviceunknown", "unknownobject", "unknown object",
            "no such object", "disconnected", "connection reset",
        ))

    @property
    def permission_denied(self) -> bool:
        marker = f"{self.name} {self}".lower()
        return "accessdenied" in marker or "permission" in marker or "not authorized" in marker


class _SdBusError(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("message", ctypes.c_char_p),
        ("_need_free", ctypes.c_int),
    ]


def _decode_cstr(value: bytes | None) -> str:
    return value.decode("utf-8", "replace") if value else ""


def _join_object_path(parent: str, child: str) -> str:
    child = str(child or "").strip()
    if not child:
        return parent or "/"
    if child.startswith("/"):
        return child
    if not parent or parent == "/":
        return "/" + child
    return parent.rstrip("/") + "/" + child


def _annotations(element: ET.Element) -> list[dict[str, str]]:
    out = []
    for ann in element.findall("annotation"):
        out.append({"name": ann.get("name", ""), "value": ann.get("value", "")})
    return out


def parse_introspection_xml(xml_text: str, object_path: str = "/") -> dict[str, Any]:
    """Parse D-Bus introspection XML without acquiring any additional state."""
    encoded = xml_text.encode("utf-8", "replace")
    if len(encoded) > MAX_INTROSPECTION_XML:
        raise DBusInspectorError(
            f"Introspection document is too large ({len(encoded):,} bytes; limit {MAX_INTROSPECTION_XML:,})."
        )
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise DBusInspectorError(f"Malformed introspection XML: {exc}") from exc
    if root.tag != "node":
        raise DBusInspectorError(f"Unexpected introspection root element: {root.tag!r}")

    interfaces = []
    for iface in root.findall("interface"):
        interface = {
            "name": iface.get("name", ""),
            "annotations": _annotations(iface),
            "methods": [],
            "properties": [],
            "signals": [],
        }
        for method in iface.findall("method"):
            args = []
            for arg in method.findall("arg"):
                args.append({
                    "name": arg.get("name", ""),
                    "type": arg.get("type", ""),
                    "direction": arg.get("direction", "in") or "in",
                    "annotations": _annotations(arg),
                })
            interface["methods"].append({
                "kind": "Method",
                "name": method.get("name", ""),
                "args": args,
                "annotations": _annotations(method),
            })
        for prop in iface.findall("property"):
            interface["properties"].append({
                "kind": "Property",
                "name": prop.get("name", ""),
                "type": prop.get("type", ""),
                "access": prop.get("access", ""),
                "annotations": _annotations(prop),
            })
        for signal in iface.findall("signal"):
            args = []
            for arg in signal.findall("arg"):
                args.append({
                    "name": arg.get("name", ""),
                    "type": arg.get("type", ""),
                    "annotations": _annotations(arg),
                })
            interface["signals"].append({
                "kind": "Signal",
                "name": signal.get("name", ""),
                "args": args,
                "annotations": _annotations(signal),
            })
        interfaces.append(interface)

    children = []
    for node in root.findall("node"):
        name = node.get("name", "")
        if name:
            children.append({"name": name, "path": _join_object_path(object_path, name)})

    return {
        "path": object_path,
        "interfaces": interfaces,
        "children": children,
        "annotations": _annotations(root),
        "xml": xml_text,
    }


def method_signature(member: dict[str, Any]) -> str:
    inputs = "".join(a.get("type", "") for a in member.get("args", []) if a.get("direction") != "out")
    outputs = "".join(a.get("type", "") for a in member.get("args", []) if a.get("direction") == "out")
    if inputs and outputs:
        return f"{inputs} → {outputs}"
    if inputs:
        return inputs
    if outputs:
        return f"→ {outputs}"
    return "—"


def signal_signature(member: dict[str, Any]) -> str:
    sig = "".join(a.get("type", "") for a in member.get("args", []))
    return sig or "—"


def property_value_safe(signature: str) -> tuple[bool, str]:
    """Conservatively exclude values that can carry UNIX_FD through h/variant containers."""
    signature = str(signature or "")
    if "h" in signature:
        return False, "UNIX_FD transfer excluded"
    if "v" in signature:
        return False, "Variant value may contain UNIX_FD; explicit value read excluded"
    return True, ""


def _render(value: Any, depth: int, counter: list[int]) -> str:
    if depth > MAX_RENDER_DEPTH:
        return "… (depth limit)"
    if counter[0] >= MAX_RENDER_ITEMS:
        return "… (item limit)"
    counter[0] += 1
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        parts = []
        for i, (key, val) in enumerate(value.items()):
            if i >= MAX_RENDER_ITEMS:
                parts.append("…")
                break
            parts.append(f"{_render(key, depth+1, counter)}: {_render(val, depth+1, counter)}")
        return "{" + ", ".join(parts) + "}"
    if isinstance(value, tuple):
        return "(" + ", ".join(_render(v, depth+1, counter) for v in value) + ")"
    if isinstance(value, list):
        return "[" + ", ".join(_render(v, depth+1, counter) for v in value[:MAX_RENDER_ITEMS]) + (", …" if len(value) > MAX_RENDER_ITEMS else "") + "]"
    return repr(value)


def format_dbus_value(value: Any, signature: str = "") -> str:
    if signature == "ay" and isinstance(value, list) and all(isinstance(v, int) and 0 <= v <= 255 for v in value):
        data = bytes(value)
        printable = data.rstrip(b"\0")
        try:
            text = printable.decode("utf-8")
            if text and all(ch.isprintable() or ch in "\t\r\n" for ch in text):
                return repr(text)
        except UnicodeDecodeError:
            pass
        preview = data[:64].hex(" ")
        return f"bytes[{len(data)}] {preview}" + (" …" if len(data) > 64 else "")
    text = _render(value, 0, [0])
    if len(text) > MAX_RENDER_CHARS:
        return text[:MAX_RENDER_CHARS] + f"\n… (display truncated at {MAX_RENDER_CHARS:,} characters)"
    return text


class SdBusClient:
    """Synchronous direct sd-bus client constrained to read-only inspection calls."""

    def __init__(self, scope: str = "system", timeout_usec: int = 5_000_000):
        scope = str(scope).lower()
        if scope not in {"system", "session"}:
            raise ValueError("scope must be 'system' or 'session'")
        self.scope = scope
        library = ctypes.util.find_library("systemd") or "libsystemd.so.0"
        try:
            self.lib = ctypes.CDLL(library)
        except OSError as exc:
            raise DBusInspectorError(f"libsystemd is unavailable: {exc}") from exc
        self._configure()
        self.bus = ctypes.c_void_p()
        opener = self.lib.sd_bus_open_system if scope == "system" else self.lib.sd_bus_open_user
        rc = opener(ctypes.byref(self.bus))
        if rc < 0:
            raise DBusInspectorError(self._errno_text(rc), code=rc)
        if hasattr(self.lib, "sd_bus_set_method_call_timeout"):
            try:
                self.lib.sd_bus_set_method_call_timeout(self.bus, ctypes.c_uint64(int(timeout_usec)))
            except Exception:
                pass
        self.unique_name = self._get_unique_name()

    def _configure(self):
        L = self.lib
        for name in ("sd_bus_open_system", "sd_bus_open_user"):
            fn = getattr(L, name)
            fn.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
            fn.restype = ctypes.c_int
        L.sd_bus_unref.argtypes = [ctypes.c_void_p]
        L.sd_bus_unref.restype = ctypes.c_void_p
        L.sd_bus_message_unref.argtypes = [ctypes.c_void_p]
        L.sd_bus_message_unref.restype = ctypes.c_void_p
        L.sd_bus_error_free.argtypes = [ctypes.POINTER(_SdBusError)]
        L.sd_bus_error_free.restype = None
        L.sd_bus_message_peek_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char_p)]
        L.sd_bus_message_peek_type.restype = ctypes.c_int
        L.sd_bus_message_enter_container.argtypes = [ctypes.c_void_p, ctypes.c_char, ctypes.c_char_p]
        L.sd_bus_message_enter_container.restype = ctypes.c_int
        L.sd_bus_message_exit_container.argtypes = [ctypes.c_void_p]
        L.sd_bus_message_exit_container.restype = ctypes.c_int
        L.sd_bus_message_read_basic.argtypes = [ctypes.c_void_p, ctypes.c_char, ctypes.c_void_p]
        L.sd_bus_message_read_basic.restype = ctypes.c_int
        L.sd_bus_call_method.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.POINTER(_SdBusError), ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p,
        ]
        L.sd_bus_call_method.restype = ctypes.c_int
        if hasattr(L, "sd_bus_get_unique_name"):
            L.sd_bus_get_unique_name.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
            L.sd_bus_get_unique_name.restype = ctypes.c_int
        if hasattr(L, "sd_bus_set_method_call_timeout"):
            L.sd_bus_set_method_call_timeout.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
            L.sd_bus_set_method_call_timeout.restype = ctypes.c_int

    @staticmethod
    def _errno_text(rc: int) -> str:
        try:
            return os.strerror(abs(int(rc)))
        except Exception:
            return f"D-Bus error {rc}"

    def _get_unique_name(self) -> str:
        if not hasattr(self.lib, "sd_bus_get_unique_name"):
            return ""
        value = ctypes.c_char_p()
        rc = self.lib.sd_bus_get_unique_name(self.bus, ctypes.byref(value))
        return _decode_cstr(value.value) if rc >= 0 else ""

    def close(self):
        if getattr(self, "bus", None):
            self.lib.sd_bus_unref(self.bus)
            self.bus = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _call(self, destination: str, path: str, interface: str, member: str, signature: str | None = None, args: tuple[str, ...] = ()) -> Any:
        error = _SdBusError()
        reply = ctypes.c_void_p()
        fixed = (
            self.bus,
            destination.encode("utf-8"), path.encode("utf-8"), interface.encode("utf-8"), member.encode("utf-8"),
            ctypes.byref(error), ctypes.byref(reply),
        )
        if signature is None:
            rc = self.lib.sd_bus_call_method(*fixed, None)
        else:
            cargs = tuple(ctypes.c_char_p(str(arg).encode("utf-8")) for arg in args)
            rc = self.lib.sd_bus_call_method(*fixed, signature.encode("ascii"), *cargs)
        if rc < 0:
            name = _decode_cstr(error.name)
            message = _decode_cstr(error.message) or self._errno_text(rc)
            self.lib.sd_bus_error_free(ctypes.byref(error))
            if reply:
                self.lib.sd_bus_message_unref(reply)
            raise DBusInspectorError(message, name=name, code=rc)
        self.lib.sd_bus_error_free(ctypes.byref(error))
        try:
            return self._decode_message(reply)
        finally:
            self.lib.sd_bus_message_unref(reply)

    def _decode_message(self, message: ctypes.c_void_p) -> Any:
        values = []
        while True:
            present = self.lib.sd_bus_message_peek_type(message, None, None)
            if present < 0:
                raise DBusInspectorError(self._errno_text(present), code=present)
            if present == 0:
                break
            values.append(self._decode_one(message))
        return values[0] if len(values) == 1 else values

    def _peek(self, message):
        type_c = ctypes.c_char()
        contents = ctypes.c_char_p()
        rc = self.lib.sd_bus_message_peek_type(message, ctypes.byref(type_c), ctypes.byref(contents))
        if rc < 0:
            raise DBusInspectorError(self._errno_text(rc), code=rc)
        if rc == 0:
            return None, None
        return type_c.value.decode("ascii"), _decode_cstr(contents.value)

    def _read_basic(self, message, kind, out_ptr):
        rc = self.lib.sd_bus_message_read_basic(message, kind.encode("ascii"), out_ptr)
        if rc < 0:
            raise DBusInspectorError(self._errno_text(rc), code=rc)
        if rc == 0:
            raise DBusInspectorError(f"Missing D-Bus value of type {kind}")

    def _decode_one(self, message):
        kind, contents = self._peek(message)
        if kind is None:
            raise DBusInspectorError("Unexpected end of D-Bus message")
        if kind in {"a", "r", "e", "v", "(", "{"}:
            rc = self.lib.sd_bus_message_enter_container(
                message, kind.encode("ascii"), contents.encode("ascii") if contents else None
            )
            if rc < 0:
                raise DBusInspectorError(self._errno_text(rc), code=rc)
            children = []
            while True:
                present = self.lib.sd_bus_message_peek_type(message, None, None)
                if present < 0:
                    raise DBusInspectorError(self._errno_text(present), code=present)
                if present == 0:
                    break
                children.append(self._decode_one(message))
            rc = self.lib.sd_bus_message_exit_container(message)
            if rc < 0:
                raise DBusInspectorError(self._errno_text(rc), code=rc)
            if kind == "v":
                return children[0] if children else None
            if kind in {"r", "(", "e", "{"}:
                return tuple(children)
            if kind == "a":
                if children and all(isinstance(x, tuple) and len(x) == 2 for x in children) and (contents or "").startswith("{"):
                    return {str(k): v for k, v in children}
                return children
        if kind in {"s", "o", "g"}:
            value = ctypes.c_char_p(); self._read_basic(message, kind, ctypes.byref(value)); return _decode_cstr(value.value)
        if kind == "b":
            value = ctypes.c_int(); self._read_basic(message, kind, ctypes.byref(value)); return bool(value.value)
        if kind == "u":
            value = ctypes.c_uint32(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "i":
            value = ctypes.c_int32(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "t":
            value = ctypes.c_uint64(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "x":
            value = ctypes.c_int64(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "q":
            value = ctypes.c_uint16(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "n":
            value = ctypes.c_int16(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "y":
            value = ctypes.c_ubyte(); self._read_basic(message, kind, ctypes.byref(value)); return int(value.value)
        if kind == "d":
            value = ctypes.c_double(); self._read_basic(message, kind, ctypes.byref(value)); return float(value.value)
        # Intentionally no 'h' decoder.  The inspector avoids calls whose declared
        # payload can transfer UNIX_FD and never uses GetConnectionCredentials.
        raise DBusInspectorError(f"Unsupported/unsafe D-Bus value type {kind!r} ({contents})")

    # ---- Bus-manager inventory: no application service activation ------------
    def list_names(self) -> list[str]:
        value = self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames")
        return [str(x) for x in (value or [])]

    def list_activatable_names(self) -> list[str]:
        value = self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListActivatableNames")
        return [str(x) for x in (value or [])]

    def get_name_owner(self, name: str) -> str:
        value = self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", (name,))
        return str(value or "")

    def get_connection_pid(self, unique_name: str) -> int | None:
        try:
            return int(self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", (unique_name,)))
        except (DBusInspectorError, TypeError, ValueError):
            return None

    def get_connection_uid(self, unique_name: str) -> int | None:
        try:
            return int(self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixUser", "s", (unique_name,)))
        except (DBusInspectorError, TypeError, ValueError):
            return None

    def get_connection_security_label(self, unique_name: str) -> str:
        try:
            value = self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionSELinuxSecurityContext", "s", (unique_name,))
        except DBusInspectorError:
            return ""
        if isinstance(value, list) and all(isinstance(v, int) and 0 <= v <= 255 for v in value):
            return bytes(value).rstrip(b"\0").decode("utf-8", "replace")
        return format_dbus_value(value)

    def get_bus_id(self) -> str:
        try:
            return str(self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetId") or "")
        except DBusInspectorError:
            return ""

    # ---- Deep inspection: callers MUST pass an already-running unique owner ---
    def introspect(self, unique_owner: str, object_path: str) -> dict[str, Any]:
        if not str(unique_owner).startswith(":"):
            raise DBusInspectorError(
                "Deep introspection requires an already-running unique bus owner; well-known names are not used as destinations."
            )
        xml = self._call(unique_owner, object_path, "org.freedesktop.DBus.Introspectable", "Introspect")
        if not isinstance(xml, str):
            raise DBusInspectorError("Unexpected Introspect reply type")
        parsed = parse_introspection_xml(xml, object_path)
        parsed["acquired"] = datetime.now().astimezone().isoformat(timespec="seconds")
        return parsed

    def get_property(self, unique_owner: str, object_path: str, interface: str, prop: str, signature: str) -> Any:
        if not str(unique_owner).startswith(":"):
            raise DBusInspectorError("Property reads require an already-running unique bus owner.")
        safe, reason = property_value_safe(signature)
        if not safe:
            raise DBusInspectorError(reason)
        return self._call(
            unique_owner, object_path, "org.freedesktop.DBus.Properties", "Get", "ss", (interface, prop)
        )



def process_groups(pid: int | None) -> list[int]:
    if not pid or pid <= 0:
        return []
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Groups:"):
                out=[]
                for token in line.split(":",1)[1].split():
                    try: out.append(int(token))
                    except ValueError: pass
                return out
    except OSError:
        pass
    return []

def process_comm(pid: int | None) -> str:
    if not pid or pid <= 0:
        return ""
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


SPECIALISTS = {
    "org.freedesktop.systemd1": "Systemd Inspector",
    "org.freedesktop.login1": "Login Inspector",
    "org.freedesktop.resolve1": "Resolver Inspector",
    "org.freedesktop.PolicyKit1": "Polkit Inspector",
}


def specialist_for_name(name: str) -> str:
    return SPECIALISTS.get(str(name), "")


def name_inventory(client: SdBusClient) -> dict[str, Any]:
    owned = set(client.list_names())
    activatable = set(client.list_activatable_names())
    records = []
    owner_map: dict[str, str] = {}
    owned_by_unique: dict[str, list[str]] = {}

    for name in sorted(owned):
        if name.startswith(":"):
            owner_map[name] = name
            owned_by_unique.setdefault(name, [])
            continue
        if name == "org.freedesktop.DBus":
            owner_map[name] = ""
            continue
        try:
            owner = client.get_name_owner(name)
        except DBusInspectorError:
            owner = ""
        owner_map[name] = owner
        if owner.startswith(":"):
            owned_by_unique.setdefault(owner, []).append(name)

    all_names = sorted(owned | activatable)
    for name in all_names:
        if name == "org.freedesktop.DBus":
            kind = "Bus"
            state = "Owned"
            owner = ""
        elif name.startswith(":"):
            kind = "Unique"
            state = "Owned"
            owner = name
        else:
            kind = "Well-known"
            is_owned = name in owned
            is_act = name in activatable
            if is_owned and is_act:
                state = "Owned + Activatable"
            elif is_owned:
                state = "Owned"
            else:
                state = "Activatable"
            owner = owner_map.get(name, "")
        records.append({
            "name": name,
            "kind": kind,
            "state": state,
            "owner": owner,
            "specialist": specialist_for_name(name),
            "activatable": name in activatable,
            "owned": name in owned,
            "this_inspector": name == client.unique_name,
        })

    return {
        "records": records,
        "owner_map": owner_map,
        "owned_by_unique": owned_by_unique,
        "bus_id": client.get_bus_id(),
        "inspector_unique_name": client.unique_name,
        "acquired": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def connection_inventory(client: SdBusClient, names_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    owned_by_unique = names_snapshot.get("owned_by_unique", {})
    unique_names = sorted({
        r.get("name") for r in names_snapshot.get("records", []) if r.get("kind") == "Unique"
    })
    records = []
    for unique in unique_names:
        if not unique:
            continue
        pid = client.get_connection_pid(unique)
        uid = client.get_connection_uid(unique)
        names = sorted(owned_by_unique.get(unique, []))
        records.append({
            "unique": unique,
            "pid": pid if pid is not None else "",
            "uid": uid if uid is not None else "",
            "process": process_comm(pid),
            "group_ids": process_groups(pid),
            "owned_names": ", ".join(names),
            "owned_names_list": names,
            "this_inspector": unique == client.unique_name,
            "security_label": None,  # lazy on selected metadata
        })
    return records
