#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

from __future__ import annotations

APPLET_ID = "linspectacles-dbus-inspector"
APPLET_NAME = "D-Bus Inspector"
APPLET_VERSION = "0.0.9"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/dbus-inspector"

from pathlib import Path
from typing import Any
from datetime import datetime

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QRadioButton,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from ._support import (
    MetadataHighlighter, NumericTableWidgetItem, apply_metadata_font,
    export_records_dialog, metadata_font_from_string, metadata_font_qss,
)
from ._metadata_semantics import annotation_explanation, signature_detail
from .dbus_backend import (
    DBusInspectorError, SdBusClient, connection_inventory, format_dbus_value,
    method_signature, name_inventory, property_value_safe, signal_signature,
)


VIEW_COLUMNS = {
    "Names": [
        ("name", "Name", 330, "left"),
        ("kind", "Kind", 105, "left"),
        ("state", "State", 155, "left"),
        ("owner", "Owner", 115, "left"),
        ("specialist", "Specialist", 180, "left"),
    ],
    "Connections": [
        ("unique", "Unique Name", 125, "left"),
        ("pid", "PID", 90, "right"),
        ("uid", "UID", 90, "right"),
        ("process", "Process", 170, "left"),
        ("owned_names", "Owned Names", 420, "left"),
    ],
    "Objects": [
        ("display_path", "Object Path", 430, "left"),
        ("state", "State", 145, "left"),
        ("interfaces_count", "Interfaces", 90, "right"),
        ("children_count", "Children", 90, "right"),
    ],
    "Interfaces": [
        ("name", "Interface", 420, "left"),
        ("methods_count", "Methods", 85, "right"),
        ("properties_count", "Properties", 95, "right"),
        ("signals_count", "Signals", 85, "right"),
        ("annotations_count", "Annotations", 105, "right"),
    ],
    "Members": [
        ("kind", "Kind", 95, "left"),
        ("name", "Member", 270, "left"),
        ("signature", "Signature", 220, "left"),
        ("access", "Access", 105, "left"),
        ("value_state", "Value State", 190, "left"),
    ],
}

VIEW_FILTERS = {
    "Names": ["All Names", "Well-known", "Unique", "Owned", "Activatable"],
    "Connections": ["All Connections", "Owns well-known names", "This Inspector"],
}

PRIMARY_VIEWS = ("Names", "Connections")
TREE_COLUMNS = [("label", "Name / Path", 430), ("kind", "Type", 125), ("state", "State", 180)]

NUMERIC_BY_VIEW = {
    "Connections": {"pid", "uid"},
    "Objects": {"interfaces_count", "children_count"},
    "Interfaces": {"methods_count", "properties_count", "signals_count", "annotations_count"},
}


SPECIALIST_NOTES = {
    "Systemd Inspector": "D-Bus Inspector exposes the service's bus API; Systemd Inspector owns systemd unit/manager semantics.",
    "Login Inspector": "D-Bus Inspector exposes the login1 API; Login Inspector owns sessions, users and seats.",
    "Resolver Inspector": "D-Bus Inspector exposes the resolve1 API; Resolver Inspector owns DNS/resolver semantics.",
    "Polkit Inspector": "D-Bus Inspector exposes the PolicyKit bus API; a specialist Polkit Inspector can own authorization-policy semantics.",
}


def _source_canvas(owner):
    w = QTextEdit()
    w.setReadOnly(True)
    w.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    font = getattr(owner, "_metadata_font", None)
    if font is not None:
        w.setFont(font); w.document().setDefaultFont(font); w.setCurrentFont(font)
    font_rule = metadata_font_qss(font) if font is not None else ""
    w.setStyleSheet(
        "QTextEdit { " + font_rule + " background-color:#151719; color:#dcdcdc; border:1px solid #333333; }"
    )
    return w


def _append_source_group(widget, heading_text, lines):
    heading = QTextCharFormat(); heading.setForeground(QColor("#9cdcfe")); heading.setFontWeight(600)
    value = QTextCharFormat(); value.setForeground(QColor("#dcdcdc"))
    cursor = widget.textCursor(); cursor.movePosition(QTextCursor.MoveOperation.End)
    if cursor.position() > 0:
        cursor.insertText("\n", value)
    cursor.insertText(str(heading_text) + "\n", heading)
    for line in lines:
        cursor.insertText("  " + str(line) + "\n", value)
    widget.setTextCursor(cursor)


def _populate_sources(widget, owner):
    widget.clear()
    _append_source_group(widget, "MESSAGE BUS", [
        f"Selected bus: {owner.bus_scope.title()}",
        "Direct libsystemd sd-bus transport; busctl/gdbus/dbus-send are not data dependencies.",
        f"Inspector connection: {getattr(owner.client, 'unique_name', '') or 'Not connected'}",
        f"Bus ID: {(owner.names_snapshot or {}).get('bus_id', '') or 'Not acquired'}",
    ])
    _append_source_group(widget, "BUS INVENTORY", [
        "org.freedesktop.DBus.ListNames",
        "org.freedesktop.DBus.ListActivatableNames",
        "org.freedesktop.DBus.GetNameOwner for already-owned well-known names",
        "GetConnectionUnixProcessID / GetConnectionUnixUser; supplementary group IDs come from /proc/<pid>/status; SELinux security context is lazy for the selected connection.",
        "GetConnectionCredentials is deliberately not used because some bus implementations may return a UNIX process FD.",
    ])
    _append_source_group(widget, "OBJECT MODEL", [
        "org.freedesktop.DBus.Introspectable.Introspect",
        "Object discovery is lazy. Inspect Service... or Inspect Object... explicitly acquires XML; tree expansion and selection only show already-acquired information.",
        "Deep requests are sent to the already-running unique owner (:1.x), never to an activatable well-known service name.",
    ])
    _append_source_group(widget, "PROPERTY VALUES", [
        "org.freedesktop.DBus.Properties.Get only after explicit Read Value.",
        "No Properties.GetAll sweep.",
        "Properties whose declared type contains UNIX_FD or a Variant container are not read in this release.",
    ])
    _append_source_group(widget, "PROCESS CONTEXT", [
        "/proc/<pid>/comm for a compact process label only.",
        "No process command-line sweep.",
    ])
    _append_source_group(widget, "SAFETY / BOUNDARIES", [
        "No arbitrary application method invocation.",
        "No Properties.Set, StartServiceByName, RequestName/ReleaseName, activation-environment changes, bus reload, or service-control calls.",
        "No BecomeMonitor, eavesdropping, signal subscription, dbus-monitor equivalent, tracing or persistent traffic capture.",
        "Connecting to the bus creates this Inspector's own temporary bus peer; it is shown rather than hidden.",
    ])
    cur = widget.textCursor(); cur.movePosition(QTextCursor.MoveOperation.Start); widget.setTextCursor(cur)
    widget.verticalScrollBar().setValue(0)


class DBusOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — D-Bus Inspector")
        self.resize(940, 700)
        root = QVBoxLayout(self)
        tabs = QTabWidget(); root.addWidget(tabs, 1)

        appearance = QWidget(); al = QVBoxLayout(appearance); al.setContentsMargins(12,12,12,12); al.setSpacing(10)
        h = QLabel("D-Bus configuration"); f=h.font(); f.setBold(True); h.setFont(f); al.addWidget(h)
        self.meta = QCheckBox("Show Metadata Details panel (F3)")
        self.meta.setChecked(owner.metadata_visible)
        self.meta.toggled.connect(lambda c: owner.set_metadata_visible(bool(c), persist=True)); al.addWidget(self.meta)
        row = QHBoxLayout(); row.addWidget(QLabel("Record details layout:"))
        self.orientation = QComboBox(); self.orientation.addItems(["Horizontal", "Vertical"])
        self.orientation.setCurrentText(owner.details_orientation.title())
        self.orientation.currentTextChanged.connect(lambda t: owner.set_details_orientation(str(t).lower(), persist=True))
        row.addWidget(self.orientation); row.addStretch(1); al.addLayout(row)
        inventory_row = QHBoxLayout()
        inventory_row.addWidget(QLabel("Inventory:"))
        self.names_radio = QRadioButton("Names")
        self.connections_radio = QRadioButton("Connections")
        self.inventory_group = QButtonGroup(self)
        self.inventory_group.setExclusive(True)
        self.inventory_group.addButton(self.names_radio)
        self.inventory_group.addButton(self.connections_radio)
        self.names_radio.setChecked(owner.current_view == "Names")
        self.connections_radio.setChecked(owner.current_view == "Connections")
        self.names_radio.toggled.connect(lambda checked: checked and owner._view_changed("Names"))
        self.connections_radio.toggled.connect(lambda checked: checked and owner._view_changed("Connections"))
        inventory_row.addWidget(self.names_radio)
        inventory_row.addWidget(self.connections_radio)
        inventory_row.addStretch(1)
        al.addLayout(inventory_row)
        inventory_note = QLabel(
            "Names lists the selected bus's names and lets you explicitly inspect a running "
            "service's objects, interfaces and members. Connections lists the bus's live "
            "peers, process identities and owned names; selecting one shows its Metadata "
            "Details without opening or inspecting a service. Ctrl+I switches inventories."
        )
        inventory_note.setWordWrap(True)
        al.addWidget(inventory_note)
        note = QLabel(
            "Shortcuts: Ctrl+I toggles Names/Connections; F4 activates the visible Inspect Service..., "
            "Inspect Object..., or Refresh Object... action; F3 Metadata Details; "
            "Ctrl+L Horizontal/Vertical; Shift+F5 Refresh active snapshot; Ctrl+/ Options."
        )
        note.setWordWrap(True); al.addWidget(note); al.addStretch(1); tabs.addTab(appearance, "Configuration")

        sources = QWidget(); sl = QVBoxLayout(sources); sl.setContentsMargins(12,12,12,12); sl.setSpacing(10)
        sh = QLabel("Data Sources"); sf=sh.font(); sf.setBold(True); sh.setFont(sf); sl.addWidget(sh)
        sn = QLabel("Direct message-bus inventory and explicit read-only introspection/property acquisition. No application service activation or traffic monitoring.")
        sn.setWordWrap(True); sl.addWidget(sn)
        self.sources_text = _source_canvas(owner); _populate_sources(self.sources_text, owner); sl.addWidget(self.sources_text, 1)
        tabs.addTab(sources, "Sources")

        export = QWidget(); el = QVBoxLayout(export); el.setContentsMargins(12,12,12,12); el.setSpacing(10)
        eh=QLabel("Export"); ef=eh.font(); ef.setBold(True); eh.setFont(ef); el.addWidget(eh)
        en=QLabel("Export contains only records already acquired in the selected inventory and, for Names, its inspected tree. It never introspects another object, reads another property, refreshes names, or activates a service.")
        en.setWordWrap(True); el.addWidget(en)
        self.include_values = QCheckBox("Include already-acquired property values")
        self.include_values.setChecked(owner.export_include_values); self.include_values.toggled.connect(owner.set_export_include_values); el.addWidget(self.include_values)
        el.addStretch(1); row=QHBoxLayout(); row.addStretch(1); btn=QPushButton("Export Current View..."); btn.clicked.connect(owner.export_current_view); row.addWidget(btn); el.addLayout(row)
        tabs.addTab(export, "Export")

        # About — follows the established LinSpectacles family presentation.
        about = QWidget()
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pix = QPixmap(str(icon_path))
            if not pix.isNull():
                icon_label.setPixmap(
                    pix.scaled(
                        112, 112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>D-Bus Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        desc = QLabel(
            "A read-only LinSpectacles applet for inspecting system and session "
            "D-Bus names, connections, objects, interfaces and members without "
            "activating services or monitoring bus traffic."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(desc)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about, "About")

        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(self.reject); root.addWidget(buttons)


def _branded_settings():
    """Use the current D-Bus Inspector settings identity."""
    return QSettings("brunonlinespace", "D-Bus Inspector")


class DBusInspectorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = _branded_settings()
        self.bus_scope = str(self.settings.value("bus", "system"))
        if self.bus_scope not in {"system", "session"}:
            self.bus_scope = "system"
        self.current_view = str(self.settings.value("view", "Names"))
        # The three formerly separate detail views are now inside the Names tree.
        if self.current_view not in PRIMARY_VIEWS:
            self.current_view = "Names"
            self.settings.setValue("view", "Names")
        self.details_orientation = str(self.settings.value("details_orientation", "horizontal"))
        if self.details_orientation not in {"horizontal", "vertical"}:
            self.details_orientation = "horizontal"
        self.metadata_visible = str(self.settings.value("metadata_visible", "true")).lower() not in {"0", "false", "no"}
        self.export_include_values = False
        self._metadata_font = metadata_font_from_string(str(self.settings.value("metadata_font", "")))
        self.client: SdBusClient | None = None
        self.names_snapshot: dict[str, Any] | None = None
        self.records_by_view = {name: [] for name in VIEW_COLUMNS}
        self.object_records: dict[str, dict[str, Any]] = {}
        self.object_cache: dict[str, dict[str, Any]] = {}
        self.member_records: dict[tuple, dict[str, Any]] = {}
        self.context_service = ""
        self.context_owner = ""
        self.context_object = ""
        self.context_interface = ""
        self._expanded_nodes: set[tuple] = set()
        self._rebuilding_tree = False
        self._applying_splitter = False
        self._build_ui()
        self._connect_bus(initial=True)
        self._restore_view_state()
        self.load_current_view()

    # ----- UI -----------------------------------------------------------------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)
        top = QHBoxLayout()
        self.inventory_count = QLabel("D-Bus Names: 0")
        count_font = self.inventory_count.font()
        count_font.setBold(True)
        self.inventory_count.setFont(count_font)
        top.addWidget(self.inventory_count)
        top.addStretch(1)
        self.inspect_btn = QPushButton("Inspect Service...")
        self.inspect_btn.clicked.connect(self._inspect_selected)
        top.addWidget(self.inspect_btn)
        self.read_btn = QPushButton("Read Property")
        self.read_btn.clicked.connect(self._read_selected_property)
        top.addWidget(self.read_btn)
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.refresh_active)
        top.addWidget(self.refresh_btn)
        self.options_btn = QPushButton("Options...")
        self.options_btn.clicked.connect(self.open_options)
        top.addWidget(self.options_btn)
        root.addLayout(top)

        filters = QHBoxLayout()
        lab = QLabel("Search:")
        lab.setStyleSheet("font-weight:600;")
        filters.addWidget(lab)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search acquired inventory...")
        self.search.setMaximumWidth(330)
        self.search.textChanged.connect(self.apply_filter)
        filters.addWidget(self.search)
        self.filter_label = QLabel("Filter:")
        self.filter_label.setStyleSheet("font-weight:600;")
        filters.addWidget(self.filter_label)
        self.filter_combo = QComboBox()
        self.filter_combo.setMinimumWidth(190)
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        filters.addWidget(self.filter_combo)
        filters.addSpacing(10)
        bus_label = QLabel("Bus:")
        bus_label.setStyleSheet("font-weight:600;")
        filters.addWidget(bus_label)
        self.bus_system_radio = QRadioButton("System")
        self.bus_session_radio = QRadioButton("Session")
        self.bus_scope_group = QButtonGroup(self)
        self.bus_scope_group.setExclusive(True)
        self.bus_scope_group.addButton(self.bus_system_radio)
        self.bus_scope_group.addButton(self.bus_session_radio)
        self.bus_system_radio.setChecked(self.bus_scope == "system")
        self.bus_session_radio.setChecked(self.bus_scope == "session")
        self.bus_system_radio.toggled.connect(lambda checked: checked and self._bus_changed("System"))
        self.bus_session_radio.toggled.connect(lambda checked: checked and self._bus_changed("Session"))
        filters.addWidget(self.bus_system_radio)
        filters.addWidget(self.bus_session_radio)
        self.filter_status = QLabel("")
        ff = self.filter_status.font()
        ff.setItalic(True)
        self.filter_status.setFont(ff)
        filters.addWidget(self.filter_status)
        filters.addStretch(1)
        root.addLayout(filters)

        self.splitter = QSplitter(Qt.Orientation.Horizontal if self.details_orientation == "horizontal" else Qt.Orientation.Vertical)
        root.addWidget(self.splitter, 1)
        self.inventory_stack = QStackedWidget()
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(TREE_COLUMNS))
        self.tree.setHeaderLabels([c[1] for c in TREE_COLUMNS])
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setSortingEnabled(False)  # Preserve service / object / interface hierarchy.
        tree_header = self.tree.header()
        tree_header.setSectionsMovable(False)
        tree_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree_header.customContextMenuRequested.connect(self._tree_column_menu)
        tree_header.sectionResized.connect(self._save_tree_widths)
        self.tree.currentItemChanged.connect(self._tree_selection_changed)
        self.tree.itemExpanded.connect(self._tree_expanded)
        self.tree.itemCollapsed.connect(self._tree_collapsed)
        self.inventory_stack.addWidget(self.tree)

        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.horizontalHeader().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.horizontalHeader().customContextMenuRequested.connect(self._column_menu)
        self.table.horizontalHeader().sectionResized.connect(self._save_column_widths)
        self.table.horizontalHeader().sortIndicatorChanged.connect(self._save_sort)
        self.inventory_stack.addWidget(self.table)
        self.splitter.addWidget(self.inventory_stack)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(8, 0, 0, 0)
        rl.setSpacing(6)
        mh = QLabel("Metadata Details")
        mf = mh.font()
        mf.setBold(True)
        mf.setPointSize(max(11, mf.pointSize()))
        mh.setFont(mf)
        rl.addWidget(mh)
        self.info = QTextEdit()
        self.info.setReadOnly(True)
        self.info.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.info.setFont(self._metadata_font)
        self.info.document().setDefaultFont(self._metadata_font)
        self.info.setCurrentFont(self._metadata_font)
        self.info.setStyleSheet("QTextEdit { background:#1e1e1e; color:#dcdcdc; border:1px solid #666; " + metadata_font_qss(self._metadata_font) + " }")
        self.highlighter = MetadataHighlighter(self.info.document())
        rl.addWidget(self.info, 1)
        self.splitter.addWidget(right)
        self.metadata_panel = right
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.splitterMoved.connect(self._save_splitter)

        self.status = QLabel("Ready")
        sf = self.status.font()
        sf.setItalic(True)
        self.status.setFont(sf)
        self.status.setFrameShape(QFrame.Shape.NoFrame)
        self.status.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.status)

        QShortcut(QKeySequence("F3"), self, activated=self.toggle_metadata)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.toggle_orientation)
        QShortcut(QKeySequence("Shift+F5"), self, activated=self.refresh_active)
        QShortcut(QKeySequence("Ctrl+/"), self, activated=self.open_options)
        self._inventory_shortcut = QShortcut(QKeySequence("Ctrl+I"), self)
        self._inventory_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._inventory_shortcut.activated.connect(self.toggle_inventory)
        self._inspect_shortcut = QShortcut(QKeySequence("F4"), self)
        self._inspect_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._inspect_shortcut.activated.connect(self.inspect_visible_action)
        self.set_details_orientation(self.details_orientation, persist=False)
        self.set_metadata_visible(self.metadata_visible, persist=False)
        self.inventory_stack.setCurrentIndex(0 if self.current_view == "Names" else 1)
        self._configure_filter()
        self._configure_columns()
        self._configure_tree_columns()
        self._update_action_enabled()

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        self._metadata_font = apply_metadata_font(
            self.info, settings.get("metadata_font", "")
        )
        self.info.setStyleSheet(
            "QTextEdit { background:#1e1e1e; color:#dcdcdc; border:1px solid #666; "
            + metadata_font_qss(self._metadata_font) + " }"
        )

    def _settings_key(self, suffix):
        return f"view/{self.current_view}/{suffix}"

    def set_status(self, text):
        self.status.setText(str(text))

    def _append(self, text):
        cur = self.info.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(str(text))
        self.info.setTextCursor(cur)

    def _section(self, name):
        self._append(f"\n--- {name} ---\n" if self.info.toPlainText() else f"--- {name} ---\n")

    def _kv(self, key, value):
        self._append(f"{key}: {value}\n")

    def _reset_info_top(self):
        cur = self.info.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.Start)
        self.info.setTextCursor(cur)
        self.info.verticalScrollBar().setValue(0)

    def _connect_bus(self, initial=False):
        if self.client is not None:
            self.client.close()
            self.client = None
        try:
            self.client = SdBusClient(self.bus_scope)
            self.set_status(f"Connected to {self.bus_scope} D-Bus as {self.client.unique_name or 'an unnamed peer'}.")
        except Exception as exc:
            self.client = None
            self.set_status(f"{self.bus_scope.title()} D-Bus unavailable: {exc}")
            if not initial:
                QMessageBox.warning(self, "D-Bus", f"Could not connect to the {self.bus_scope} bus:\n{exc}")

    def _bus_changed(self, text):
        scope = str(text).lower()
        if scope == self.bus_scope:
            return
        self.bus_scope = scope
        self.settings.setValue("bus", scope)
        self._reset_deep_context()
        self.names_snapshot = None
        self.records_by_view = {name: [] for name in VIEW_COLUMNS}
        self._connect_bus()
        # System/Session chooses the bus; it must not change the user's inventory view.
        self.load_current_view()

    def _view_changed(self, text):
        if text not in PRIMARY_VIEWS or text == self.current_view:
            return
        self.current_view = text
        self.settings.setValue("view", text)
        self.inventory_stack.setCurrentIndex(0 if text == "Names" else 1)
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self._configure_filter()
        if text == "Connections":
            self._configure_columns()
        self.load_current_view()

    def toggle_inventory(self):
        self._view_changed("Connections" if self.current_view == "Names" else "Names")

    def inspect_visible_action(self):
        if not self.inspect_btn.isHidden() and self.inspect_btn.isEnabled():
            self._inspect_selected()

    def _configure_filter(self):
        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        self.filter_combo.addItems(VIEW_FILTERS[self.current_view])
        default = VIEW_FILTERS[self.current_view][0]
        saved = str(self.settings.value(self._settings_key("filter"), default))
        # Old Names filter values are migrated only by meaning, not by an old-brand alias.
        if saved == "All":
            saved = default
        idx = self.filter_combo.findText(saved)
        self.filter_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.filter_combo.blockSignals(False)

    def _configure_columns(self):
        # Connections retains its table, saved widths, column visibility and sorting.
        cols = VIEW_COLUMNS["Connections"]
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setColumnCount(len(cols))
        self.table.setHorizontalHeaderLabels([c[1] for c in cols])
        self.table.setRowCount(0)
        hidden = {x for x in str(self.settings.value("view/Connections/hidden_columns", "")).split(",") if x}
        widths = str(self.settings.value("view/Connections/widths", ""))
        try:
            parsed = [int(x) for x in widths.split(",") if x]
        except ValueError:
            parsed = []
        self.table.horizontalHeader().blockSignals(True)
        for i, (cid, _lab, w, _align) in enumerate(cols):
            self.table.setColumnWidth(i, parsed[i] if i < len(parsed) and parsed[i] > 20 else w)
            self.table.setColumnHidden(i, cid in hidden)
        self.table.horizontalHeader().blockSignals(False)
        self._update_resize_modes()
        section = int(self.settings.value("view/Connections/sort_section", 0) or 0)
        order = int(self.settings.value("view/Connections/sort_order", 0) or 0)
        if 0 <= section < len(cols):
            self.table.horizontalHeader().setSortIndicator(section, Qt.SortOrder.DescendingOrder if order else Qt.SortOrder.AscendingOrder)

    def _configure_tree_columns(self):
        hidden = {x for x in str(self.settings.value("view/Names/tree_hidden_columns", "")).split(",") if x}
        if len(hidden) >= len(TREE_COLUMNS):
            hidden.clear()
        widths = str(self.settings.value("view/Names/tree_widths", ""))
        try:
            parsed = [int(x) for x in widths.split(",") if x]
        except ValueError:
            parsed = []
        header = self.tree.header()
        header.blockSignals(True)
        for i, (cid, _lab, width) in enumerate(TREE_COLUMNS):
            self.tree.setColumnWidth(i, parsed[i] if i < len(parsed) and parsed[i] > 20 else width)
            self.tree.setColumnHidden(i, cid in hidden)
        header.blockSignals(False)
        header.setStretchLastSection(True)

    def _tree_column_menu(self, pos):
        menu = QMenu(self)
        for i, (_cid, label, _width) in enumerate(TREE_COLUMNS):
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(not self.tree.isColumnHidden(i))
            action.triggered.connect(lambda checked, index=i: self._set_tree_column_visible(index, checked))
        menu.exec(self.tree.header().mapToGlobal(pos))

    def _set_tree_column_visible(self, index, visible):
        if not visible and sum(not self.tree.isColumnHidden(i) for i in range(len(TREE_COLUMNS))) <= 1:
            self.set_status("At least one column must remain visible.")
            return
        self.tree.setColumnHidden(index, not visible)
        self.settings.setValue("view/Names/tree_hidden_columns", ",".join(TREE_COLUMNS[i][0] for i in range(len(TREE_COLUMNS)) if self.tree.isColumnHidden(i)))

    def _save_tree_widths(self, *_):
        if self.tree.columnCount() == len(TREE_COLUMNS):
            self.settings.setValue("view/Names/tree_widths", ",".join(str(self.tree.columnWidth(i)) for i in range(len(TREE_COLUMNS))))

    def _update_resize_modes(self):
        header = self.table.horizontalHeader()
        visible = [i for i in range(self.table.columnCount()) if not self.table.isColumnHidden(i)]
        if not visible:
            return
        for i in visible:
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch if i == visible[-1] else QHeaderView.ResizeMode.Interactive)

    def _column_menu(self, pos):
        menu = QMenu(self)
        for i, (_cid, label, *_) in enumerate(VIEW_COLUMNS["Connections"]):
            act = menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(not self.table.isColumnHidden(i))
            act.triggered.connect(lambda checked, index=i: self._set_column_visible(index, checked))
        menu.exec(self.table.horizontalHeader().mapToGlobal(pos))

    def _set_column_visible(self, index, visible):
        if not visible and sum(not self.table.isColumnHidden(i) for i in range(self.table.columnCount())) <= 1:
            self.set_status("At least one column must remain visible.")
            return
        self.table.setColumnHidden(index, not visible)
        self._update_resize_modes()
        self.settings.setValue("view/Connections/hidden_columns", ",".join(VIEW_COLUMNS["Connections"][i][0] for i in range(self.table.columnCount()) if self.table.isColumnHidden(i)))

    def _save_column_widths(self, *_):
        if self.table.columnCount() == len(VIEW_COLUMNS["Connections"]):
            self.settings.setValue("view/Connections/widths", ",".join(str(self.table.columnWidth(i)) for i in range(self.table.columnCount())))

    def _save_sort(self, section, order):
        self.settings.setValue("view/Connections/sort_section", int(section))
        self.settings.setValue("view/Connections/sort_order", 1 if order == Qt.SortOrder.DescendingOrder else 0)

    def _save_splitter(self, *_):
        if not self._applying_splitter:
            self.settings.setValue(f"splitter/{self.details_orientation}", ",".join(str(x) for x in self.splitter.sizes()))

    def _restore_view_state(self):
        raw = str(self.settings.value(f"splitter/{self.details_orientation}", ""))
        try:
            sizes = [int(x) for x in raw.split(",") if x]
        except ValueError:
            sizes = []
        if len(sizes) == 2 and all(x > 0 for x in sizes):
            self._applying_splitter = True
            try:
                self.splitter.setSizes(sizes)
            finally:
                self._applying_splitter = False

    def set_metadata_visible(self, visible, persist=True):
        self.metadata_visible = bool(visible)
        self.metadata_panel.setVisible(self.metadata_visible)
        if self.metadata_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            self.settings.setValue("metadata_visible", self.metadata_visible)

    def toggle_metadata(self):
        self.set_metadata_visible(not self.metadata_visible)

    def set_details_orientation(self, orientation, persist=True):
        if orientation not in {"horizontal", "vertical"}:
            return
        # Kernel Modules 0.0.5: orientation-specific margins and proportions.
        self._applying_splitter = True
        try:
            self.details_orientation = orientation
            layout = self.metadata_panel.layout()
            if orientation == "vertical":
                self.splitter.setOrientation(Qt.Orientation.Vertical)
                layout.setContentsMargins(0, 8, 0, 0)
                self.splitter.setSizes([430, 330])
            else:
                self.splitter.setOrientation(Qt.Orientation.Horizontal)
                layout.setContentsMargins(8, 0, 0, 0)
                self.splitter.setSizes([480, 700])
        finally:
            self._applying_splitter = False
        # Preserve meaningful per-orientation D-Bus splitter preferences.
        self._restore_view_state()
        if persist:
            self.settings.setValue("details_orientation", orientation)

    def toggle_orientation(self):
        self._save_splitter()
        self.set_details_orientation("vertical" if self.details_orientation == "horizontal" else "horizontal")

    def set_export_include_values(self, value):
        self.export_include_values = bool(value)

    def _current_record(self):
        if self.current_view == "Names":
            item = self.tree.currentItem()
            return item.data(0, Qt.ItemDataRole.UserRole) if item else None
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _current_tree_key(self):
        item = self.tree.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole + 1) if item else None

    def _update_action_enabled(self):
        r = self._current_record()
        inspect = False
        read = False
        label = "Inspect Service..."
        if self.client is not None and r and self.current_view == "Names":
            if r.get("node_type") == "name":
                inspect = bool(r.get("owner", "")) and r.get("kind") != "Bus" and r.get("state") != "Activatable"
            elif r.get("node_type") == "object":
                inspect = bool(self.context_owner and r.get("path"))
                label = "Refresh Object..." if r.get("introspection") else "Inspect Object..."
            elif r.get("node_type") == "member":
                safe, _ = property_value_safe(r.get("signature", ""))
                read = (r.get("kind") == "Property" and "read" in r.get("access", "") and r.get("value_state") != "Available" and safe)
        self.inspect_btn.setText(label)
        self.inspect_btn.setVisible(inspect)
        self.read_btn.setVisible(read)

    # ----- acquisition ---------------------------------------------------------
    def load_current_view(self):
        if self.client is None:
            if self.current_view == "Names":
                self._render_names_tree()
            else:
                self._show_records([])
            self.info.clear()
            return
        if self.current_view == "Names":
            if self.names_snapshot is None:
                self._load_names()
            else:
                self._render_names_tree()
        elif self.current_view == "Connections":
            self._load_connections()

    def _load_names(self):
        try:
            self.set_status(f"Scanning {self.bus_scope} D-Bus names...")
            self.names_snapshot = name_inventory(self.client)
            self.records_by_view["Names"] = self.names_snapshot["records"]
            self._render_names_tree()
            self.set_status(f"{len(self.records_by_view['Names'])} bus names · {self.bus_scope.title()} bus · snapshot complete.")
        except Exception as exc:
            self.names_snapshot = None
            self.records_by_view["Names"] = []
            self._render_names_tree()
            self.set_status(f"Could not read bus-name inventory: {exc}")

    def _ensure_names(self):
        if self.names_snapshot is None:
            self._load_names()
        return self.names_snapshot is not None

    def _load_connections(self):
        if not self._ensure_names():
            self.records_by_view["Connections"] = []
            self._show_records([])
            return
        try:
            self.set_status("Reading live D-Bus connection identities...")
            records = connection_inventory(self.client, self.names_snapshot)
            self.records_by_view["Connections"] = records
            self._show_records(records)
            self.set_status(f"{len(records)} live bus connections · PID/UID context acquired without GetConnectionCredentials.")
        except Exception as exc:
            self.records_by_view["Connections"] = []
            self._show_records([])
            self.set_status(f"Could not read connection inventory: {exc}")

    def _reset_deep_context(self):
        self.object_records.clear()
        self.object_cache.clear()
        self.member_records.clear()
        self.context_service = ""
        self.context_owner = ""
        self.context_object = ""
        self.context_interface = ""
        self._expanded_nodes.clear()

    def _start_object_context(self, service, owner):
        if not self.client or not owner or not str(owner).startswith(":"):
            self.set_status("Deep inspection requires an already-running unique owner; inactive activatable services are never activated.")
            return
        self._reset_deep_context()
        self.context_service = str(service or owner)
        self.context_owner = str(owner)
        self.context_object = "/"
        self._expanded_nodes.update({("name", self.context_service), ("object", self.context_owner, "/")})
        # Explicit navigation must not be defeated by a previously chosen root filter.
        if self.current_view == "Names" and self.filter_combo.currentText() not in {"All Names", "All"}:
            self.filter_combo.setCurrentText("All Names")
        try:
            intro = self.client.introspect(self.context_owner, "/")
            self._merge_object_intro(intro)
            self.set_status(f"Inspected root object of {self.context_service} using the running owner {self.context_owner}.")
        except Exception as exc:
            self.object_records["/"] = {"path": "/", "display_path": "/", "state": self._error_state(exc), "interfaces_count": 0, "children_count": 0, "introspection": None, "error": str(exc)}
            self.set_status(f"Could not introspect {self.context_service} at /: {exc}")
        name_record = next((r for r in self.records_by_view["Names"] if r.get("name") == self.context_service), None)
        if name_record is not None and not self._matches_filter(name_record, self.filter_combo.currentText(), "Names"):
            self.filter_combo.setCurrentText("All Names")
        self._render_names_tree(select_key=("object", self.context_owner, "/"))

    def _merge_object_intro(self, intro):
        path = intro["path"]
        self.object_cache[path] = intro
        # A fresh XML result invalidates older property values for that object.
        self.member_records = {key: value for key, value in self.member_records.items() if key[1] != path}
        self.object_records[path] = {"path": path, "display_path": path, "state": "Inspected", "interfaces_count": len(intro.get("interfaces", [])), "children_count": len(intro.get("children", [])), "introspection": intro, "error": ""}
        for child in intro.get("children", []):
            cpath = child["path"]
            if cpath not in self.object_records:
                self.object_records[cpath] = {"path": cpath, "display_path": cpath, "state": "Not inspected", "interfaces_count": "", "children_count": "", "introspection": None, "error": ""}

    def _inspect_object(self, r):
        path = r.get("path", "")
        if not path or not self.client or not self.context_owner:
            return
        try:
            intro = self.client.introspect(self.context_owner, path)
            self._merge_object_intro(intro)
            self.set_status(f"Inspected object {path}: {len(intro.get('interfaces', []))} interfaces, {len(intro.get('children', []))} declared children.")
        except Exception as exc:
            rec = self.object_records.get(path, r)
            rec.update({"state": self._error_state(exc), "error": str(exc)})
            self.object_records[path] = rec
            self.set_status(f"Could not introspect {path}: {exc}")
        self._expanded_nodes.add(("object", self.context_owner, path))
        self._render_names_tree(select_key=("object", self.context_owner, path))

    def _error_state(self, exc):
        if isinstance(exc, DBusInspectorError):
            if exc.vanished:
                return "Service disappeared"
            if exc.permission_denied:
                return "Permission denied"
        return "Read failed"

    # ----- tree model & filtering: only already acquired facts -----------------
    def _member_nodes(self, path, iface):
        iface_name = iface.get("name", "")
        nodes = []
        for kind, collection in (("Method", "methods"), ("Property", "properties"), ("Signal", "signals")):
            for m in iface.get(collection, []):
                name = m.get("name", "")
                identity = (kind, self.context_owner, path, iface_name, name)
                if kind == "Method":
                    sig = method_signature(m)
                elif kind == "Signal":
                    sig = signal_signature(m)
                else:
                    sig = m.get("type", "") or "—"
                record = self.member_records.get(identity)
                if record is None:
                    record = {"kind": kind, "name": name, "signature": sig,
                              "access": m.get("access", "") if kind == "Property" else "—",
                              "value_state": "Not read" if kind == "Property" else "—",
                              "value_display": "", "member": m, "identity": identity}
                    self.member_records[identity] = record
                record.update({"node_type": "member", "path": path, "interface_name": iface_name, "signature": sig, "member": m})
                key = ("member", self.context_owner, path, iface_name, kind, name)
                nodes.append({"key": key, "label": name, "kind": kind, "state": record.get("value_state", "") if kind == "Property" else "", "record": record, "children": []})
        return sorted(nodes, key=lambda n: (n["kind"], n["label"].lower()))

    def _object_node(self, path, records, visiting=None):
        # A discovered child may have a path between two inspected levels.
        visiting = set(visiting or ())
        if path in visiting:
            return None
        visiting.add(path)
        r = records.get(path)
        if r is None:
            return None
        record = dict(r, node_type="object")
        key = ("object", self.context_owner, path)
        children = []
        intro = r.get("introspection")
        if intro:
            for iface in sorted(intro.get("interfaces", []), key=lambda x: x.get("name", "").lower()):
                name = iface.get("name", "")
                iface_record = {"node_type": "interface", "name": name, "path": path,
                                "methods_count": len(iface.get("methods", [])),
                                "properties_count": len(iface.get("properties", [])),
                                "signals_count": len(iface.get("signals", [])),
                                "annotations_count": len(iface.get("annotations", [])), "interface": iface}
                children.append({"key": ("interface", self.context_owner, path, name),
                                 "label": name, "kind": "Interface", "state": "",
                                 "record": iface_record, "children": self._member_nodes(path, iface)})
            child_paths = [c.get("path", "") for c in intro.get("children", [])]
            for child_path in sorted(set(child_paths)):
                if child_path != path:
                    child_node = self._object_node(child_path, records, visiting)
                    if child_node:
                        children.append(child_node)
        return {"key": key, "label": path, "kind": "Object", "state": r.get("state", ""), "record": record, "children": children}

    def _full_names_model(self):
        model = []
        for r in self.records_by_view["Names"]:
            key = ("name", r.get("name", ""))
            children = []
            if self.context_owner and r.get("name") == self.context_service and "/" in self.object_records:
                root = self._object_node("/", self.object_records)
                if root:
                    children.append(root)
            model.append({"key": key, "label": r.get("name", ""),
                          "kind": r.get("kind", ""), "state": r.get("state", ""),
                          "record": dict(r, node_type="name"), "children": children})
        return model

    def _filter_tree_node(self, node, query, ancestor_matched=False):
        values = (node["label"], node["kind"], node["state"])
        direct = not query or any(query in str(value).lower() for value in values)
        # A matching parent retains acquired children; a matching descendant
        # retains every parent, preserving context as in Cgroups Inspector.
        keep_all = ancestor_matched or direct
        children = [match for child in node["children"] if (match := self._filter_tree_node(child, query, keep_all)) is not None]
        if keep_all or children:
            return dict(node, children=children)
        return None

    def _tree_expanded(self, item):
        if not self._rebuilding_tree:
            self._expanded_nodes.add(item.data(0, Qt.ItemDataRole.UserRole + 1))

    def _tree_collapsed(self, item):
        if not self._rebuilding_tree:
            self._expanded_nodes.discard(item.data(0, Qt.ItemDataRole.UserRole + 1))

    def _render_names_tree(self, select_key=None):
        if not hasattr(self, "tree"):
            return
        if select_key is None and self.current_view == "Names":
            select_key = self._current_tree_key()
        query = self.search.text().strip().lower() if self.current_view == "Names" else ""
        filt = self.filter_combo.currentText() if self.current_view == "Names" else "All Names"
        full = self._full_names_model()
        shown = []
        for root in full:
            if not self._matches_filter(root["record"], filt, "Names"):
                continue
            filtered = self._filter_tree_node(root, query)
            if filtered is not None:
                shown.append(filtered)
        items = {}
        self._rebuilding_tree = True
        self.tree.blockSignals(True)
        try:
            self.tree.clear()
            def insert(parent, node):
                item = QTreeWidgetItem([str(node["label"]), str(node["kind"]), str(node["state"])])
                item.setData(0, Qt.ItemDataRole.UserRole, node["record"])
                item.setData(0, Qt.ItemDataRole.UserRole + 1, node["key"])
                if parent is None:
                    self.tree.addTopLevelItem(item)
                else:
                    parent.addChild(item)
                items[node["key"]] = item
                for child in node["children"]:
                    insert(item, child)
                match_self = any(query in str(x).lower() for x in (node["label"], node["kind"], node["state"]))
                if node["key"] in self._expanded_nodes or (query and node["children"] and not match_self):
                    item.setExpanded(True)
            for root in shown:
                insert(None, root)
            selected = items.get(select_key)
            if selected is None and shown:
                # Match a visible acquired record first; never preserve stale metadata.
                selected = next((items.get(n["key"]) for n in shown if query and query in n["label"].lower()), None)
                selected = selected or items[shown[0]["key"]]
            if selected is not None:
                self.tree.setCurrentItem(selected)
                selected.setSelected(True)
        finally:
            self.tree.blockSignals(False)
            self._rebuilding_tree = False
        if self.current_view == "Names":
            self._tree_selection_changed(self.tree.currentItem(), None)
        total = len(full)
        self.inventory_count.setText(f"D-Bus Names: {total}")
        if self.current_view == "Names":
            self.filter_status.setText(f"Showing {len(shown)} of {total} names" if query or filt != "All Names" else "")
            self.settings.setValue("view/Names/filter", filt)

    def _tree_selection_changed(self, current, _previous):
        if self.current_view != "Names":
            return
        self._update_action_enabled()
        if current is None:
            self.info.clear()
            return
        r = current.data(0, Qt.ItemDataRole.UserRole)
        if not r:
            self.info.clear()
            return
        typ = r.get("node_type")
        if typ == "name":
            self.context_object = ""
            self.context_interface = ""
            self._meta_name(r)
        elif typ == "object":
            self.context_object = r.get("path", "")
            self.context_interface = ""
            self._meta_object(r)
        elif typ == "interface":
            self.context_object = r.get("path", "")
            self.context_interface = r.get("name", "")
            self._meta_interface(r)
        elif typ == "member":
            self.context_object = r.get("path", "")
            self.context_interface = r.get("interface_name", "")
            self._meta_member(r)
        self._reset_info_top()

    # ----- filtering/table -----------------------------------------------------
    def _matches_filter(self, r, flt, view=None):
        v = view or self.current_view
        if flt in {"All Names", "All Connections", "All"}:
            return True
        if v == "Names":
            if flt in {"Well-known", "Unique"}:
                return r.get("kind") == flt
            if flt == "Owned":
                return bool(r.get("owned"))
            if flt == "Activatable":
                return bool(r.get("activatable"))
        elif v == "Connections":
            if flt == "Owns well-known names":
                return bool(r.get("owned_names_list"))
            if flt == "This Inspector":
                return bool(r.get("this_inspector"))
        return True

    def apply_filter(self, *_, select_key=None):
        if self.current_view == "Names":
            self._render_names_tree(select_key)
            return
        records = self.records_by_view.get("Connections", [])
        query = self.search.text().strip().lower()
        filt = self.filter_combo.currentText() or "All Connections"
        shown = [r for r in records if self._matches_filter(r, filt) and (not query or any(query in str(v).lower() for k, v in r.items() if k not in {"owned_names_list"}))]
        self._populate_table(shown, select_key=select_key)
        self.inventory_count.setText(f"D-Bus Connections: {len(records)}")
        self.filter_status.setText(f"Showing {len(shown)} of {len(records)} connections" if query or filt != "All Connections" else "")
        self.settings.setValue("view/Connections/filter", filt)

    def _show_records(self, records, select_key=None):
        self.records_by_view["Connections"] = list(records)
        if self.current_view == "Connections":
            self.apply_filter(select_key=select_key)

    def _populate_table(self, records, select_key=None):
        cols = VIEW_COLUMNS["Connections"]
        old = self._current_record() if self.current_view == "Connections" else None
        key = select_key or (("unique", old.get("unique")) if old else None)
        self.table.blockSignals(True)
        try:
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(records))
            for row, r in enumerate(records):
                for col, (cid, _lab, _w, align) in enumerate(cols):
                    value = r.get(cid, "")
                    if cid in NUMERIC_BY_VIEW["Connections"] and isinstance(value, int):
                        item = NumericTableWidgetItem(f"{value:,}", value)
                    else:
                        item = QTableWidgetItem(str(value))
                    if col == 0:
                        item.setData(Qt.ItemDataRole.UserRole, r)
                    item.setTextAlignment((Qt.AlignmentFlag.AlignRight if align == "right" else Qt.AlignmentFlag.AlignLeft) | Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(row, col, item)
            self.table.setSortingEnabled(True)
            section = self.table.horizontalHeader().sortIndicatorSection()
            order = self.table.horizontalHeader().sortIndicatorOrder()
            if 0 <= section < len(cols):
                self.table.sortItems(section, order)
            selected = None
            if key:
                for row in range(self.table.rowCount()):
                    item = self.table.item(row, 0)
                    rec = item.data(Qt.ItemDataRole.UserRole) if item else None
                    if rec and rec.get(key[0]) == key[1]:
                        selected = row
                        break
            if selected is None and self.table.rowCount():
                selected = 0
            if selected is not None:
                self.table.selectRow(selected)
        finally:
            self.table.blockSignals(False)
        self._selection_changed()

    # ----- selection/metadata -------------------------------------------------
    def _selection_changed(self):
        if self.current_view != "Connections":
            return
        r = self._current_record()
        self._update_action_enabled()
        if not r:
            self.info.clear()
            return
        self._meta_connection(r)
        self._reset_info_top()

    # ----- selected record details: cached facts only -------------------------
    def _annotation_details(self, annotations, heading="ANNOTATIONS"):
        """Keep original name/value evidence and explain only known annotations."""
        if not annotations:
            return
        self._section(heading)
        for index, ann in enumerate(annotations, 1):
            name = ann.get("name", "")
            value = ann.get("value", "")
            meaning = annotation_explanation(name, value)
            self._kv(f"Annotation {index}", f"{name} = {value}")
            if meaning:
                self._kv(f"Meaning {index}", meaning)

    def _interface_overview(self, kind, members, limit=12):
        """List existing XML declarations without duplicating the inventory tree."""
        self._kv(f"{kind} Count", len(members))
        singular = {"Methods": "Method", "Properties": "Property", "Signals": "Signal"}[kind]
        for index, member in enumerate(members[:limit], 1):
            name = member.get("name", "")
            if kind == "Methods":
                args = member.get("args", [])
                incoming = "".join(a.get("type", "") for a in args if a.get("direction") != "out")
                outgoing = "".join(a.get("type", "") for a in args if a.get("direction") == "out")
                detail = f"Input: {signature_detail(incoming)}; Output: {signature_detail(outgoing)}"
            elif kind == "Properties":
                detail = f"{signature_detail(member.get('type', ''))}; access: {member.get('access', 'Not declared')}"
            else:
                detail = signature_detail("".join(a.get("type", "") for a in member.get("args", [])))
            self._kv(f"{singular} {index}", f"{name} — {detail}")
        if len(members) > limit:
            self._kv(f"{kind} Omitted", f"{len(members) - limit} more; see the inventory tree")

    def _meta_name(self, r):
        self.info.clear()
        self._section("BUS NAME")
        self._kv("Name", r.get("name"))
        self._kv("Kind", r.get("kind"))
        self._kv("Snapshot State", r.get("state"))
        kind = r.get("kind")
        if kind == "Well-known":
            self._kv("Name Type", "Human-readable, potentially transferable bus name")
        elif kind == "Unique":
            self._kv("Name Type", "Unique identity assigned to a bus connection")
        elif kind == "Bus":
            self._kv("Name Type", "Message-bus manager")
        if r.get("this_inspector"):
            self._kv("Observation", "This Inspector's own temporary bus connection")
        owner = r.get("owner", "")
        self._section("OWNERSHIP")
        self._kv("Owner", owner or "None / bus-internal")
        self._kv("Owned in Snapshot", "Yes" if r.get("owned") else "No")
        if owner:
            owned = (self.names_snapshot or {}).get("owned_by_unique", {}).get(owner, [])
            other_names = [name for name in owned if name != r.get("name")]
            self._kv("Other Well-known Names", len(other_names))
            for index, name in enumerate(other_names, 1):
                self._kv(f"Other Name {index}", name)
        self._section("ACTIVATION")
        self._kv("Activatable", "Yes" if r.get("activatable") else "No")
        if r.get("state") == "Activatable":
            self._kv("Safety", "Service is not running. LinSpectacles will not introspect it or send messages that could activate it.")
        if r.get("specialist"):
            self._section("RELATED INSPECTOR")
            self._kv("Inspector", r.get("specialist"))
            self._kv("Boundary", SPECIALIST_NOTES.get(r.get("specialist"), "A specialist inspector may provide deeper service semantics."))
        self._section("SOURCE")
        self._kv("Bus", self.bus_scope.title())
        self._kv("Inventory", "org.freedesktop.DBus manager methods")
        self._kv("Bus ID", (self.names_snapshot or {}).get("bus_id", "Not reported"))
        self._kv("Snapshot Acquired", (self.names_snapshot or {}).get("acquired", "Not reported"))
        self._kv("Inspector Connection", self.client.unique_name if self.client else "Unavailable")

    def _meta_connection(self, r):
        self.info.clear()
        self._section("CONNECTION")
        self._kv("Unique Name", r.get("unique"))
        self._kv("Identity", "Unique bus peer; may own zero or more well-known names")
        self._kv("PID", r.get("pid") if r.get("pid") != "" else "Unavailable")
        self._kv("UID", r.get("uid") if r.get("uid") != "" else "Unavailable")
        if r.get("this_inspector"):
            self._kv("Observation", "This Inspector's own temporary bus connection")
        self._section("PROCESS CONTEXT")
        self._kv("Process", r.get("process") or "Unavailable")
        self._kv("Supplementary Group IDs", ", ".join(str(x) for x in (r.get("group_ids") or [])) or "Unavailable")
        # Existing selection-triggered label lookup is preserved; no new call is added.
        if r.get("security_label") is None and self.client:
            r["security_label"] = self.client.get_connection_security_label(r.get("unique", ""))
        self._section("SECURITY CONTEXT")
        self._kv("Linux Security Label", r.get("security_label") or "Not exposed")
        self._section("OWNED NAMES")
        names = r.get("owned_names_list") or []
        self._kv("Well-known Names", len(names))
        for index, name in enumerate(names, 1):
            self._kv(f"Name {index}", name)
        self._section("SOURCE")
        self._kv("Bus", self.bus_scope.title())
        self._kv("Names Snapshot Acquired", (self.names_snapshot or {}).get("acquired", "Not reported"))
        self._kv("PID/UID", "org.freedesktop.DBus dedicated credential methods")
        self._kv("Process Name", "/proc/<pid>/comm")
        self._kv("Supplementary Groups", "/proc/<pid>/status")
        self._kv("Security Label", "GetConnectionSELinuxSecurityContext (on selection)")

    def _meta_object(self, r):
        self.context_object = r.get("path", self.context_object)
        self.info.clear()
        path = r.get("path", "")
        self._section("OBJECT")
        self._kv("Path", path)
        if path and path != "/":
            self._kv("Parent Path", path.rsplit("/", 1)[0] or "/")
        self._kv("Service", self.context_service)
        self._kv("Unique Owner", self.context_owner)
        self._kv("State", r.get("state"))
        if r.get("error"):
            self._kv("Error", r.get("error"))
        intro = r.get("introspection")
        self._section("INTROSPECTION")
        if intro:
            children = intro.get("children", [])
            self._kv("Interfaces", len(intro.get("interfaces", [])))
            self._kv("Declared Children", len(children))
            inspected = sum(bool((self.object_records.get(child.get("path")) or {}).get("introspection")) for child in children)
            self._kv("Inspected Child Objects", f"{inspected} of {len(children)}")
            self._kv("Acquired", intro.get("acquired", "Not reported"))
            for index, iface in enumerate(intro.get("interfaces", []), 1):
                self._kv(f"Interface {index}", iface.get("name", ""))
            for index, child in enumerate(children, 1):
                self._kv(f"Child {index}", child.get("path", ""))
            self._annotation_details(intro.get("annotations", []))
        else:
            self._kv("Acquisition", "Not acquired")
        self._section("SOURCE")
        self._kv("Method", "org.freedesktop.DBus.Introspectable.Introspect")
        self._kv("Destination", self.context_owner or "Not selected")
        self._kv("Safety", "Unique owner destination prevents service activation/replacement substitution.")

    def _meta_interface(self, r):
        self.context_interface = r.get("name", self.context_interface)
        iface = r.get("interface") or {}
        self.info.clear()
        self._section("INTERFACE")
        self._kv("Name", r.get("name"))
        self._kv("Object Path", self.context_object)
        self._kv("Service", self.context_service)
        self._kv("Unique Owner", self.context_owner)
        self._section("MEMBERS")
        self._interface_overview("Methods", iface.get("methods", []))
        self._interface_overview("Properties", iface.get("properties", []))
        self._interface_overview("Signals", iface.get("signals", []))
        self._annotation_details(iface.get("annotations", []))
        self._section("SOURCE")
        self._kv("Definition", "Introspection XML already acquired for selected object")
        self._kv("Acquired", (self.object_cache.get(self.context_object) or {}).get("acquired", "Not reported"))

    def _args_meta(self, args, heading):
        self._section(heading)
        if not args:
            self._kv("Arguments", "None declared")
            return
        self._kv("Arguments", len(args))
        for index, arg in enumerate(args, 1):
            self._kv(f"Argument {index}", arg.get("name") or f"arg{index}")
            self._kv(f"Type {index}", signature_detail(arg.get("type", "")))
            if arg.get("direction"):
                self._kv(f"Direction {index}", arg.get("direction"))
            self._annotation_details(arg.get("annotations", []), heading=f"ARGUMENT {index} ANNOTATIONS")

    def _meta_member(self, r):
        member = r.get("member") or {}
        self.info.clear()
        kind = r.get("kind", "Member")
        self._section(kind.upper())
        self._kv("Name", r.get("name"))
        self._kv("Interface", self.context_interface)
        self._kv("Object Path", self.context_object)
        if kind == "Method":
            args = member.get("args", [])
            inputs = [arg for arg in args if arg.get("direction") != "out"]
            outputs = [arg for arg in args if arg.get("direction") == "out"]
            self._kv("Input Signature", signature_detail("".join(a.get("type", "") for a in inputs)))
            self._kv("Output Signature", signature_detail("".join(a.get("type", "") for a in outputs)))
            self._args_meta(inputs, "INPUT ARGUMENTS")
            self._args_meta(outputs, "OUTPUT ARGUMENTS")
            self._section("SAFETY")
            self._kv("Invocation", "Not available — methods are API metadata only")
        elif kind == "Signal":
            self._kv("Signature", signature_detail(r.get("signature", "")))
            self._args_meta(member.get("args", []), "SIGNAL ARGUMENTS")
            self._section("SAFETY")
            self._kv("Subscription", "Not available — signal definitions only; no live monitoring")
        else:
            self._kv("Type", signature_detail(r.get("signature", "")))
            self._kv("Access", r.get("access"))
            safe, reason = property_value_safe(r.get("signature", ""))
            self._section("VALUE")
            self._kv("State", r.get("value_state"))
            if r.get("value_state") == "Available":
                self._kv("Value", r.get("value_display", ""))
                self._kv("Value Acquired", r.get("value_acquired", "Not reported"))
            elif not safe:
                self._kv("Safety", reason)
            elif "read" not in r.get("access", ""):
                self._kv("Readability", "Property is not declared readable")
            else:
                self._kv("Acquisition", "Use Read Property for a single explicit Properties.Get")
        self._annotation_details(member.get("annotations", []))
        self._section("SOURCE")
        self._kv("Definition", "Introspection XML")
        self._kv("Object Inspected", (self.object_cache.get(self.context_object) or {}).get("acquired", "Not reported"))
        self._kv("Destination", self.context_owner)

    # ----- actions -------------------------------------------------------------
    def _inspect_selected(self):
        r = self._current_record()
        if not r or not self.client or self.current_view != "Names":
            return
        if r.get("node_type") == "name":
            if not r.get("owner") or r.get("kind") == "Bus" or r.get("state") == "Activatable":
                return
            self._start_object_context(r.get("name"), r.get("owner"))
        elif r.get("node_type") == "object":
            self._inspect_object(r)

    def _read_selected_property(self):
        r = self._current_record()
        if r and self.current_view == "Names" and r.get("node_type") == "member":
            self._read_property(r)

    def _read_property(self, r):
        safe, reason = property_value_safe(r.get("signature", ""))
        if not safe:
            self.set_status(reason)
            return
        if "read" not in r.get("access", ""):
            self.set_status("Property is not declared readable.")
            return
        if not self.client or not self.context_owner or not self.context_object or not self.context_interface:
            return
        identity = r["identity"]
        try:
            value = self.client.get_property(self.context_owner, self.context_object, self.context_interface,
                                             r.get("name", ""), r.get("signature", ""))
            r["value_obj"] = value
            r["value_display"] = format_dbus_value(value, r.get("signature", ""))
            r["value_state"] = "Available"
            r["value_acquired"] = datetime.now().astimezone().isoformat(timespec="seconds")
            self.set_status(f"Read property {self.context_interface}.{r.get('name')} from existing owner {self.context_owner}.")
        except Exception as exc:
            r["value_state"] = self._error_state(exc)
            r["value_display"] = ""
            self.set_status(f"Property read failed: {exc}")
        self.member_records[identity] = r
        self._render_names_tree(select_key=("member", self.context_owner, identity[2], identity[3], identity[0], identity[4]))

    def refresh_active(self):
        if self.client is None:
            self._connect_bus()
            if self.client is None:
                return
        # Refresh List is always a deliberate base-inventory refresh. It does
        # not silently re-introspect objects or read property values.
        self._reset_deep_context()
        self.names_snapshot = None
        if self.current_view == "Names":
            self._load_names()
        else:
            self._load_connections()

    def open_options(self):
        DBusOptionsDialog(self).exec()

    def _acquired_tree_export(self):
        """Flatten only the already-acquired tree; no D-Bus calls."""
        records = []
        def walk(node):
            r = node["record"]
            kind = node["kind"]
            entry = {
                "label": node["label"], "kind": kind, "state": node["state"],
                "owner": r.get("owner", self.context_owner if r.get("node_type") != "name" else ""),
                "object_path": r.get("path", ""),
                "interface": r.get("interface_name", r.get("name", "") if r.get("node_type") == "interface" else ""),
                "signature": r.get("signature", ""),
                "access": r.get("access", ""),
                "acquired_value": (r.get("value_display", "") if self.export_include_values and r.get("value_state") == "Available" else ""),
            }
            records.append(entry)
            for child in node["children"]:
                walk(child)
        for root in self._full_names_model():
            walk(root)
        return records

    def export_current_view(self):
        sections = {"Safety": "Export contains only already-acquired records; no introspection, property reads, bus refresh or service activation."}
        if self.current_view == "Names":
            columns = [("label", "Name / Path"), ("kind", "Type"), ("state", "State"),
                       ("owner", "Owner"), ("object_path", "Object Path"), ("interface", "Interface"),
                       ("signature", "Signature"), ("access", "Access")]
            if self.export_include_values:
                columns.append(("acquired_value", "Acquired Value"))
            records = self._acquired_tree_export()
        else:
            columns = VIEW_COLUMNS["Connections"]
            records = [{cid: r.get(cid, "") for cid, _label, *_ in columns} for r in self.records_by_view["Connections"]]
        if not records:
            QMessageBox.information(self, "Export", "There is no acquired data in the current view to export.")
            return
        if self.context_owner:
            sections["Deep inspection context"] = f"Service: {self.context_service}\nUnique owner: {self.context_owner}"
        path = export_records_dialog(self, f"{APPLET_NAME} — {self.current_view}", records, columns=columns, sections=sections)
        if path is not None:
            self.set_status(f"Exported current {self.current_view} snapshot to {path}.")


def create_applet(parent=None):
    return DBusInspectorTab(parent)
