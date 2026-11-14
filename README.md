# D-Bus Inspector

**Expose. Explore. Explain.**

D-Bus Inspector is a graphical read-only explorer for the Linux system and session D-Bus. It exposes names, live connections, object paths, interfaces and declared members while deliberately avoiding service activation, arbitrary method calls and traffic monitoring.

Current release: **0.0.9**

Repository: <https://github.com/linspectacles/dbus-inspector>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/dbus-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/dbus-inspector.png"
      alt="D-Bus Inspector screenshot"
      width="900"
    >
  </a>
</p>

## What D-Bus Inspector is

D-Bus Inspector is designed to make the object model of an **already-running D-Bus environment** inspectable without turning the application into a D-Bus command console.

It works from bus-manager inventory through progressively deeper, user-directed inspection. Deep introspection is sent to an already-running **unique owner** (`:1.x`) rather than to an inactive activatable well-known name.

## Highlights

- Separate **System** and **Session** bus inspection.
- Five views: Names, Connections, Objects, Interfaces and Members.
- Well-known, unique and activatable name inventory with ownership state.
- Live connection PID/UID context and visible well-known-name ownership.
- Lazy object-path discovery through `org.freedesktop.DBus.Introspectable.Introspect`.
- Declared methods, properties, signals, signatures, access and annotations.
- Readable property values acquired only through an explicit one-at-a-time **Read Property** action.
- Direct `libsystemd` **sd-bus** transport; `busctl`, `gdbus`, `dbus-send` and `dbus-monitor` are not data providers.
- No service activation, arbitrary method invocation, eavesdropping or traffic capture.
- Search/filter state, view state, table/splitter presentation and Metadata Details are persisted.

## Views

### Names

Shows well-known, unique and activatable names, ownership state, unique owner where applicable and limited specialist context for known services.

### Connections

Shows live unique peers with PID, UID, compact process identity and owned well-known names. SELinux connection security context is acquired lazily for the selected connection.

### Objects, Interfaces and Members

Object paths are discovered through D-Bus introspection against the selected running owner. Interfaces expose their declared methods/properties/signals, and Members presents signatures, property access and annotations.

Property reads use `org.freedesktop.DBus.Properties.Get` only after explicit user action. Declared UNIX_FD (`h`) and Variant-bearing (`v`) property types are intentionally not read in this release.

## Data sources and transport

D-Bus Inspector talks directly to D-Bus through `libsystemd` sd-bus. Important calls include:

- `org.freedesktop.DBus.ListNames`
- `ListActivatableNames`
- `GetNameOwner`
- `GetConnectionUnixProcessID`
- `GetConnectionUnixUser`
- `GetConnectionSELinuxSecurityContext` when explicitly needed
- `org.freedesktop.DBus.Introspectable.Introspect`
- `org.freedesktop.DBus.Properties.Get`

`/proc/<pid>/comm` and `/proc/<pid>/status` provide limited process-label/group context only.

## Interface and export

The top row contains the current View, contextual inspection actions, Refresh and Options. Contextual buttons are hidden when they do not apply rather than being presented as permanently disabled commands.

Search, view-specific filtering and the System/Session bus selector sit on the second row. Export uses only already-acquired records and does not trigger deeper inspection.

## Read-only guarantees

There is no `StartServiceByName`, arbitrary method invocation, `Properties.Set`, `Properties.GetAll`, bus-name request/release, activation-environment modification, bus reload, signal subscription, `BecomeMonitor`, eavesdropping or traffic capture.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details layout | `Ctrl+L` |
| Refresh active inventory / snapshot | `Shift+F5` |
| Options | `Ctrl+/` |

The in-application interface remains authoritative for context-specific actions that do not have a global shortcut.

## Running from source

The current source is directly runnable on Linux. Runtime requirements are deliberately kept separate from distribution packaging:

- Python 3.
- PyQt6 for the graphical interface.
- Linux with D-Bus available for the selected bus scope.
- `libsystemd.so.0`, used directly through sd-bus.

A local virtual environment is a straightforward way to run the applet without installing its Python GUI dependency into the system Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_dbus_inspector/standalone.py
```

If PyQt6 is already provided by the Python environment you intend to use, the virtual-environment step is optional.

The standalone launcher is the canonical direct source entrypoint in this source package.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_dbus_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── dbus_inspector/
    ├── applet.py
    ├── _metadata_semantics.py
    ├── _support.py
    ├── dbus_backend.py
    ├── icon.png
    └── README.md
```

`applet.json` provides the LinSpectacles applet identity and entrypoint metadata, while `create_applet()` in `applet.py` provides the host-loadable widget factory. `standalone.py` launches the same applet as an independent window.

## Configuration

UI preferences are stored through Qt `QSettings` under the `brunonlinespace` organisation and the applet’s application name. The exact persisted presentation fields depend on the applet, but are limited to UI/inspection presentation state such as view/filter choices, columns, sorting, splitter/layout state and Metadata Details where implemented.

The applet does not use configuration persistence as a path to modify the inspected Linux subsystem.

## Scope

D-Bus Inspector owns declarative bus/object/member inspection. It is not a D-Bus monitor, signal recorder, service controller or generic IPC tracer.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/dbus-inspector>
- Issues: <https://github.com/linspectacles/dbus-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/dbus-inspector">
    <img
      src="dbus_inspector/icon.png"
      alt="D-Bus Inspector"
      width="256"
    >
  </a>
</p>
