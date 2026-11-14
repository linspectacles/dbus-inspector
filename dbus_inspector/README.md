# D-Bus Inspector 0.0.9

A read-only LinSpectacles applet for inspecting the Linux system and session message buses without becoming a command console or live bus monitor.

## Inventories and navigation

- **Names** — the primary D-Bus name inventory (well-known, unique and activatable names), with a Cgroups-style tree for an explicitly inspected service. After selecting a running service, **Inspect Service...** acquires its root object. The resulting tree shows **object paths → interfaces → methods/properties/signals**, all within Names.
- **Connections** — a separate inventory of live unique peers, PID/UID and process context, with a lazily read security label for the selected connection. Selecting a connection updates Metadata Details without inspecting its service or changing to Names; there is no Inspect Service... action in this view.
- **Tree selection and expansion** — selecting or expanding an already-discovered branch only displays cached information. It does **not** send a D-Bus introspection request. An unknown child object is marked **Not inspected**; select it and choose **Inspect Object...** to acquire its XML. An inspected object can be deliberately queried again with **Refresh Object...**.
- **Properties** — a readable property with a supported signature exposes **Read Property**. It performs only a single explicit `Properties.Get` request. Methods and signals are definitions, not executable or subscribed actions.
- Only one service's deep object tree is held at a time. Inspecting another service clears the earlier deep context; it does not change the underlying Names or Connections inventories.

## Interface

- Upper row: bold inventory count, relevant contextual inspection action (hidden when unavailable), **Refresh List**, **Options...**. The **Names / Connections** inventory radios now live in **Options → Configuration**, following the Systemd Inspector pattern; **Ctrl+I** toggles the inventory.
- Filter row: **Search**, an inventory-specific **Filter**, and the exclusive **System / Session** bus radio buttons.
- Switching System / Session keeps the selected primary inventory, discards the previous bus's deep tree, and reloads the new bus's relevant inventory.
- The Names filters use D-Bus names/ownership concepts: **All Names, Well-known, Unique, Owned, Activatable**. Connections uses **All Connections, Owns well-known names, This Inspector**. Tree search retains ancestors of matching already-acquired records, without acquiring additional objects.
- Metadata Details always corresponds to the currently selected visible tree/table item and clears on empty filtered results.
- Metadata Details explains D-Bus argument/property signatures in plain language while preserving their raw type codes, interprets recognised standard introspection annotations alongside their original name/value pairs, and presents cached ownership, object-child, interface/member and acquisition context.
- The orientation-specific Metadata Details margins and default proportions follow Kernel Modules (`[480, 700]` horizontal, `[430, 330]` vertical), with saved splitter sizes retained when valid.
- Options → Configuration includes the Names/Connections inventory radios, a short explanation of both, and the shortcut summary: **Ctrl+I** toggles inventory; **F4** activates the available Inspect Service..., Inspect Object..., or Refresh Object... action (nothing when none is visible); **F3** toggles Metadata Details; **Ctrl+L** toggles horizontal/vertical arrangement; **Shift+F5** explicitly refreshes the current primary inventory; **Ctrl+/** opens Options.
- Column visibility (right-click headers), widths and Connections sorting persist. Previously saved System/Session, primary View and filter preferences are preserved where applicable.
- Export contains the already acquired primary inventory; for Names it also includes the acquired deep tree. Property values are included only if explicitly read and the Export option is selected. Export never acquires data.

## Safety contract

- Deep introspection uses an already-running **unique owner** (`:1.x`), never an inactive activatable well-known name.
- No `StartServiceByName`, arbitrary method invocation, `Properties.Set`, `Properties.GetAll`, name requests/releases, activation-environment changes, bus reload, signal subscription, `BecomeMonitor`, eavesdropping or traffic capture.
- Property reads are explicit `Properties.Get` requests. Declared UNIX_FD (`h`) and Variant-bearing (`v`) property signatures are not read.
- No cross-applet navigation or relation engine; specialist names in Metadata Details remain informational only.

The applet uses **libsystemd sd-bus directly**; `busctl`, `gdbus`, `dbus-send` and `dbus-monitor` are not data providers.

## Project identity

- **Suite:** LinSpectacles — Linux Inspection Suite
- **Tagline:** Expose. Explore. Explain.
- **Applet ID:** `linspectacles-dbus-inspector`
- **Python package:** `linspectacles_dbus_inspector`
- **Organisation ID:** `linspectacles`
- **Author / editor / publisher:** `brunonlinespace`
- **Organisation:** https://github.com/linspectacles/
- **Repository:** https://github.com/linspectacles/dbus-inspector

GPL-3.0-or-later.
