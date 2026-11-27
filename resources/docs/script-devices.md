# Script devices

## Script device versus Device scope

| Term | What it is | Where it appears |
|---|---|---|
| **Script device** | The first field of a Script line, such as `SSH` or `DLLQSPR#QUICK`. It is the engine dispatch target. | `device` argument of line and discovery tools |
| **Device scope** | The Device name on a definition, link, or Example. Blank means Global (shared) knowledge. | `device_scope` argument; `resolution` labels `global`/`scoped` |
| **Interface** | The channel or family a Function executes through, such as `SSH`, `QSPR`, or `WIFI_TEST`. | Function identity `(source, interface, name)` |

Do not pass a Device scope as `device`, or a Script device as `device_scope`.

## Forming a Script device

- **BUILT-IN** Functions use the Interface as the Script device: `SSH`.
- **DLL** Functions prefix the Interface with `DLL`: Interface `WIFI_TEST` gives `DLLWIFI_TEST`.
- A DLL Script device may carry an execution-mode suffix after `#`. The audited suffixes are uppercase `#QUICK` and `#PROXY`, such as `DLLQSPR#QUICK`. The suffix selects a mode; the Function is still resolved on the base Interface. Other suffixes are preserved and reported as unchecked.
- `list_devices` returns every reachable Script device with its source, Interface, accepted mode suffixes, and Function counts.

## Interface aliases

Discovery tools (`get_device`, `list_functions`, `get_function`, `list_function_fields`, `list_examples`, `get_function_readiness`, `suggest_criteria`, and the `catalog://` resources) also accept a bare Interface name when it maps to exactly one Script device. `WIFI_TEST` resolves to `DLLWIFI_TEST`. Such results carry `script_device` and `matched_by: "interface"`.

Line tools (`compose_line`, `validate_line`, `parse_line`) dispatch on the literal Script device and never alias. An unknown Script device returns `unknown_device` with close `candidates`.

## Device scope resolution

- When `device_scope` is omitted, it defaults to the resolved Interface.
- Links with the matching scope override Global links with the same name.
- Each linked definition resolves at the exact scope first, then Global. Unrelated scopes are never merged.
