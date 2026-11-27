# INI bundle dialects

An INI bundle is a set of logical files that together define a test station's flow. `validate_ini_bundle`, `compare_plan_to_bundle`, and `compose_ini_bundle` take the files as text; nothing is executed or written to disk. Every request names its `dialect` explicitly.

## Files

- `MAIN_FLOW.ini` is required. It holds the `[TEST FLOW:<name>]` sections and the sections they call.
- `MACRO_LIST.ini` is needed to check `MACRO` targets; without it, macro rows are unchecked.
- Composition needs all six files: `MAIN_FLOW.ini`, `MACRO_LIST.ini`, `FACTORY_SETTING.ini`, `PARAMETER_LIST.ini`, `RD_SETTING.ini`, and `TEST_SPEC.ini`.
- File names are unique case-insensitively and use only ASCII letters, digits, `_`, `-`, or `.`.
- `selected_flow` names the flow to analyse, such as `[TEST FLOW:Normal]`.

Each row is `LABEL = "DEVICE|FUNCTION|PARAMETER|CRITERIA|TIMEOUT|PASS|FAIL|ERROR_CODE"`. The quoted value is a Script line; see `docs://script-grammar`.

## `hh5k`

The current station dialect, and the only one `compose_ini_bundle` supports.

- Seven core fields plus an optional eighth error code. Fields beyond the eighth are an error.
- Timeout is decimal digits (zero allowed) or `NULL`. This is looser than `compose_line`, which needs a positive integer.
- Pass and fail targets are a label in the same section or an uppercase control token: `NEXT`, `QUIT`, `FAIL`, `PASS`, or `END`. Mixed-case tokens are an error.
- A nonempty error code must be `ERRCODE:<token>` or `ErrorCode:<token>` (case-insensitive). Its meaning stays opaque.
- Dispatch suffixes `#QUICK` and `#PROXY` are known; others are preserved and unchecked.
- Embedded double quotes inside the outer quotes are literal payload bytes. A missing closing quote is invalid.

## `checker_legacy`

Matches the older script checker for historical bundles.

- Embedded double quotes are reported as `MALFORMED_QUOTE`.
- Extra fields and mixed-case control tokens are reported as unchecked (incomplete), not as errors, because legacy runtime behaviour is unproven.
- It never repairs or normalizes text.

## Validation layers

Findings are grouped into `structure`, `control_flow`, `references`, and `catalog` layers, each `valid`, `invalid`, or `incomplete`.

- `*V:` references resolve against the supplied files, including indirect references, up to a depth of 16. Deeper chains and cycles report `REFERENCE_LIMIT`.
- Values written at runtime report `RUNTIME_VALUE_UNCHECKED`; supply `runtime_bindings` for known values.
- `sensitive_values` are redacted from the report.

## Plans and drafts

`compare_plan_to_bundle` checks structured test-plan requirements against a bundle for an explicit `flow_variant` (`normal` or `sampling`). `compose_ini_bundle` returns a read-only draft and diff for the HH5K Wireless Test_2 station. Missing limits, settings, or unsupported encodings appear as blockers. Export needs separate user approval.
