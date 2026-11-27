# Script line grammar

A Script line is one pipe-delimited Function invocation. The server composes and validates lines; it never executes them.

## Fields

| Convention | Shape |
|---|---|
| convention 1 | `DEVICE\|FUNCTION\|PARAMETER\|CRITERIA\|TIMEOUT` (five fields) |
| convention 2 | `DEVICE\|FUNCTION\|PARAMETER\|CRITERIA\|TIMEOUT\|PASS_PATH\|FAIL_PATH\|ERROR_CODE` (eight fields) |

- `DEVICE` is the Script device; see `docs://script-devices`.
- `FUNCTION` is the Function name on that Script device.
- `PARAMETER` and `CRITERIA` follow the Function's Grammar profile (below).
- `TIMEOUT` is an explicit positive integer in milliseconds. `compose_line` never fills a default.
- Convention 2 needs nonempty `PASS_PATH` and `FAIL_PATH`. `ERROR_CODE` is an opaque token; an absent code is an empty eighth field, so the trailing `|` stays. Flow fields on a convention 1 Function are rejected.
- `validate_line` also accepts historical seven- and nine-field convention 2 lines with compatibility warnings. Composition emits only five or eight fields.
- `|`, CR, and LF are forbidden inside every field. There is no escaping scheme.
- A line starting with `;` or `//` is a comment; `validate_line` reports it as `commented_line`.

## Grammar profiles

Each Function has a Grammar profile that fixes how its parameter and criteria fields are encoded. The server implements two encodings:

- **Named**: `KEY=value` assignments joined with `&`, such as `ANT=1,2&POWER=5dB`. Dictionary names can differ from emitted keys (`QSPR_ROOT` is emitted as `Root`). Duplicate keys are rejected.
- **Raw**: the whole field is one payload, such as an SSH command. `&` and `=` are preserved as literal text.

Functions without an audited Named or Raw profile have no machine-checked encoding.

Write `NULL` in the criteria field when there are no criteria. Criteria are named comparisons (`Remainder=0&Power=5dB`) or a raw expectation when the profile allows one. Unknown criteria keys are preserved with warnings.

Only audited profiles can be composed. Other Functions return `unsupported_grammar` instead of a guessed encoding; use `get_function_readiness` to check.

## SINGLE and MULTIPLE values

A parameter definition is `SINGLE` or `MULTIPLE`. In `compose_line` arguments, pass a string for `SINGLE` and an array of strings for `MULTIPLE`. `MULTIPLE` values are comma-joined inside one field (`ANT=1,2,4,8`). Cardinality never changes the separator between definitions. Defaults are never applied automatically; the link's `required` flag is authoritative.

## References

| Form | Meaning | Line-tool treatment |
|---|---|---|
| `*V:Section-Key#` | One INI bundle value | Preserved; Warning `bundle_reference_unchecked` |
| `*V:Section#` | A whole INI section merged into named fields | Named profiles only; see below |
| `*E:...#`, `*I:...#`, `*T:...#` | Engine runtime references | Preserved; Warning `runtime_reference_unchecked` |

- A whole `*V:Section#` token in the parameter or criteria field is a section reference. `compose_line` takes these as `param_sections` and `criteria_sections` and emits them first, joined with `&`. Required fields they may supply become optional with Warning `required_from_section`.
- A value that is exactly one reference skips its pattern check. An embedded reference (`TX_TARGET_POWER=*V:Limits-Power#dBm`) is masked before the pattern is matched.
- Each `*X:` opener needs its own `#`. Unknown prefixes, empty payloads, and missing terminators are `invalid_reference`.
- A single line has no bundle, so references are never resolved. `validate_ini_bundle` resolves `*V:` references against supplied files.

## Validation status

`validate_line` reports `valid`, `invalid`, or `incomplete` with field-level diagnostics. Any violation makes a line `invalid`. Otherwise, unchecked items (runtime references, unsupported patterns, unresolved sections) make it `incomplete`.
