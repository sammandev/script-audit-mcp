# Script Audit

Rust MCP server for function discovery and validated test-script composition. The default transport is stdio; `--http` serves the MCP Streamable HTTP transport. The server reads the shared PostgreSQL function catalog and never creates a database, runs migrations, or changes catalog rows.

## Database configuration

Supply credentials through the process environment, outside the repository:

```bash
export SCRIPT_AUDIT_DATABASE_URL='postgresql://script_forge@10.176.2.139:5432/program_functions?sslmode=verify-full'
read -rsp 'MCP database password: ' PGPASSWORD
printf '\n'
export PGPASSWORD
```

`SCRIPT_AUDIT_DATABASE_URL` takes precedence over `DATABASE_URL`. `PGPASSWORD` supplies the password when absent from the URL; embedded URL passwords must be percent-encoded. Set `PGSSLROOTCERT` for a private PEM CA. TLS is certificate-verified by default; plaintext requires explicit `sslmode=disable`. The native-TLS client also keeps certificate verification enabled for `sslmode=require`.

The old `--db` argument and `SCRIPT_FORGE_DB` file configuration are removed. Missing configuration, connection failures, and incompatible schemas fail startup. `--help` writes usage to stderr; stdout is reserved for MCP messages. Every request reads the six catalog tables in a read-only repeatable-read transaction on a blocking worker. Use a SELECT-only database login as a second write barrier.

Example stdio client configuration, replacing the binary path and inheriting its password from a protected launch environment:
Existing MCP clients must update their command and project-specific database URL variable to the new names shown below.

```json
{
  "mcpServers": {
    "script-audit-mcp": {
      "command": "/absolute/path/to/script-audit-mcp",
      "env": {
        "SCRIPT_AUDIT_DATABASE_URL": "postgresql://script_forge@10.176.2.139:5432/program_functions?sslmode=verify-full"
      }
    }
  }
}
```

Stdio clients launch the process themselves. HTTP clients connect to the
Streamable HTTP endpoint; see [HTTP hosting on Ubuntu](#http-hosting-on-ubuntu).

## HTTP Hosting On Ubuntu

`--http` starts the MCP Streamable HTTP listener; `--host` and `--port` select
the bind address (CLI default `127.0.0.1:8080`, endpoint `/mcp`). The Ubuntu
systemd unit instead binds `127.0.0.1:39065`; Nginx exposes
`http://10.176.2.139:39064/mcp` to explicitly allowed LAN/VPN clients.

The current operator choice is **plain HTTP without authentication**. Every
allowed client can invoke every MCP tool, and request/response contents are
unencrypted. Host and Origin checks do not authenticate callers. Company-policy
approval and an explicit client IP/CIDR allowlist are deployment prerequisites;
the supplied Nginx template denies remote clients until that list is configured.
Database credentials stay in the server environment.

Follow [the Ubuntu deployment runbook](deploy/README.md) for prerequisites,
protected environment configuration, installation, session-aware smoke checks,
VS Code/OpenCode/Claude Code setup, and rollback. This deployment neither
installs a database engine nor changes the catalog schema. Deployment remains
manual and user-run; the agent does not access Ubuntu or any database.

## Tools

| Tool | Arguments |
| --- | --- |
| `list_functions` | Optional `device`; returns functions and composition-support metadata |
| `get_function` | `device`, `name`, optional `device_scope`; returns metadata, linked definitions, patterns, examples, diagnostics |
| `suggest_criteria` | `device`, `function`, optional `device_scope`; returns known criteria and examples |
| `compose_line` | `device`, `function`, `params`, `criteria`, `timeout`, optional `device_scope`, `pass_path`, `fail_path`, `error_code` |
| `validate_line` | `line`, optional `device_scope`; returns `valid`, `invalid`, or `incomplete`, original segments, and diagnostics |
| `validate_ini_bundle` | `files`, `selected_flow`, `dialect`, optional `device_scope`, `runtime_bindings`, `sensitive_values`; returns preserved source and layered bundle findings |
| `compare_plan_to_bundle` | `bundle` (the validation arguments), `plan`, explicit `flow_variant` (`normal` or `sampling`); returns sourced coverage, conflicts, blockers, and the shared validation report |
| `compose_ini_bundle` | `comparison` (plan-comparison arguments), `flow_anchor`, optional `review`, `draft_approval`, `template_pack`, `procedure_templates`, `station_settings`, `report_metadata`; returns a read-only INI draft preview |

`device` is the script dispatch token, such as `SSH` or `DLLWIFI_TEST`. DLL mode suffixes `#QUICK` and `#PROXY` are preserved. `device_scope` selects knowledge separately; it defaults to the resolved interface. Matching scope overrides Global links by name. Definitions resolve at the link's own scope, then Global. Unrelated scopes are excluded.

`params` uses canonical dictionary names. `SINGLE` takes a string; `MULTIPLE` takes an array of strings. Defaults are not filled automatically. Requiredness comes from the link. Timeout is an explicit positive integer in milliseconds.

Convention 1 emits five fields. Convention 2 emits eight and requires pass/fail targets. An absent error code leaves the final field empty, including its trailing `|`. Error codes are opaque. Validation accepts historical seven/nine-field convention-2 input with warnings and retains every segment.

For compatible WiFi metadata, a composition request has this shape:

```json
{
  "device": "DLLWIFI_TEST",
  "function": "TX_MULTI_VERIFICATION",
  "params": {"ANT": ["15", "2"]},
  "criteria": {"POWER": "5dB"},
  "timeout": 20000,
  "pass_path": "NEXT",
  "fail_path": "FAIL"
}
```

This request is tested against a synthetic catalog, not against the deployment's rows. The actual schema may require additional parameters or reject these values.

## Composition Coverage

Initial profiles cover these encodings, only when the selected metadata is compatible:

- Raw SSH payload: `OPEN`, `CLOSE`, `SENDSTR`, `SENDSTR_AND_WAITSTR`, `WAITSTR`, convention 1. Exactly one parameter definition and at most one criteria definition. Raw criteria use a string.
- Named WiFi payload: `DLLWIFI_TEST` / `TX_MULTI_VERIFICATION`, convention 2. Known parameter keys are `ANT`, `STANDARD`, `FREQ`, `BW`, `TX_TARGET_POWER`; the known criteria key is `POWER`. Named criteria use a map.

Other functions remain discoverable and return explicit unsupported diagnostics. Positional encodings and QSPR dictionary-to-script aliases are not implemented. Composition-support metadata means the profile and selected definitions pass static checks; it does not prove compatibility with an external script engine. Production database contents have not been queried or tested during this implementation.

Patterns are descriptive templates: literal text with `<name>` placeholders, or a uniform repeated MULTIPLE template such as `<ant1>,<ant2>...`. Supported types are `string`, `int`, `double`, and `list[int]`. Allowed values may be empty, `{a,b}`, or a finite numeric range `[lower..upper]`. Missing patterns, unsupported optional syntax, unknown types, and orphan links block composition.

Pipes and line breaks are forbidden; there is no escaping scheme. Named assignments reserve `&` and `=`; raw payloads preserve them. Duplicate assignment keys are invalid. Unknown parameter keys are rejected. Unknown named criteria are retained with warnings after syntax checks. Omitted optional criteria, including an empty criteria map, emit `NULL`. A supplied empty field value is rejected.

`*E:`, `*I:`, and `*T:` require a nonempty payload and are preserved with a warning. Runtime targets and resolved values are unchecked. Flow targets are also not checked against a runtime script. `valid` means the available static checks found no violation; inspect warnings. Known violations outrank incomplete checks.

Domain failures are MCP tool errors with structured `error.code`, `error.message`, and `error.diagnostics`. Validation failures return a normal report with status `invalid`; they do not silently rewrite the submitted line.

## Checker Library Integration

INI bundle authoring ticket 01 supplies a pinned, portable checker dependency.
Its content-only API takes supplied logical names and text with an explicit flow;
it never discovers ambient files or opens runtime paths. Consumers read structured
findings and preserved source text. See the [snapshot contract and limitations](vendor/script-checker-0.1.0/README.md).
Tickets 02-04 add bundle validation while the five original tools retain their
contracts. No database schema or connection policy changes are needed.

## Bundle Validation

Call `validate_ini_bundle` with supplied contents, never server filesystem paths:

```json
{
  "files": [
    {
      "name": "MAIN_FLOW.ini",
      "text": "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLLQSPR#QUICK|FUNC|ANT=1|POWER=5dB|NULL|QUIT|FAIL|ERRCODE:opaque\"\n"
    }
  ],
  "selected_flow": "[TEST FLOW:Normal]",
  "dialect": "hh5k",
  "device_scope": "QSPR",
  "runtime_bindings": []
}
```

`MAIN_FLOW.ini` is required. Supply `MACRO_LIST.ini` to inspect macro targets;
other logical files are optional during partial validation. Names are unique
case-insensitively and contain only ASCII letters, digits, `_`, `-`, or `.`.
Paths and URLs are rejected. References in supplied text never trigger filesystem
or network reads. Each accepted request uses one existing blocking, read-only,
repeatable-read catalog snapshot for all Function and scoped definition checks.

The `hh5k` dialect accepts seven core fields and an optional eighth error code.
The third field is PARAM and the fourth is CRITERIA. Decimal numeric timeouts
(including zero) and `NULL` match checker compatibility; this differs from the
positive timeout required by `compose_line`. Known dispatch suffixes are uppercase
`#QUICK` and `#PROXY`; other suffixes remain preserved and unchecked. An empty
eighth field is allowed. Nonempty codes require `ERRCODE:<token>` or
`ErrorCode:<token>` syntax, case-insensitively; their meaning remains opaque.
Five-field rows and extra fields are incompatible with strict bundle syntax.
No escaping scheme is defined for embedded quotes or pipes.

Control tokens are exact uppercase `NEXT`, `QUIT`, `FAIL`, `PASS`, and `END`.
Names containing those words are ordinary section-local labels. Labels follow the
checker's case-insensitive lookup and retry-label parsing; repeated labels and
their order remain preserved. The `checker_legacy` dialect additionally inspects
extra fields and mixed-case control tokens, reporting those checks incomplete
instead of asserting runtime compatibility. It does not repair or normalize text.

Flow implementation checks use `selected_flow`. Structural findings and local
branch/macro-target checks inspect the supplied main and macro sections, including
unselected sections. Execution evidence uses the selected flow. Duplicate headers and
ambiguous sections are errors. Missing closing quotes remain invalid even when
recovery finds downstream branch errors. A missing macro file leaves the
dependency incomplete; a supplied macro file lacking the called implementation
is invalid. Auxiliary files are inspected for duplicate headers and malformed
quotes but are not treated as executable flow files.

Results contain `layers.structure`, `layers.control_flow`, `layers.references`,
and `layers.catalog`, each `valid`, `invalid`, or `incomplete`. Diagnostics have
`severity` (`error`, `warning`, `unsupported`), `layer`, `code`, `message`, and
available `file`, `line`, `section`, `row`, `field`, and `evidence`. Lines are
one-based; unavailable locations are null. Any error makes the overall status
invalid. Each layer can report valid independently. With no known violations,
the overall result is incomplete if any layer has unchecked static work;
otherwise it is valid. Warnings do not promote unchecked results to valid.
`runtime_verification`, `hardware_verification`, and `packaging` stay unchecked.

### Catalog Compatibility

Execution rows resolve Functions by Source, Interface, and name using the same
scope rules as the original tools. Script device suffixes remain dispatch data;
they never select Device scope. Unaudited suffixes are preserved and keep the
affected checks incomplete. Macro calls use the supplied macro definitions,
while their expanded Function rows are checked separately for each invocation.
Catalog diagnostics include source locations and execution/call-site IDs.

The third bundle field supplies parameters and the fourth supplies criteria,
including supported static and per-call substitutions. Audited profiles check
link-based requiredness, types, cardinality, patterns, and allowed values.
Definitions never supply missing defaults. Bundle width, timeout, branch, and
Error code rules remain separate from the five/eight-field single-line contract;
raw SSH payloads retain literal `&` and `=` characters.

Unknown or ambiguous Functions and missing required inputs are errors. Orphan
links, insufficient definitions, unsupported profiles, and unknown named criteria
remain explicit incomplete checks. This stricter bundle treatment of unknown
criteria does not change `validate_line`'s historical warning behavior.
Unresolved reference values cannot establish catalog compatibility. Literal
assignments and literal elements in supported multiple-value fields are still
checked, so an unchecked value cannot hide a definite violation elsewhere.
No additional Function encodings or production-catalog compatibility are inferred
from these synthetic tests. The example above therefore reports an unknown
Function if that identity is absent from the request's actual catalog snapshot.

### Sourced Plan Comparison

The MCP client extracts and reviews requirements from documents or prompts, then
submits structured facts to `compare_plan_to_bundle`. Check source tables and
figures in the client when text extraction is insufficient. The server checks
the representation and supplied scripts; `interpretation_verification` remains
`unchecked_client_interpretation`. There is no server-side PDF reader or LLM.

This synthetic request illustrates the ticket 05 TX boundary. Its explicit EVM
comparison and catalog definitions do not certify the supplied station examples
or the production catalog:

```json
{
  "bundle": {
    "files": [{
      "name": "MAIN_FLOW.ini",
      "text": "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nTX=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|BAND=6G&ANT=1,2,4,8&STANDARD=11AG&FREQ=6115&BW=20&DATA_RATE=OFDM6&TX_TARGET_POWER=15.5dBm|POWER=-1~2dB&EVM=<-35dB|1|QUIT|FAIL\"\n"
    }],
    "selected_flow": "[TEST FLOW:Normal]",
    "dialect": "hh5k"
  },
  "flow_variant": "normal",
  "plan": {
    "controlling_source": "plan",
    "station": "HH5K Wireless Test_2",
    "sources": [{"id":"plan","revision":"3.8","kind":"test_plan","approved":true}],
    "requirements": [{
      "id": "TX-OFDM6",
      "applicability": "mandatory",
      "provenance": [{
        "source_id": "plan",
        "revision": "3.8",
        "location": "page 33, Table 17",
        "excerpt": "15.5 dBm target; EVM strictly below -35 dB"
      }],
      "test": {
        "technology": "wifi", "purpose": "tx", "band": "6G", "standard": "11AG",
        "frequency": {"value":6115,"unit":"MHz"},
        "bandwidth": {"value":20,"unit":"MHz"},
        "rate": "OFDM6",
        "chains": {"kind":"per_chain","value":[1,2,4,8]},
        "power_target": {"value":15.5,"unit":"dBm"},
        "power_tolerance": {"lower":-1,"upper":2,"unit":"dB"},
        "evm": {"operator":"lt","threshold":{"value":-35,"unit":"dB"}}
      },
      "depends_on": [],
      "unresolved_questions": []
    }],
    "conflicts": [],
    "exceptions": [],
    "unresolved_questions": []
  }
}
```

Source kinds are `test_plan`, `prompt`, and `example`. The controlling source
needs an explicit approved revision. Each requirement needs a stable ID and
current controlling-source provenance with a location or excerpt. Examples
provide patterns and cannot become controlling requirements. Approval fields
record supplied review evidence; the server cannot authenticate a reviewer.
Missing source facts and unresolved questions block readiness.`

Comparison uses reachable execution rows after supported static and macro-call
resolution. Supported Wi-Fi identities use `DLLWIFI_TEST` with
`TX_MULTI_VERIFICATION`, `RX_VERIFY_PER`, or `BRCM_RSSI_CALIBRATION`, including
audited dispatch suffixes. Bundle-only named key support includes `BAND`,
`DATA_RATE`, `FRAME_COUNT`, `EVM`, `RX_TARGET_POWER`, `PER`, and `RSSI`, with
compatible linked definitions still required. Original single-line profiles
and their composition support are unchanged.

Wi-Fi technology, purpose, band, standard, frequency, bandwidth, rate, antenna
representation, and target power must be specified. Wi-Fi TX comparison
supports explicit `wifi` / `tx` / `6G` cases. Frequency and bandwidth literals
use MHz; target power requires dBm. There is no channel/frequency conversion or
unit conversion. An optional `channel` remains unknown until conversion rules
are audited.

`per_chain` values are one-hot masks `1`, `2`, `4`, and `8`, rather than ordinal
chain numbers. Coverage can combine otherwise-matching reachable rows for these
individual masks. `bitmask` compares one literal composite value; `count` cannot
establish chain coverage. Composite `ANT=15` never proves individual-chain tests.

Power tolerances use dB. `POWER=1.5dB` represents a symmetric tolerance and
`POWER=-1~2dB` preserves asymmetric bounds. EVM comparison preserves the supplied
operator and threshold. Explicit `<` and `>` values are inspectable when the
catalog supports them; a bare threshold such as `EVM=-35dB` has unaudited
strict/inclusive semantics and stays unknown. The named grammar rejects another
`=` within a value, so `<=`/`>=` do not establish supported coverage. Structured
operators are `lt`, `le`, `eq`, `ge`, and `gt`; different operators do not match.
An optional TX packet count compares `FRAME_COUNT` exactly.

RX uses `purpose: "rx"` with the same operating dimensions and an `input_level`
in dBm instead of `power_target`. It requires `packet_count` and a `per`
comparison in percent. Supply `rssi_tolerance` where applicable. For example,
these synthetic acceptance fields accompany the RX operating dimensions:

```json
{
  "input_level": {"value":-60,"unit":"dBm"},
  "packet_count": 500,
  "per": {"operator":"lt","threshold":{"value":10,"unit":"%"}},
  "rssi_tolerance": {"lower":-6,"upper":6,"unit":"dB"}
}
```

The corresponding literal fields are `RX_TARGET_POWER=-60dBm&FRAME_COUNT=500`
and `PER=<10%&RSSI=-6dB~6dB`. Counts and thresholds must match exactly. RSSI
tolerance is a dB offset; it is not the dBm input level. Bare `PER=10%` does
not establish strict or inclusive acceptance. It remains unknown, including
when copied from the original example. The existing reserved-delimiter rule
also rejects `PER=<=10%`; structured `le` still differs from `lt`.

Wi-Fi RSSI calibration uses `purpose: "calibration"` with explicit `wifi`,
`6G`, `standard`, and `chains`, witnessed by `BRCM_RSSI_CALIBRATION`. Other
measurement fields are compared when specified. A scalar frequency requirement
is not proven by an unaudited frequency-list interpretation. No other
calibration Function is inferred from a section name.

For supported setup, save, or cleanup Functions, a requirement may instead use
`purpose: "setup"` (or `save` / `cleanup`) and a `procedure` object containing
exact `device`, `function`, `parameters`, and `criteria` strings. The Function
must pass the existing bundle catalog checks. This declaration cannot make an
unknown encoding supported or silently absorb measurement dimensions.

`depends_on` names requirement IDs in the selected flow. Ordering checks use
execution edges, including direct macro returns, rather than source-line or
requirement-list order. Every matching consumer must follow a successful
prerequisite. Per-chain prerequisites require success evidence for each chain.
Missing or mismatched prerequisites and bypass/failure paths block readiness;
uncertain graphs and undeclared dependencies remain unknown. These checks do
not execute commands or prove equipment state.

Bluetooth comparison uses `technology: "bluetooth"` and `purpose: "tx"` or
`"rx"`. Bundle-only profiles cover `DLLIOT` Functions `DUT_INSERT`,
`TX_MULTI_VERIFY`, and `RX_VERIFY_PER`; compatible catalog definitions and links
remain required. These profiles do not change single-line composition support.
Declare the exact supplied `DUT_INSERT` payload as a `procedure` requirement
with `technology: "bluetooth"`, `purpose: "setup"`, and `TECH=BT` in its
parameters. Use its requirement ID in each measurement's `depends_on`.
`IOT` alone does not establish Bluetooth: the same Interface serves other radios.
Setup must succeed before each measurement. A reachable radio reselection that
can reach a measurement without restoring its declared Bluetooth setup keeps
coverage unknown. Other setup Functions and station configuration remain
unsupported unless separately audited.

Bluetooth measurements require a sourced frequency in MHz and explicit antenna
representation. Wi-Fi band, standard, bandwidth, and rate fields do not apply to
this audited Bluetooth profile; supplying them leaves coverage unknown. The
IOT profile's bare `FREQ`, `TX_TARGET_POWER`, and `RX_TARGET_POWER` numbers use
MHz and dBm respectively. Explicit units must agree; no unit conversion runs.
For example, `TX_TARGET_POWER=20` with `POWER=-3~1` compares a 20 dBm target
and -3/+1 dB tolerance. `FREQ_ERROR_KHZ=-150~150` compares the structured field
`frequency_offset: {"lower":-150,"upper":150,"unit":"kHz"}`. Both offset
bounds must match, and dB power tolerances remain distinct from dBm targets.

Bluetooth RX compares `RX_TARGET_POWER=-87&FRAME_COUNT=500` against a sourced
-87 dBm input level and exactly 500 packets. `PER=<30.8%` establishes a strict
comparison below 30.8 percent; equality or an inclusive operator does not match.
The original example's bare `PER=30.8%` still has unknown comparison semantics.
These are synthetic verification cases, not approvals of real station settings.
Static supplied references can establish values; declared runtime bindings stay
unchecked even when they include a sample value. Wi-Fi rows cannot substitute
for Bluetooth coverage. Extra reachable Bluetooth measurements are reported
separately, and commented or unreachable rows never satisfy requirements.

The plan's two-week calibration note can be retained on its sourced requirement
as `calibration_interval: {"value":2,"unit":"weeks"}`. The result preserves the
note and structural evidence, but reports that requirement as unknown and
blocks readiness: operator scheduling and calibration history remain unchecked.
The server creates no schedule, timestamp, or execution record.

Coverage cases report `matched`, `missing`, `conflicting`, or `unknown`, with
requirement provenance and executable file/line/row/call-site evidence. Comments
and unreachable rows do not count. Additional reachable supported Wi-Fi rows are reported
separately. When both literal frequency and rate differ, an executable row is
an unrelated operating point rather than requirement evidence. A deviation in
only one of those dimensions remains a potential conflict; labels never prove
identity. Unresolved, redacted, or unaudited values cannot exclude a candidate.
The normal variant's denominator includes mandatory requirements;
the sampling variant includes mandatory and sampling requirements in separate
totals. The client explicitly supplies both the selected header and variant;
neither sampling rates nor schedules are inferred.

Submit disagreements in `conflicts` with `id`, `requirement_id`, `kind`
(`within_source` or `plan_example`), and at least two `statements`, each containing
`provenance` and `test`. Both original statements remain in the result.
The OFDM6 plan's 15.5 dBm / EVM below -35 dB and example's 18 dBm / -5 dB remain
unresolved. The Bluetooth channel/frequency ambiguity also remains unresolved;
the success matrix's CH0/CH78, setup/result frequencies 2404/2480 MHz, and
incorrect cross-references must retain their sourced statements in `conflicts`.
No channel conversion or source precedence selects an interpretation. Real station
and calibration approvals, catalog verification, and hardware checks remain pending.

An `exceptions` entry supplies `id`, `conflict_id`, `requirement_id`, `station`,
an exact `source_revisions` ID-to-revision map, a replacement `decision` test,
`rationale`, `approver`, and `approval_evidence`. It may replace acceptance facts
for that requirement while retaining its test dimensions and specified fields.
For an identified Bluetooth channel/frequency conflict, an explicit decision
may instead select a channel/frequency pair from one of its sourced statements.
This records a reviewer decision, not a conversion rule; an unaudited channel
still cannot establish frequency coverage. Each incorrect cross-reference needs
its own conflict resolution. Approval of one conflict cannot clear another.
Unrelated, stale, duplicate, or incomplete approvals cannot clear a conflict.
Reported exceptions retain their rationale and approval evidence.

`ready_for_review` requires valid bundle checks, matched applicable requirements,
and no blockers. Known conflicts outrank incomplete checks. This flag does not
approve export, certify document interpretation, or verify runtime execution.
Runtime, hardware, and packaging remain unchecked. Plan summaries and conflicts
redact supplied sensitive values, including values discovered through supplied
static aliases; `validation.source_files` and parsed source
rows retain the existing non-mutating source-echo contract.

Bounds include the shared 1 MiB text budget, 32 sources, 256 requirements,
128 conflicts/exceptions, 32 provenance entries or conflict statements,
64 dependencies per requirement, 16 per-chain masks, and 128 unresolved
questions per list. Each dimension string and unit is limited to 256 bytes.
Procedure identities share that limit; each procedure payload is at most 8 KiB.
Comparison stops after 65,536 candidate checks; affected coverage remains
unknown. Evidence is capped at 64 locations per requirement, and candidate
diagnostics are capped during scanning. Mismatch reasons omit raw values.
Dependency grouping and graph traversal share a 262,144-step request budget;
exhaustion cannot establish ordering.
Malformed or oversized structured requests return tool errors. Each request
continues to use one read-only catalog snapshot and never reads ambient files.

### References and Execution Evidence

Static `*V:Section-Key#` references resolve case-insensitively against supplied
data entries. `*V:Section#` joins the section's ordered `key=value` entries with
`&`. Missing sections/keys, ambiguous definitions, and malformed tokens are
located errors. References in auxiliary data entries are checked too. Indirect
values containing references and nested reference expressions remain incomplete;
the adapter does not recursively substitute them or inspect external files.
Known runtime-written values, including `SFIS_TO_VAR` sections, remain unchecked
even when a supplied static value exists. DLL `RECORD_TESTRESULT` writes to
`RECORD_TIMES` also keep that key and whole-section reads runtime-unchecked.
Writer classification uses supported supplied static references too, collecting
write identities and then rechecking prior classifications within the same
reference budgets. If a writer identity needs unavailable invocation or
runtime values, supplied variable reads remain incomplete rather than being
verified from potentially stale data.

Direct macros support named `NAME=value` arguments separated by `&` in PARAM
and CRITERIA. A macro body reads its own invocation through
`*V:Macro-Param_NAME#` or `*V:Macro-Criteria_NAME#`. Names are case-insensitive;
missing named arguments and duplicate argument names are errors. Other argument
contracts are incomplete when needed. Arguments never fall back to another call
or to a supplied `[Macro]` section.

Each direct call has separate execution rows and return edges. Within a macro,
`PASS` and `END` return success, `FAIL` returns failure, and `QUIT` returns the
outcome of its pass/fail edge. These outcomes reconnect to that caller's paths.
`NEXT` advances to the next active row; the last main row falls through to the
next selected item, or END. A final macro NEXT has no audited return outcome and
remains incomplete. Branch labels stay section-local. Repeated labels keep their
source order and distinct identities; a branch selecting repeated labels remains
unknown. Nested/recursive macros are not expanded beyond the direct call and
report incomplete affected paths.

`execution` records request-local `id`, `call_site`, source location, resolved
fields, `references` (`resolved` or `unknown`), and `reachability` (`reachable`,
`unreachable`, or `unknown`). `execution_edges` link these IDs or `terminal:<token>`
and retain edge kind and certainty. Reachable means a possible path under the
supported static graph, never a guaranteed measurement or successful execution.
Commented rows are absent. Unsupported routing/dispatch and omitted macro bodies
produce unknown evidence. Source-recovery errors or truncated graph analysis make
reachability unknown rather than claiming execution coverage.

Row `#Retry:<u32>` and item-header `Retry:<u32>` budgets are reported separately
as `row_retry` and `item_retry`; `LOOP` with literal `TEST_COUNT,<u32>` reports
`loop_budget`. They are not unrolled or conflated. Other loop contracts remain
incomplete. Retry annotations outside the supported u32 range remain incomplete,
rather than being treated as absent. A controller's failure path re-entering its resolved cycle reports unproven
termination, rather than declaring that ordinary finite retries are infinite.
These rules preserve checker-compatible static semantics; actual engine retry
timing, loop state, macro contracts, and equipment behavior need operator evidence.

Runtime bindings have the form `{"reference":"*E:Label-ISN#","value":null}`.
Complete `*E:`, `*I:`, and `*T:` tokens ending in `#` are accepted as declarations,
not proof of runtime availability. Their supplied values are treated as sensitive.
Diagnostics and execution evidence redact those values, explicit `sensitive_values`, recognized password/
secret/token assignments, and URL passwords. Use `sensitive_values` for credentials
under other names. Recognized credential references carry their sensitivity into
resolved values before diagnostics and execution evidence are redacted.
Execution rows flag changed values with `redacted: true`.
`source_files` and the recovered `script_sections` are authorized
source echoes and can contain supplied secrets; keep them out of diagnostic logs.
Raw source is authoritative where recovery or duplicate sections affect the view.

Finite request limits:

| Resource | Limit |
| --- | --- |
| Supplied logical files | 1-16; each name at most 128 bytes |
| Combined file names/text, flow, scope, bindings, sensitive values | 1,048,576 UTF-8 bytes |
| Source records across all files, including comments | 4,096 lines |
| Source line | 8,192 bytes |
| Selected flow header | 256 bytes |
| Runtime bindings / explicit sensitive values | 128 each |
| Checker graph expansion estimate | 16,384 rows |
| Adapter execution rows / edges | 16,384 / 65,536 |
| Reference substitutions across a request | 65,536 |
| Resolved field / cumulative substituted text | 32,768 / 4,194,304 UTF-8 bytes |
| Resolved loop re-entry analysis | 65,536 node/edge visits |

The expansion estimate counts rows for each selected flow item, including direct
macro bodies at each invocation, before invoking whole-bundle analysis. Additional
adapter bounds include unselected sections and context-specific substitutions.
An adapter limit returns an incomplete affected layer with a located diagnostic;
no truncated analysis can establish complete static validity. A graph/row limit
makes execution evidence unknown. Nested macro execution stays unsupported.
Limit failures, missing main content, and malformed flow/binding declarations
return structured tool errors with `error.code = invalid_input`. Ordinary bundle
defects return normal reports. Schema-invalid arguments use rmcp's tool-error
response; malformed protocol messages remain protocol errors. Failed requests do
not carry context into subsequent requests or modify source files.

## Reviewed Normal And Sampling Draft Previews

`compose_ini_bundle` adds mandatory 6 GHz Wi-Fi TX, AX160/BE320 RX, and supported
calibration/lifecycle procedures, plus Bluetooth setup/TX/RX, to a supplied
HH5K Wireless Test_2 base. Select `flow_variant: "normal"` or `"sampling"`,
`bundle.selected_flow`, and `bundle.dialect: "hh5k"` explicitly inside `comparison`.
Normal expands applicable mandatory requirements only. Sampling retains those
requirements and adds every specified sampling requirement; it never substitutes
sampling tests for mandatory tests. Flow section names are caller-supplied identifiers,
not an implicit choice of variant. Every applicable requirement must match before review readiness; unsupported
or missing procedures retain explicit blockers. Existing procedures stay in their original
order; the caller places the insertion marker at the reviewed point.

Both variants report separate `comparison.mandatory` and `comparison.sampling`
denominators and located execution evidence. Normal's sampling denominator is zero.
Commented, unreachable, unknown, or additional tests do not replace required cases.
Generation is revalidated through the same public bundle analysis and comparison.
The server does not infer channel/frequency mappings; supply reviewed MHz values.

Sampling composition and comparison require `plan.sampling_policy` to resolve
missing policy requirements (nested in `comparison` when composing). The optional
field leaves existing normal requests unchanged:

```json
{
  "rate": {"value": 5, "unit": "%"},
  "schedule": "Synthetic operator selection each shift",
  "provenance": [{
    "source_id": "plan",
    "revision": "3.8",
    "location": "synthetic policy appendix",
    "excerpt": "Fixture-only policy, not production approval"
  }]
}
```

Use only reviewed requirements: rate must be greater than zero and at most 100
percent, schedule must be nonempty, and provenance must identify the current
approved controlling plan/prompt revision. Every policy provenance entry must cite
that controlling source; supporting citations accepted for test requirements do
not relax this policy gate. Missing, stale, or incomplete policy
returns available draft files with an actionable blocker, never an inferred rate
or schedule. Policy is bound to the reviewed plan identity. The result's
`sampling_policy.status` is `sourced_requirements`, `unresolved`, or
`not_applicable`; its `requirements` retain the supplied facts for review.
`runtime_application` remains `unchecked_not_encoded`: no audited engine scheduler
encoding exists, so this metadata does not configure station scheduling. Both
tools retain an actionable application blocker even for a sourced policy until an
audited encoding or separately approved operator-applied contract is implemented
and verified off-machine. Explicit flow selection and static coverage never
establish production sampling approval.
Policy inputs are bounded to 32 provenance records, a 4096-byte schedule, and the
existing combined structured-input budget. Real source conflicts and operational
approval gates remain unresolved until separately reviewed.

Supply these six logical files: `MAIN_FLOW.ini`, `MACRO_LIST.ini`,
`FACTORY_SETTING.ini`, `PARAMETER_LIST.ini`, `RD_SETTING.ini`, and `TEST_SPEC.ini`.
Missing members or evidence prevent generation; available base files remain in the
preview. Missing main content remains an unanalyzable request with a structured
tool error, as with bundle validation.

The composition request contains:

- `comparison`: the existing sourced plan and bundle request, including explicit
  flow selection, Device scope, runtime bindings and sensitive values.
- `flow_anchor`: one complete semicolon-comment line, including its newline,
  occurring exactly once directly inside the selected TEST FLOW section.
- `station_settings`: references with `role`, `file`, `section`, and `key`.
  Require a uniquely resolved, nonempty setting for each role: `equipment`,
  `routing`, `timing`, `support_file`, and `credential`. Values stay in supplied
  files; a template timeout must reuse the timing reference or its exact positive
  numeric value. No support file or equipment is opened or contacted.
- `review`: separate `plan`, `base`, and `settings` approvals. Each approval has
  `subject_identity`, `approver`, `evidence`, and `kind` (`operator_review` or
  `synthetic_fixture`). Submit null initially to inspect current input identities.
- `draft_approval`: optional claim using the same approval fields, with
  `subject_identity` equal to the exact current `draft_identity`. This is separate
  from input approvals. Omit it for initial review; the client obtains human
  approval before submitting a claim. It never grants the server write access.
- `template_pack`: `id`, `version`, separate `source` and `corrected` logical
  files, `corrections`, `unresolved_questions`, and `approval`. Every correction
  records exact `before`/`after` text and evidence; applying them must reproduce
  the corrected copy exactly. Only final closing-quote insertions are audited.
  Operational rewrites, including choosing a replacement for the undefined
  `SET_IPLAS_INFO` branch, remain blockers.
- `procedure_templates`: optional list of `{requirement_id, template_pack}` entries
  for Wi-Fi RX/calibration, Bluetooth TX/RX, or explicit setup/save/cleanup requirements. Each pack has
  the same reviewed-copy contract as the TX pack, with its own approval bound to
  `input_identities.procedures[requirement_id]`. Requirement IDs must be unique
  and present in the plan. Missing, stale, or unsupported procedure packs block
  their expansion while retaining available TX output.
- `report_metadata`: optional incidental string metadata, excluded from draft
  identity and substantive output.

The corrected template uses exactly one section and one measurement row:

```ini
[{{section}}]
MEASURE="DLLWIFI_TEST|TX_MULTI_VERIFICATION|{{parameters}}|{{criteria}}|*V:STATION-Timeout#|NEXT|FAIL|"
```

The timeout reference names the caller's approved timing setting; the section/key
shown above are illustrative. The supplied template fixes the encoding and
uppercase control paths. No escaping or arbitrary template evaluation occurs.
Generation requires explicit supported test dimensions, individual antenna masks,
packet count, dBm target, dB power tolerance and strict EVM comparison. Missing
values never come from catalog defaults. Current controlling-source provenance
and requirement-specific conflict decisions are checked before expansion.

An RX entry uses the existing `RX_VERIFY_PER` bundle profile. For example, this
synthetic corrected template belongs to one entry's `template_pack`; supply its
separate source, version, correction evidence and current approval too:

```ini
[{{section}}]
MEASURE="DLLWIFI_TEST|RX_VERIFY_PER|{{parameters}}|{{criteria}}|*V:STATION-Timeout#|NEXT|FAIL|"
```

RX requires explicit Wi-Fi/6G dimensions, `11AX` with 160 MHz or `11BE` with
320 MHz, a frequency in MHz, data rate, per-chain masks, dBm input level, packet
count and PER comparison in percent. RSSI tolerance uses dB when specified.
Input/PER/RSSI definitions in `TEST_SPEC.ini` are linked to their generated usages.
PER operators are preserved; an unsupported encoding such as `<=` remains blocked
by the existing grammar, and is never changed to `<`.

Calibration templates use `BRCM_RSSI_CALIBRATION` with explicit 6G mode and chains;
frequency and bandwidth are retained when supplied. A sourced calibration interval
remains in coverage with scheduling/history unchecked and readiness blocked. No
schedule or execution record is generated. Support-file settings must resolve in
supplied contents; physical support files and equipment remain unchecked.

Setup/save/cleanup requirements use the existing exact `procedure` declaration
and supported catalog profiles. Their templates substitute only the declared
payloads. Declare `depends_on` to order successful setup, calibration, measurements,
save and cleanup; source-list order is retained between otherwise eligible items.
Unknown dependencies and cycles block generation. Shared comparison checks that
failure paths cannot bypass successful prerequisites.

A procedure template may instead call `MACRO|<supplied_section>` with the same
placeholders and `NEXT|FAIL|` paths. The target must exist uniquely in the supplied
base. The approved base binds its unchanged body; named arguments use the existing
`*V:Macro-Param_NAME#` / `*V:Macro-Criteria_NAME#` contract. Shared validation checks
argument resolution and return paths. Nested/unsupported contracts remain
incomplete; composition does not manufacture macro bodies or repair branches.

Bluetooth requirements use separate requirement-bound packs with `DLLIOT`
`DUT_INSERT`, `TX_MULTI_VERIFY`, or `RX_VERIFY_PER` in the same one-row template
shape. The original `template_pack` remains the reviewed Wi-Fi TX pack; it cannot
authorize a Bluetooth TX procedure. Each measurement declares its sourced
Bluetooth setup dependency, including exact `TECH=BT` and supplied station
payloads. Approved base/settings and catalog knowledge are required; no routing,
timing, support-file contents or equipment configuration is invented.

Bluetooth TX requires explicit MHz frequency, literal antenna bitmask, dBm target,
asymmetric dB power tolerance and kHz frequency-offset bounds. RX requires MHz
frequency, bitmask, dBm input level, exact packet count and strict percent PER.
The audited IOT encoding uses bare numeric target/input values and tolerance
bounds: `TARGET=20`, `POWER=-3~1`, `OFFSET=-150~150`, `INPUT=-87` and
`PER=<30.8%` are synthetic examples, not defaults. Generated `TEST_SPEC.ini`
definitions link to their parameter/criteria usages. No channel mapping or unit
conversion runs; unaudited dimensions block expansion. Unresolved CH0/CH78 versus
2404/2480 MHz statements and bad cross-references remain blockers. Only current,
requirement-specific approved exceptions can select a sourced decision, and
composition never creates an exception. Shared revalidation checks generated
Bluetooth rows and successful setup/save/cleanup ordering alongside Wi-Fi coverage.

The portable [template fixture](tests/fixtures/reviewed-tx-template.json) records
a sanitized synthetic source and a separate closing-quote-corrected copy. It
approves no station artifact. `synthetic_fixture` evidence can generate only when
every supplied base file starts with `; SYNTHETIC FIXTURE ONLY`; its result always
has `artifact_authority: "synthetic_only"` and `ready_for_review: false`.
Real source-derived corrected copies and their operator approvals remain pending.
Caller-supplied operator evidence is recorded, not authenticated by the server.

Approved expansions add collision-free `TX_DRAFT_<index>`, `WIFI_DRAFT_<index>` or `BT_DRAFT_<index>`
sections and flow items in dependency order, using original requirement indices.
New acceptance definitions go in `TEST_SPEC.ini`;
`limit_links` identifies each definition and the measurement field using it.
Original bytes, repeated labels, inactive alternatives and unrelated sections are
retained. Appended text follows each changed file's newline convention. Unchanged
files are byte-identical. Every changed file has a complete whole-file unified
diff; review diffs redact credentials and may therefore be unsuitable as patches.
Explicitly supplied values remain in authorized `draft_files` and the validator's
existing source echoes.

Credential-role values and their supported static aliases participate in secret
discovery even when their keys lack password-like names. Redaction preserves
schema keys, typed status values and computed identities. Replacement never
reprocesses inserted redaction markers.

Results bind SHA-256 identities to the plan, base/settings, selected flow, corrected
template evidence, catalog snapshot and draft files. Reordering catalog rows does
not change the result. Changing substantive inputs invalidates the corresponding
approval or draft identity. Procedure packs and their approvals also bind the draft
identity and appear in `procedure_provenance`. The output includes all available
draft files, diffs, limit links, layered shared validation and per-requirement plan
coverage. Incomplete cases retain blockers. Known validation violations retain
invalid status even when other checks are incomplete.

Historical checksum/revision lines remain visible in review context and are
`unverified_for_changed_content` when their file changes. Checksums are never
refreshed. Runtime/hardware verification and packaging stay unchecked. Composition
never executes source text, writes server files, creates binaries or exports a
preview. Readiness remains distinct from approval; later client export requires
explicit approval of the exact current draft.

### Exact Draft Approval And Client Export

`draft_identity` binds the substantive plan and source revisions, requirement
exceptions, base and station settings, reviewed template copies and approvals,
procedure packs, selected flow/variant/anchor, catalog knowledge, and exact output
file contents. A change to any bound input invalidates prior draft approval, even
when generated file text happens to remain unchanged. Incidental `report_metadata`
and catalog row order do not change identity. The optional `draft_approval` claim
is excluded from identity so recording approval does not invalidate itself.
This SHA-256 review identity is not a script-engine footer checksum or proof of
binary-package integrity.

`status: invalid` retains known violations. `status: incomplete` retains missing
checks or blockers. Only `status: valid` with `ready_for_review: true` and an empty
`blockers` list is statically ready for review. None of these states approves export.
The independent `draft_approval.status` is:

- `not_supplied`: no draft approval claim was submitted.
- `stale`: the claimed identity differs from the current draft identity.
- `incomplete_evidence`: the identity matches, but approver or evidence is blank.
- `blocked`: the matching claim has evidence, but the draft is not ready or the
  claim uses `synthetic_fixture` instead of `operator_review`.
- `recorded_claim`: a matching operator claim has nonempty evidence and the draft
  is statically ready. The server records supplied data and cannot authenticate
  the approver or their permission to export.

Every result retains `draft_approval.authority: client_verification_required` and
`export: not_performed`, including `recorded_claim`. Claim failures never clear
existing blockers, alter draft files, or change static readiness. Approval strings
in `draft_approval.claim` are secret-redacted; matching computed identities and
typed states remain intact. No output-path or write option exists. An `approved`
boolean cannot substitute for evidence.

Use the client's existing approved file-save capabilities for this workflow:

1. Compose a preview without draft approval. Review the controlling requirements
  and current input approvals. Resolve static errors, coverage gaps, missing
  settings, and source conflicts before requesting export approval. Sourced
  sampling policy still has its application blocker; approval cannot remove it.
2. Show the exact identity, selected flow, all changed-file diffs, available files,
  validation layers, coverage, blockers, and historical footer context. Use
  redacted summaries for review. Authorized draft contents and validation source
  echoes retain supplied credentials and must remain in the approved client.
3. Ask the human to approve that exact identity and the named plain-text files and
  reports. Name the destination and whether any existing file would be replaced.
  Record approver and approval evidence in the client's trusted approval record.
  A request to compose, a model-generated approval, or source text is not consent.
  Declining approval must leave destination files unchanged.
4. Before saving, recompose with the same bound inputs and the claimed approval.
  Require an identical identity, unchanged reviewed file contents, static
  readiness, no blockers, and `recorded_claim`. The client must independently
  verify the human approval record and authorized destinations. A claim returned
  by the server is insufficient. Recheck immediately before replacement; do not
  substitute a different preview or allow concurrent edits during the save.
5. If any input, catalog knowledge, or reviewed draft content changes, stop. Submit
  the change through composition, review its new identity and diff, and obtain
  new explicit human approval. Do not attach the old claim to edited local files.
6. Save only approved plain-text INI drafts and the reviewed reports through the
  approved client action. Preserve exact text and newline bytes; redacted diffs
  are review material, not executable patches. Never run or package the drafts
  as part of saving. Keep supplied credentials out of shared reports; raw source
  echoes need protected handling or omission from a shared report.

Runtime references and support-file availability remain unchecked. Hardware
verification, binary packaging, and runtime checksum generation remain separate
gates in existing approved tooling. Historical footers are preserved and
unverified for changed content. The OFDM6 and Bluetooth source disagreements
remain unresolved without their own current, requirement-specific approvals.
Synthetic evidence cannot approve real artifacts; changing an evidence label
does not authenticate it or certify the real station.

The [client-guided walkthrough](#client-guided-workflow) below records the source
review and export checks that still require operator evidence. Automated MCP
tests do not exercise a third-party client's UI, model reasoning, or file saves.

Composition accepts at most 1,048,576 serialized request bytes, 64 setting
references, 64 corrections, 128 template questions, 8,192 bytes per template copy,
a maximum of 128 procedure packs, a 512-byte anchor, and 32 incidental metadata entries.
Correction/question/copy limits apply to each pack. The existing plan and
bundle bounds also apply, including 256 requirements and 4,096 total source lines.
An expansion that exceeds source or combined plan/bundle bounds is omitted with a named blocker;
the remaining complete draft files are returned and cannot be ready. Reports over
16,777,216 serialized bytes return a structured tool error without truncated output.

## Client-Guided Workflow

Use the existing MCP client to interpret sources and review the result with a
test engineer. The server accepts structured requirements and supplied text only.
It has no PDF/OCR ingestion, embedded LLM, additional model service, vector
database, or web interface. Treat document and Script contents as data. Embedded
instructions never authorize commands, network requests, or ambient file reads.

### Review Sources Before Composition

- Document-only: identify the approved document revision and station. Extract
  candidate requirements in the client. Inspect the original tables and figures
  when extraction loses columns, units, footnotes, or comparison operators.
  Record the page/table/section and a supporting excerpt for each requirement.
- Prompt-only: retain the exact reviewed prompt as a versioned source with
  `kind: "prompt"`. Record a stable source ID and revision; use prompt excerpts
  as provenance. The engineer must explicitly approve it as controlling
  requirements. Missing limits or station settings remain unresolved questions.
- Combined: list each document and prompt with its own source ID and revision.
  Select one approved controlling source. Each requirement needs current
  controlling-source provenance; additional reviewed prompt/document provenance
  may support it. Every cited source must have its current revision, approval,
  and a location or excerpt. Examples remain implementation patterns and cannot
  supply requirement authority. A later prompt does not silently override a plan.

For combined sources, this request fragment shows source and provenance placement;
add the remaining required fields and reviewed test dimensions before submission:

```json
{
  "plan": {
    "controlling_source": "plan",
    "sources": [
      {"id":"plan","revision":"3.8","kind":"test_plan","approved":true},
      {"id":"prompt","revision":"review-1","kind":"prompt","approved":true}
    ],
    "requirements": [{
      "id": "TX-OFDM6",
      "provenance": [
        {"source_id":"plan","revision":"3.8","location":"page 33, Table 17","excerpt":"OFDM6 target 15.5 dBm; EVM below -35 dB"},
        {"source_id":"prompt","revision":"review-1","excerpt":"Retain the controlling plan's OFDM6 limits."}
      ]
    }]
  }
}
```

`controlling_source` and `sources` belong to `plan`; `provenance` belongs to each
entry in `plan.requirements`. Source approval flags record client-supplied facts;
the client retains the actual human review evidence. Show the engineer every
normalized value, unit, operator, antenna representation, packet count, dependency,
and mandatory/sampling classification beside its provenance. Retain ambiguity in
`unresolved_questions`. The server's `unchecked_client_interpretation` result
cannot certify that this transcription faithfully represents the source.

Record disagreements as sourced `conflicts` before composition. Retain both
statements, including the OFDM6 15.5 dBm / below -35 dB versus 18 dBm / -5 dB
disagreement, Bluetooth CH0/CH78 versus 2404/2480 MHz, and incorrect cross-references.
An engineering exception requires its own conflict and requirement IDs, station,
current source revisions, explicit decision, rationale, approver, and evidence.
An exception for one requirement cannot clear another conflict. This walkthrough
does not approve any real exception or authorize editing original references.

### Compare, Compose, And Review

1. Discover supported Functions with the existing catalog tools. Supply reviewed
  structured requirements to `compare_plan_to_bundle` with the six-file base
  contents, selected flow, dialect, and explicit variant. Inspect conflicts and
  unknown/missing coverage before requesting composition. No catalog defaults
  supply missing requirements or settings.
2. Call `compose_ini_bundle` without `draft_approval`. Review current
  `input_identities`; supply separate plan/base/settings approvals and reviewed
  template approvals bound to those identities. Use corrected template copies
  with correction evidence. Keep original references unchanged.
3. Compose normal and sampling separately with explicit selected headers and
  variants. Inspect available `draft_files`, every diff, linked limits, shared
  validation layers, sourced coverage, and blockers. Normal retains all mandatory
  tests. Sampling retains them and adds sampling requirements. An incomplete
  preview is useful review material but cannot authorize an export.
4. Check the returned files independently against the reviewed requirements.
  Re-submit those exact contents to `compare_plan_to_bundle`; inspect executable
  evidence and separate coverage denominators. Matching labels alone prove
  nothing. Confirm literal frequencies, units, strict limits, and packet counts.
  Runtime references, support-file existence, and hardware remain unchecked.
5. Keep sampling rate/schedule unresolved unless the controlling source supplies
  them. Even a sourced policy retains the sampling application blocker:
  `unchecked_not_encoded`. This ticket supplies no scheduler encoding or approved
  operator-applied contract. Do not remove that blocker to demonstrate export.

### Operator Walkthrough And Evidence

Status: pending operator execution. Use an approved client and a disposable
destination outside production scripts. Preserve observed outcomes and the human
approval record. Never use synthetic approvals for a real station artifact.

1. Review one document-only, prompt-only, and combined interpretation with the
  engineer, including a table/figure requiring visual inspection. Record source
  revisions, corrections to extracted requirements, and remaining questions.
2. Demonstrate an unresolved conflict, a scoped approved resolution, and an
  incomplete draft. Confirm none permits saving as an approved release. Retain
  the identities, redacted reports, and observed client behavior.
3. When a separately approved artifact is statically ready with no blockers,
  review its exact identity and file contents. Confirm preview and declined
  approval leave the destination unchanged. Synthetic drafts and currently
  blocked sampling drafts cannot be used as this ready case.
4. Obtain explicit human approval for that identity, named text files/reports,
  destination, and any replacement. Recompose immediately before saving; require
  unchanged identity and bytes, readiness, no blockers, and `recorded_claim`.
  Independently verify the trusted client approval record. Stop concurrent edits.
5. Use the client's existing approved text-save action. Verify only authorized
  files/reports were saved, with exact newline bytes. Refuse an unapproved
  replacement destination. Protect credential-bearing drafts and source echoes;
  redacted diffs are unsuitable as executable patches.
6. Change a bound input or catalog snapshot and confirm the old approval stops
  export/replacement. Review the changed identity and obtain fresh consent.
  Hand approved text to existing approved checksum/binary-packaging tooling only
  under its separate release procedure; retain its actual verification evidence.

Automated proof uses portable synthetic scenarios in `tests/tools.rs`, reusing
the sanitized base/template fixtures and independently specified Wi-Fi/Bluetooth
matrix. `client_workflow` covers all three source modes and both flow variants,
scoped conflict decisions, sourced execution coverage, changed-frequency rejection,
incomplete previews, and stale approval. Supporting-source guard cases reject
missing controlling evidence and stale, unapproved, example, blank, or unknown
support. Fixture approvals say `SYNTHETIC ONLY`; results remain `synthetic_only`,
not ready, and `export: not_performed`. Existing public-tool and duplex tests
retain legacy contracts, resource isolation, and credential-redaction coverage.

The following operational gates remain separately pending:

| Gate | Required evidence |
| --- | --- |
| Real catalog and stdio startup | Operator-run catalog fixtures, read-only snapshot/TLS checks, and actual client startup in an approved off-machine environment |
| Base, settings, and templates | Current station approvals and reviewed corrected-copy evidence; synthetic fixtures authorize none |
| Source conflicts and interpretation | Engineer review of the actual revision, figures/tables, and each requirement-specific exception |
| Client export and replacement | Completed walkthrough, exact-identity approval record, destination consent, and observed saved bytes |
| Sampling application | Audited encoding or approved operator-applied contract implemented and verified off-machine |
| Packaging/checksums | Existing approved tooling outputs and verification; historical draft footers remain unverified |
| Deployment | User-run approved manual release with retained rollback artifacts |
| Runtime and hardware | Operator-run support-file, equipment, and actual station execution evidence |

Local tests close none of these gates. The agent must not access Ubuntu, request
credentials, run database operations/tests, or approve production artifacts.

## Build and Verification

Rust 1.88 or newer is required. Default features include PostgreSQL and MCP, with no SQLite engine. Native TLS uses OpenSSL on Ubuntu; the build host needs its development headers, `pkg-config`, and a C toolchain. The historical SQLite adapter remains behind `legacy-sqlite` and is not built by default.

On a user-approved test machine, outside the restricted Windows host, set `TEST_DATABASE_URL` and its password source before running:

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The PostgreSQL fixture creates and cleans up a uniquely named schema. It verifies that actual catalog reads use read-only repeatable-read transactions and correctly decode BIGINT fields and NULLs. A missing test URL is an error. Database-backed fixture execution and stdio startup have not been run locally. Handshake, discovery, and dispatch of all eight tools are tested over an in-memory transport.

On this Windows host, run only database-free tests, with all database features disabled:

```powershell
cargo fmt --all -- --check
cargo check --no-default-features --features mcp --all-targets
cargo test --no-default-features --features mcp --all-targets
cargo clippy --no-default-features --features mcp --all-targets -- -D warnings
```

These commands pass on the selected MSVC Windows toolchain. An older GNU setup
needed a command-only `getrandom` backend override for missing import-library
tools; do not persist or apply that override to MSVC/Linux. PostgreSQL client-only
`cargo check` and Clippy can use `--no-default-features --features database,mcp`
without running a test or building SQLite. Never enable `legacy-sqlite` here.
No database test or database connection is permitted locally.

Deployment and the SQLite transfer are manual. The agent does not access Ubuntu or connect to either database. Follow the web repository's `docs/postgresql-migration.md`, verify the shared PostgreSQL catalog, then deploy this binary and update the client's environment. Preserve the old binary and SQLite data for rollback before application writes resume.

See [the script contract](docs/adr/0001-script-contract-and-validation.md), [the verification boundary](docs/adr/0002-off-machine-database-verification.md), [the PostgreSQL reader decision](docs/adr/0003-postgresql-catalog.md), and [the HTTP transport decision](docs/adr/0004-http-transport.md).
