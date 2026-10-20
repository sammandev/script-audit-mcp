# Checker Source Snapshot

Script Audit uses this checked-in `script-checker` 0.1.0 source snapshot through
an exact `=0.1.0` dependency and a repository-relative path. No absolute workstation
path, shared Cargo workspace, network checkout, or registry download is needed
for the checker. The upstream library and CLI remain separate targets.

Origin: the standalone `script-checker-tool` repository, baseline commit
`7ac457adbb313d5dbc110735049ee12be601ea86`, plus the supplied-content extraction
for INI bundle authoring ticket 01. This snapshot is not an upstream release tag.
`CHECKSUMS.sha256` records SHA-256 hashes of Cargo.toml and every Rust source,
with CRLF normalized to LF. Cargo does not enforce checksums for path dependencies;
review these hashes when refreshing the snapshot and retain the lockfile change.

The snapshot contains source only. Original station references, runtime files,
build outputs, and databases are excluded. Keep the standalone checker parity
tests green before updating the snapshot, then run Script Audit's database-free
`checker` test and original in-memory tool/protocol suite.

## Integration Boundary

Use `script_checker::analysis::analyze_contents` with `ContentAnalysisRequest`.
Supply the main `SourceFile`, optional macro file, auxiliary texts, required file
names, and an explicit flow header. Names are opaque, case-insensitively unique
identifiers. The content entry point never discovers or opens paths, including
runtime folders or paths written in script payloads, and performs no network I/O.
Missing required names yield `SCRIPT_FILE_MISSING`; unresolved values remain
visible in the typed reference results. An unknown selected flow is a normal
error report. Empty selections or empty/duplicate names return `Err(String)`.

Read typed diagnostics, counts, graph findings, and `script_sections` rather than
parsing display JSON. `source_files` preserves submitted text exactly, in main,
macro, auxiliary order. Comments and inactive rows remain in that text; parsed
sections expose active recovered rows, including repeated labels and line numbers.
Legacy parser recovery may merge duplicate sections, so use the original text
when reconstructing source structure. Validation does not rewrite files.

Historical names require positional mapping: `ScriptRow.criteria` is the third
field, PARAM; `ScriptRow.parameters` is the fourth field, CRITERIA. Do not use their
names to interpret arguments. Existing single-line tools retain ADR 0001's contract.

The legacy status is not Script Audit's layered validation status.
Unresolved references do not necessarily make it an error. Nested macros, full
test-spec checks, runtime verification, and resource bounds remain limitations.
No catalog compatibility, plan conformance, checksum verification, or hardware
execution is claimed. Ticket 01 adds no MCP tools and no filesystem export.
