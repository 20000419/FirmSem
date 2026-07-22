# FirmSem Artifact Provenance and License Status

This file applies to the submitted reviewer artifact. It is not a blanket
relicensing of third-party source code.

## Project-authored material

The experiment drivers, analysis scripts, and GuardIR implementation are
licensed under Apache License 2.0. Project-authored benchmark metadata,
annotations, documentation, tables, and figures are licensed under CC BY 4.0.
These licenses apply only to material authored by the FirmSem contributors and
do not relicense third-party excerpts or derived upstream content.

## Third-party material

Rows derived from Decompile-Eval, ExeBench, Zephyr, Mbed TLS, Juliet, and other
public projects retain their upstream copyright and license conditions. Source
family, project, path, build, and localization provenance are retained in the
released JSON records and source manifest. No upstream project is claimed to
endorse the labels or release-policy interpretation.

The reconstruction pins the two downloaded dataset snapshots and the principal
source trees used by the final public corpus:

- `LLM4Binary/decompile-eval`: `b9271fae3c556e46948559f4176ffa6f8b4f9491`
- `jordiae/exebench`: `093085f8558cfd53de8e2c8f4ccc7b9e73dc22ae`
- Zephyr source tree: `356c8cbe63ae01b3ab438382639d25bb418a0213`
- Zephyr vendored Mbed TLS module: `6e7841e5a08eb5da3c82dbc8b6b6d82ae4b7d2a0`

The artifact redistributes project-authored metadata and the exact excerpts
needed for review, not a blanket copy of every upstream repository. Reviewers
who rematerialize third-party sources remain subject to each upstream license.

## Hosted-model outputs

Codex CLI and Claude Code outputs are released as experiment records only.
Provider/model identifiers, timestamps, exposed usage fields, prompts, parse
status, and latency are preserved. Hosted weights and provider services are not
redistributed.

## Integrity

`artifact_manifest.json` records the relative path, byte length, and SHA-256 of
every payload member. The ZIP builder refuses to overwrite an existing bundle
and validates every archive member after creation.
