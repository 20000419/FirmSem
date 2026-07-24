# FirmSem

FirmSem is a reference implementation and evidence archive for an empirical
study of security-guard survival in release binaries. Given a source-backed
security obligation selected before release, it records typed binary evidence
and tests whether equivalent runtime enforcement survives the build.

The repository intentionally separates reusable software from the larger
frozen-evidence archive. The source tree contains the audit core, compact
curated examples, the annotation protocol, and executable policy-replay
examples. The versioned v2.0.0 archive contains the Route-B human-review
records, frozen model responses, bounded mechanism evidence, result ledgers,
and deterministic audit scripts.

## Install

```powershell
git clone https://github.com/20000419/FirmSem.git
cd FirmSem
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Minimal example

```python
from firmsem import extract_guard_ir

assembly = """
test %rdi, %rdi
je .Lfail
mov (%rdi), %eax
ret
"""

record = extract_guard_ir(assembly)
print(record.observed_guard_class)
print(record.unguarded_arg_access)
```

## Repository map

| Path | Contents |
|---|---|
| `firmsem/` | GuardIR, obligation matching, cascade, metrics, and model-evaluation utilities |
| `data/` | Curated development, project-holdout, mechanism-holdout, and security-impact records |
| `docs/annotation_protocol.md` | Executed 2+1 annotation and adjudication protocol |
| `docs/RESULTS.md` | Scope and frozen result summary |
| `docs/REPRODUCIBILITY.md` | v2.0.0 replay scope and explicit acquisition boundary |
| `examples/security_impact/` | GCC/Clang security-impact replay source and frozen outputs |
| `tests/` | Small public regression suite |

## Evidence boundary

FirmSem verifies selected source-backed obligations. It is not an open-world
detector that can reconstruct missing source intent from an arbitrary stripped
function. The public results distinguish guard survival, mechanism attribution,
and security consequence rather than treating them as interchangeable claims.

## Archival release

- GitHub release: <https://github.com/20000419/FirmSem/releases/tag/v2.0.0>
- Version DOI: <https://doi.org/10.5281/zenodo.21485535>

The v2.0.0 ZIP is a compact frozen-evidence and audit package. It verifies
archive integrity, exercises the reusable code, and deterministically
recomputes selected derived analyses from frozen records. It deliberately
excludes multi-gigabyte source checkouts, compiler build trees, and raw
intermediate traces, so it is not a self-contained replay of every acquisition
stage. The exclusion ledger and exact reproduction boundary are included in
the archive.

## License

Project-authored code is Apache-2.0. Project-authored benchmark metadata,
annotations, documentation, tables, and figures are CC BY 4.0. Third-party
excerpts retain their upstream terms; see `THIRD_PARTY_NOTICES.md`.
