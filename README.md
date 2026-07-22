# FirmSem

FirmSem provides a compact implementation and frozen public data for auditing
whether an approved source-level security obligation still has an equivalent
runtime enforcement mechanism in a compiler-optimized binary.

The public repository is intentionally small. It contains the reusable core,
curated final data, the annotation protocol, and executable security-impact
examples. Full raw transcripts, annotation returns, and regeneration logs are
kept in the versioned archival artifact attached to the GitHub release and the
Zenodo record.

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
| `examples/security_impact/` | GCC/Clang security-impact replay source and frozen outputs |
| `tests/` | Small public regression suite |

## Evidence boundary

FirmSem verifies selected source-backed obligations. It is not an open-world
detector that can reconstruct missing source intent from an arbitrary stripped
function. The public results distinguish guard survival, mechanism attribution,
and security consequence rather than treating them as interchangeable claims.

## Archival release

- GitHub release: <https://github.com/20000419/FirmSem/releases/tag/v1.0.0>
- Version DOI: <https://doi.org/10.5281/zenodo.21485535>

The archival ZIP contains the complete frozen evidence needed to audit reported
numbers. It intentionally excludes manuscript drafts, internal peer-review
workflows, and private working notes.

## License

Project-authored code is Apache-2.0. Project-authored benchmark metadata,
annotations, documentation, tables, and figures are CC BY 4.0. Third-party
excerpts retain their upstream terms; see `THIRD_PARTY_NOTICES.md`.
