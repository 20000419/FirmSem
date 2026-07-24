# Reproducibility

The compact repository is the reusable source and curated-data entry point.
The versioned `FirmSem_RouteB_Artifact_v2.0.0.zip` release asset is the compact
frozen-evidence and audit package for the Route-B empirical study.

The archive contains final 2+1 annotation returns and adjudications, frozen
GPT-5.4, Claude Opus 4.6, and Qwen records, deterministic and learned controls,
bounded mechanism-attribution summaries, executable policy-replay sources and
outputs, derived statistical analyses, and a one-command audit orchestrator.

After extracting the v2.0.0 artifact:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_route_b_audit.ps1
```

The orchestrator verifies the strict SHA-256 manifest, runs the reusable
software tests and P0-1 adapter tests, and deterministically recomputes selected
R4/R5 analyses from frozen records. The archive's
`REPRODUCTION_VALIDATION.md` records the fresh-extraction result.

The compact archive deliberately excludes the documented multi-gigabyte P0-1
project checkouts, compiler build trees, raw logs, and intermediate
LLVM/assembly products. It therefore cannot rerun the complete compiler matrix
or bounded attribution from acquisition. See `P01_INTERMEDIATE_EXCLUSIONS.md`
inside the archive for exact counts and sizes.

Fresh hosted-model generation is not required to reproduce the reported
metrics: prompts and exact raw responses are frozen and rescored offline. New
provider calls require credentials and are not expected to be byte-identical.
