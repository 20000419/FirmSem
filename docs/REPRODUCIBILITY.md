# Reproducibility

The compact repository is the reusable source and curated-data entry point.
The versioned `FirmSem_complete_artifact_v1.0.0.zip` release asset is the full
scientific evidence package.

The complete artifact contains the upstream benchmark mothers, final 2+1
annotation returns and adjudications, frozen GPT-5.4 and Claude Opus 4.6 raw
responses, deterministic and learned baselines, compiler-security replay
sources and outputs, 10,000-sample bootstrap analyses, and a one-command
PowerShell orchestrator.

After extracting the complete artifact:

```powershell
python -m pip install -r requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_all.ps1
```

The published bundle was cold-tested from a fresh extraction. The run completed
all 8 cross-architecture compiler profiles, regenerated every scientific stage,
passed 53/53 regression tests, and reproduced 12 key JSON artifacts byte for
byte. Use `-SkipCompilerReplays` only when the recorded compiler toolchains are
not installed.

Fresh hosted-model generation is not required to reproduce the reported
metrics: prompts and exact raw responses are frozen and rescored offline. New
provider calls require credentials and are not expected to be byte-identical.
