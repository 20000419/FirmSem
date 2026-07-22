# Cross-Architecture Security-Impact Replay

This is a static code-generation replication. Runtime consequences are measured
separately by `run_security_impact_replays.py` on x86-64.

| Architecture | Policy | fallocate inst./cond. | allocation inst./cond. | post-shift inst./cond. | pre-shift inst./cond. |
|---|---|---:|---:|---:|---:|
| x86_64 | default | 10/3 | 8/2 | 2/0 | 4/1 |
| x86_64 | wrap_policy | 14/5 | 18/6 | 2/0 | 4/1 |
| aarch64 | default | 9/3 | 6/2 | 2/0 | 3/1 |
| aarch64 | wrap_policy | 11/4 | 14/5 | 2/0 | 3/1 |
| riscv64 | default | 11/4 | 8/3 | 2/0 | 3/1 |
| riscv64 | wrap_policy | 11/4 | 14/5 | 2/0 | 3/1 |
| armv7 | default | 22/8 | 7/2 | 2/0 | 5/1 |
| armv7 | wrap_policy | 27/8 | 15/6 | 2/0 | 5/1 |

For the two signed-overflow cases, every target emits additional policy-build
logic relative to default `-O3`; the exact instruction idiom is ISA-specific.
The post-shift check remains non-recoverable under `-fwrapv`, while moving the
check before the shift preserves the policy independently of signed-overflow flags.
