# Security-Impact Replay Results

These replays separate standards-conforming compiler behavior from a release
policy that intends to reject attacker-controlled overflow or shift values.

| Profile | Runtime output | fallocate branches | allocation branches | canary branches | post-shift branches | pre-shift branches |
|---|---|---:|---:|---:|---:|---:|
| gcc15_O0 | `fallocate=-27; allocation=-75; allocation_required=4294967300; canary_corrupted=-75; shift_post=0; shift_pre=-1` | 31 | 25 | 19 | 6 | 4 |
| gcc15_O3_default | `fallocate=-9223372036854775805; allocation=4; allocation_required=4294967300; canary_corrupted=1; shift_post=0; shift_pre=-1` | 21 | 18 | 16 | 1 | 1 |
| gcc15_O3_policy | `fallocate=-27; allocation=-75; allocation_required=4294967300; canary_corrupted=-75; shift_post=0; shift_pre=-1` | 26 | 22 | 16 | 1 | 1 |
| clang22_O0 | `fallocate=-27; allocation=-75; allocation_required=4294967300; canary_corrupted=-75; shift_post=0; shift_pre=-1` | 6 | 6 | 12 | 2 | 3 |
| clang22_O3_default | `fallocate=-9223372036854775805; allocation=4; allocation_required=4294967300; canary_corrupted=1; shift_post=0; shift_pre=-1` | 3 | 2 | 6 | 0 | 0 |
| clang22_O3_policy | `fallocate=-27; allocation=-75; allocation_required=4294967300; canary_corrupted=-75; shift_post=0; shift_pre=-1` | 5 | 6 | 6 | 0 | 0 |

Interpretation: the default optimized profiles may legally erase post-operation
checks because signed overflow and oversized shifts are undefined in C. The policy
profiles preserve signed-wrap checks, while the shift case requires moving the
check before the operation. A guard-loss finding is therefore a release-policy
mismatch, not automatically a compiler bug.
The bounded canary witness makes the allocation consequence explicit: default
O3 accepts four bytes for a 4,294,967,300-byte logical request and overwrites
the modeled adjacent canary; O0 and policy builds reject before the write.

Mechanism evidence: GCC's default O3 optimized tree removes the
allocation rejection block, while its policy tree retains the -75 path.
Clang's default O3 IR marks the multiply `nuw nsw`; the `-fwrapv` IR
uses an overflow intrinsic and retains the -75 result. The raw tree/IR
files are emitted beside this report.
