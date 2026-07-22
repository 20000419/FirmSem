# FirmSem Final 2+1 Annotation Protocol

## Scope and Audit Unit

This document records the protocol actually used for the final FirmSem evaluation. The semantic audit unit is a `(function, source obligation, optimized artifact)` tuple, not a marker disappearance or a function name. The final question is whether a runtime-relevant source obligation is preserved by an equivalent mechanism in the optimized artifact.

Three independent rounds were run:

1. **Development obligation audit:** 131 obligations from 49 projects already represented in public-v4.
2. **Untouched-project audit:** 100 candidates selected before annotation from five project commits absent from development; eligibility and survival were labeled separately.
3. **Untouched-mechanism paired audit:** 24 build rows from 12 externally documented incidents; pair identity, build role, mitigation flags, and external oracle were sealed.

## Team and Blinding

- Annotator A and Annotator B labeled independently.
- Adjudicator C did not participate in Phase 1 and saw only disagreement rows plus their dossiers and A/B rationales.
- Model predictions, model explanations, author labels, and mining scores were not provided to the annotators.
- Final model-evaluation packages omit auditor notes, adjudication rationales, gold mechanisms, O0 assembly, and compile commands.

## Labels

For an eligible runtime obligation, the survival label is one of:

- `CHECK_PRESENT`: the exact obligation remains as a direct branch, transformed or branchless predicate, equivalent dataflow enforcement, caller/callee enforcement, or equivalent fail/trap/assert path.
- `CHECK_ELIMINATED`: no equivalent runtime enforcement remains before the protected operation.
- `AMBIGUOUS`: the supplied evidence cannot distinguish preservation, elimination, configuration removal, or an unmatched obligation reliably enough for binary scoring.

`PARTIALLY_PRESERVED` is retained as a preservation-mode annotation. It is not automatically treated as eliminated: the adjudicator decides whether the security-relevant rejection semantics remain.

The untouched round additionally labels **eligibility**. A row is eligible only when the source evidence defines a concrete runtime security obligation attributable to the target function/build. API-only contracts, ordinary computation, compile-time-only conditions, or evidence that cannot be tied to the target are excluded rather than forced into the negative class.

The paired round applies the same eligibility gate. If one or both build rows in an incident do not encode a runtime security check, the excluded rows are not converted to `CHECK_PRESENT` controls. Incident-pair structure is restored only after final human labels are frozen.

## Required Evidence

Each Phase-1 record contains:

- an exact or auditable source predicate and protected entity;
- the first relevant hazard or protected operation;
- source and O3 excerpts with provenance;
- a survival label and preservation mode;
- a concise evidence-based rationale.

For macro/configuration cases, annotators distinguish optimizer transformation from preprocessor or build-policy removal. A missing debug assertion is not silently conflated with a production runtime validation; the final mechanism ledger records assertion policy, configuration/macro policy, or unresolved mechanism separately.

## Procedure

### Phase 1: Independent labeling

A and B independently label every supplied row. In the untouched round they first decide eligibility, then label survival only when eligible.

### Phase 2: Agreement measurement

Cohen's kappa is computed on the complete Phase-1 outputs before adjudication. For the untouched round, joint-code kappa is reported over eligibility plus survival, and survival agreement is also reported on the jointly eligible subset so that obligation-mining disagreement is not mistaken for check-survival disagreement.

### Phase 3: Non-overlapping adjudication

Only disagreements are sent to C. C records the final decision and a case-specific rationale. Agreement rows retain the shared Phase-1 decision. Ambiguous rows remain in the released gold but are excluded from binary metric denominators.

## Executed Results

### Development obligations

- Phase-1 agreement: 124/131.
- Cohen's kappa: 0.889; 10,000-resample 95% bootstrap CI [0.805, 0.956].
- Adjudicated disagreements: 7.
- Final labels: 42 `CHECK_ELIMINATED`, 87 `CHECK_PRESENT`, 2 `AMBIGUOUS`.
- Binary evaluation denominator: 129.

### Untouched projects

- Frozen candidate pool: 1,255 rows; deterministic selection: 20 rows from each of five projects, 100 total.
- Joint eligibility/survival agreement: 74/100; Cohen's kappa 0.534, 95% CI [0.372, 0.682].
- All 26 Phase-1 disagreements were eligibility disagreements.
- Jointly eligible survival decisions: 36/36 agreement, kappa 1.0 (5 eliminated, 31 present).
- Adjudication produced 37 eligible scored obligations: 5 eliminated and 32 present; 63 candidates were excluded.
- All five positives are assertion-policy cases. This set therefore tests project-disjoint transfer and false-positive control, not broad mechanism prevalence.

### Untouched mechanisms

- Frozen input: 24 build rows from 12 real-incident clusters; no prior project/source/source-token/assembly hash collision.
- Phase-1 joint eligibility/survival agreement: 16/24; Cohen's kappa 0.497, incident-cluster bootstrap 95% CI [0.250, 0.845].
- C adjudicated 9 substantive rows and excluded 8 rows forming four complete incident pairs as `EXCLUDE_NOT_SECURITY_CHECK`.
- Final scored gold: 16 build rows in 8 incident clusters, with 9 `CHECK_ELIMINATED` and 7 `CHECK_PRESENT`.
- Human gold agrees with the sealed construction oracle on 15/16 scored rows. The human label is authoritative for the mismatch.
- The frozen-primary and post-freeze cross-check strata each contain four final pairs and are always reported separately.

## Localization and Boundary Disclosure

- O0 markers, source locations, or paired-build alignment may localize candidates, but marker absence never determines the final label.
- Coverage is limited to obligations and target regions that can be localized confidently.
- The strongest results use known function boundaries. Automatic-boundary and stripped-binary results are reported separately and are not merged into this denominator.

## Released Evidence

Raw A/B/C CSV returns, agreement reports, final JSON gold, scored clean packages, frozen predictions, baseline outputs, and regeneration scripts are included in the artifact. The clean development and untouched-project packages have zero project overlap. The paired package additionally removes pair role, oracle, compile flags, and human notes; source-only fields are identical within every retained incident pair.
