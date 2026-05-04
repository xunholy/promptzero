<!--
Thanks for the contribution! A couple of quick notes:

1. PromptZero is built primarily with Claude. Co-authored / AI-assisted PRs are welcome —
   just say so in the description so reviewers know how to weight the change.
2. Run `task lint` and `task test` before pushing. CI runs them too, but local catches
   round-trip faster.
3. For new tools (anything in internal/tools/), please classify Spec.Risk correctly —
   the read-only safety rail (--read-only) refuses anything above risk.Low, so a
   misclassified Low tool weakens the gate.
-->

## Summary

<!-- 1–3 sentences. Why is this change here? What user-visible behaviour does it add or fix? -->

## Type of change

- [ ] Bug fix (no breaking change; fixes an issue)
- [ ] New feature (no breaking change; adds capability)
- [ ] Breaking change (fix or feature that would change existing behaviour)
- [ ] Documentation only

## Test plan

<!-- How did you verify the change? Check what applies, add specifics. -->

- [ ] `task vet` clean
- [ ] `task lint` clean (`golangci-lint` 0 issues)
- [ ] `task test` passes (54+ packages green)
- [ ] Manual verification — describe below
- [ ] Hardware-in-the-loop verification — describe below

## Notes for reviewer

<!-- Optional. Things you want eyes on, decisions that need a sanity check, or follow-ups. -->
