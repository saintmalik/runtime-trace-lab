# runtime-trace-lab

Companion lab for [Runtime Trace attestation: signed image, dishonest process](https://blog.saintmalik.me/runtime-trace-process-attestation/)

Prove Cosign **image signature PASS** + **Runtime Trace policy PASS/FAIL**.

| Profile | Image verify | Trace policy |
|---------|--------------|--------------|
| clean   | PASS         | PASS         |
| dirty   | PASS         | FAIL         |

## Run

Actions → **Runtime Trace lab** → Run workflow.

## Platform pieces (what to copy)

```text
.github/workflows/runtime-trace-lab.yml
.github/exporter/tetragon_to_runtime_trace.py
.github/policies/policy.cue
.github/tetragon-policies/
```

1. **lizrice/tetragon-ci setup** — start Tetragon (community demo, not official Cilium Marketplace).
2. **`tetra getevents -o json`** — capture events for the Trace (prefer over the file sink alone on noisy GHA runners).
3. **Exporter** — Tetragon JSONL → in-toto Runtime Trace predicate.
4. **`cosign attest` / `verify-attestation --policy`** — attach + gate.

## Dirty

CI codegen with wrong module path (`proto-gen-connect-go` typosquat of `protoc-gen-connect-go`), same shape as `go install templ && templ generate`. Clean skips that step.
