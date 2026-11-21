# Engineering conventions — netkeep

This is the short rule set. [`develop.md`](develop.md) is the detailed guide:
workflow, the area-doc index, and the GPUI component rules. Read the area doc
before writing code in that area; when the two disagree, the area doc wins.

A change that does not pass `just ci` is not done.

## Environment

- **Tests are offline and unprivileged.** `just test` must not need the network,
  root, NFQUEUE or eBPF. The packet path is written so its logic can be tested
  without them: `ProcessResolver`, `Classifier`, `FlowRegistrar` and
  `NftablesBootstrap` are traits, and the tests use their fakes.
- **Root-only paths are verified on the installed daemon**, not simulated. When
  behaviour depends on eBPF, nftables or a real proxy, install it, exercise it,
  and record what the journal showed — dated — in the relevant
  `docs/investigations/` file. Do not report a root-only path as verified
  because a unit test passed.
- **Never commit scratch output.** Redirect diagnostics to `/tmp/opencode`, not
  into the repository.

## Security invariants

These are the reason the project exists. A change that weakens one needs a
recorded decision, not a workaround.

- **Nothing is allowed without proof.** A flow matches a rule only when every
  field the rule pins matches the flow. An unattributed flow never inherits a
  rule written for an app.
- **Names are ranked by what proves them.** A name in the packet (TLS `SNI`,
  HTTP `Host`) may authorize. A name from DNS is scoped to the process that
  asked and to hostname-bearing ports. A reverse-DNS name is display only —
  the owner of a reverse zone can claim any name (issue #23).
- **Every verdict must be explainable.** The `policy:` line names the rule id,
  the action and the fields that matched. A new decision path that cannot say
  why it decided is not acceptable.
- **Every drop carries a reason counter.** `netkeep_packets_dropped_total` must
  distinguish "pending", "route setup failed", "no mark", and so on.
- **Fail closed on ambiguity.** Two possible owners, two candidate names, or a
  scan that could not read every process all mean "not proven".

## Rust

- No `unwrap`/`expect` on packet or request paths. Startup glue may use
  `anyhow`; libraries use `thiserror` per crate.
- Keep the dependency direction: `core-types` ← `policy-engine` ←
  `control-service` ← `daemon`. `enforcer` renders verdicts and knows nothing
  about the database.
- Public functions state their failure modes in one line.
- The packet path stays allocation-light and lock-free where it already is; a
  new lock on that path needs a reason.
- Comments explain *why* a rule exists. Evidence belongs next to the code that
  depends on it.

## Data

- The SQLite schema is created in `state-store`. A column change is a migration,
  and old rows must still load: new fields are `#[serde(default)]` with a value
  that means "unknown".
- Timestamps are epoch seconds (`u64`). No local time in storage.

## UI (GPUI)

- Use `gpui-component` primitives and the atoms in `apps/gpui/src/components/ds.rs`.
  Do not hand-roll a badge, chip or picker that already exists.
- Colours and spacing come from `apps/gpui/src/colors.rs`; no hard-coded hex in
  a component.
- Verify through the running app: the log viewer for decision streams,
  `netkeep-cli` for daemon state. A screenshot is a last resort and belongs to
  a sub-agent, never to the main conversation.

## Decisions

- Design decisions live in the investigation docs (`§10 Open decisions`) and in
  `docs/architecture.md`. If a change contradicts one, stop and record the
  conflict, or the new decision, instead of working around it.
- Measured claims carry their evidence: the command, the journal excerpt, or the
  table of counts. Do not write "many", "often" or "improved" without a number.

## Workflow

- **Every change lands through a pull request.** `main` is protected: no direct
  pushes, no force-push, no rewriting published history. Branch from `main` as
  `fix/<n>-slug` or `feat/<n>-slug`, and end the PR body with `Fixes #<n>` so the
  issue closes on the squash merge.
- Work is tracked in GitHub issues; a change with no issue either has an obvious
  one or needs one filed first.
- Update the area doc in the same change that taught you something. A fix whose
  lesson stays only in the diff will be rediscovered.
