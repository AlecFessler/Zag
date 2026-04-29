# 01_basic — kEntry-rooted reachability + alias resolution

Tests:
- `main.kEntry` is the boot entry (seeded by indexer).
- `aliveFn` is reached transitively via direct call from kEntry.
- `lib.aliveLeaf` is reached via `aliveFn` AND aliased through
  `lib.aliveAlias`, which kEntry references.
- `deadFn` and `deadConst` have no caller / use → flagged.
- `lib.deadLeaf` is referenced inside `deadFn`, but the
  bare-identifier heuristic counts it alive because `deadLeaf` token
  appears in source. This is a known false-negative the legacy
  analyzer also has — neither tool tracks whether the *using*
  entity is itself alive. With IR present, transitive ir_call
  reachability would catch this; fixtures don't ship IR.
