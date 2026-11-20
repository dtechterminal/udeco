# The Go reference of the Deco protocol: removed

This folder held the Go reference that `../deco-tmp-protocol.md` was written
beside: a module of its own (`module deco`) with `business.go`,
`discovery.go`, `schemas.go`, `tmp.go` and `emulator_test.go`.

`internal/deco` was ported from it and has moved on since (the Mesh, the
client view, the Wi-Fi applier, more opcodes), so the copy here was a stale
second version of the same functions that no build, test or document used.
It is gone from the tree; `internal/deco` is the only copy of the protocol
code.

The old files are in the history. They were added in commit `2962bb0` and
never changed; `0a0200d`, the commit the branch that removed them started
from, still has them:

```sh
git show 0a0200d:docs/deco/reference-go/tmp.go
```
