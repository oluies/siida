# modules/core

Shared primitives used by other Siida modules.

Unlike the other modules in this directory, `core` is **not owned by a
single numbered spec**. Instead, primitives that turn out to be shared
across multiple roadmap features (wire-format types, common
serialisation helpers, error types, time and clock abstractions) land
here as those features need them.

Until the first such primitive is extracted, `core` contains only the
bootstrap `Placeholder` used to prove the build wiring (see spec
[`001-project-bootstrap`](../../specs/001-project-bootstrap/spec.md)).
