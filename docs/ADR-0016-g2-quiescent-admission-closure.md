# ADR-0016 — STY-G2-05h1: irreversible admission closure before FsStore shutdown

Parent: [STY-G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7); dedicated ownership contract [G2-05h #21](https://github.com/Lalalalendia/staya-transfer/issues/21); Linux fork/exec diagnostic [PR #17](https://github.com/Lalalalendia/staya-transfer/pull/17). This is a narrow, independent prerequisite: no new lock API, no new blob backend, no production Akula integration.

## Why a close gate is mandatory

A shared in-flight resource ledger admits real Bao imports through `SharedAdmission::reserve` while a separate `StoreLease` holds cooperative OS custody. A clean shutdown must first **stop all new imports**, then wait for in-flight work to finish, *then* terminate the real FsStore actor. Checking `usage() == (0,0,0)` without closing admission is a time-of-check/time-of-use race: another thread can create a new permit immediately after the check.

`SharedAdmission::stop_admissions()` acquires the **same mutex** as `reserve` and flips an irreversible `accepting=false` flag. Either a racing reservation receives a permit **before** this linearization point (and remains counted), or the reservation is denied. A cloned `SharedAdmission` cannot bypass the closing state. Retrying after closure is denied, even if the retry budget would otherwise allow it.

`admissions_drained()` returns true **only** when shutdown has begun, there are no outstanding reservations, and all three local resource usage counters are zero. Poisoned mutex state fails closed. This is bounded, cooperative process-local accounting; it does not block an unregistered actor, network peer, independent process, or hostile writer.

## Safety boundary — drained is NOT quiescent

There are at least four distinct prerequisites for a safe clean handoff:

1. No new reservations are admitted (this change).
2. All existing in-flight import reservations are released (this change measures it).
3. **The pinned FsStore actor actually shuts down** with a successful `FsStore::shutdown`, pending physical writes resolved and relevant storage fences validated (NOT established by a drained ledger).
4. All registered child writer processes holding the store authority have exited; `flock` may otherwise survive a parent descriptor close. The Linux negative test in #17 demonstrates that explicit `LOCK_UN` while an inherited writer stays alive may prematurely admit another owner.

This PR implements **only steps 1-2**. It does not expose any `StoreLease::release` or `unlock()`, does not claim that an async import actor has finished solely from an `InflightPermit` Drop, and does not modify FsStore's shutdown internals. If actor shutdown fails, recovery remains fail-closed and can only trust independently verified Bao bytes on re-open.

## Required checks

- Rust custody unit test: stop admission with a live permit, cross-thread clone must deny new `reserve` and retry, drained false until the permit drops, then true; a closed ledger cannot reopen.
- 64 independent competing `reserve` vs `stop_admissions` transitions: a permit racing before closure remains counted, a later request is denied; never return a false drained state.
- Actual release + pinned-fork interop: after a valid authenticated Bao import under a live permit, close the gate, verify active permit blocks `admissions_drained`, drop it, deny a new real import even when drained, then separately call `FsStore::shutdown`, physically audit actual sparse Bao data, and ensure no checkpoint is created.
- Exact-head `cargo test --locked`, fmt and Clippy on Linux + Windows and pinned iroh-blobs release/fork interop. No new deps or lockfile modifications.

## Next gate G2-05h2

Connect the transition to a **non-forgeable real FsStore writer supervisor** which retains the original `StoreLease` from Active through Closing to Quiescent. Only after actual actor shutdown, completed imports, valid file-path fence and registered child-writer joins may that supervisor attempt a *clean* explicit release. Failure/cancellation may not mint a quiescence token; crash path does not call clean unlock. Continue independent Linux/Windows kill/reopen tests and distinguish transient `WouldBlock` from any authority to reuse bytes.

**Unchanged HOLD:** physical durability on Windows, adversarial path replacement, production File Gate, actual physical disk quotas, validated restart range skip and the G2-06 acceptance gate.
