# S05 atomic public-source readback

The node retains its complete first public frame for one call. Final readback
still opens and reads the actual bounded file through EOF, compares every byte,
then checks the private grammar digest after the diagnostic callback. An exact
match avoids a second framing/copy pass. The one-entry public bundle parser memo
now admits frames up to8MiB; larger valid frames remain uncached. Separate PMT/PMA
and protected-head memo limits, authority and effect guards are unchanged.

`artifacts/node-atomic-readback-20261105-focused02` passed the Release source-mode
build with zero warnings/errors and1714 unchanged source inputs. All26 focused
cases passed with zero failures/skips and2388 unchanged source/binary inputs.
Thirteen new rows cover small/5–8MiB/above8MiB frames, actual rereads, disposal and
source ownership, mutated record buffers and timing callbacks, and actual file,
issuer and signed-successor changes during floor commit. The larger framing
fixtures do not claim a verified authority lineage. Existing proof, expiry,
floor and changed-observation cases also passed. Native test duration3.867s.

The earlier focused01 build omitted `DeepProtocolSourceCutover=true` and failed
before tests; that receipt remains preserved. Restoring the exact existing
source graph and passing the existing property fixed the invocation, without
package changes. Full Node qualification, transport smoke/rehearsal and retained
CLI latency evidence remain open. No release or latency qualification is claimed.
