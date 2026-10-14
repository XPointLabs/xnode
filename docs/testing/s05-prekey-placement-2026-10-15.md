# S05 — prekey journal across carriage-view renewal

Date: 2026-10-15. Source candidate; normative semantics and exact case retirement:
[DR-0121](../../../docs/survival-program/decisions/DR-0121-prekey-publication-placement-lifecycle.md).

Incoming fragments still require independently minted current view before any
mutation. An obsolete view rejects without poisoning an existing immutable
operation. Stored logical equality excludes only transient tag4; all other
fields, aggregate bytes, assignment and exact receipts remain bound. No changes
to claim counters, node admission, peer authentication or public listeners.

Focused01 native0:118/0/0 (48 core,70 integration), two nonempty TRX plus the
solution's exact empty filtered receipt in
`artifacts/s05-prekey-placement-20261015/focused-01/`.
Filter: DeepIdV2Publication, DeepIdV2ReplicaStage, DeepIdV2InventoryLineage and
DeepIdV2PreKeyClaim, with `DeepProtocolSourceCutover=true`.
Four cold phase-resume cases retain exact aggregate/receipts without invoking
receipt signing. Negative stale-view, immutable-conflict and integrity cases
remain required.

The prior full1508/0/0 belongs to the previous source. New canonical Node full
is pending; it must declare the exact old-case/replacement binding from DR-0121,
not waive missing cases or alter prior TRX. Actual local prekey completion is
recorded by [DevOps](../../../deep-devops/docs/S05-PREKEY-LIFECYCLE-2026-10-15.md);
this is not contact/message/device acceptance.
