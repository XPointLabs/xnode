# ADR 0007: retired managed replica cache

Status: superseded by [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
Original date: 2026-08-09. Human owner: **Mr. X**.

The PMA1/PMR1 node provider, PMC2 cache/preposition surface and old replica
fanout are removed from the compiled current node. Their positive runtime
corpus and operational activation instructions are not retained here; Git
history records the retired design. This record grants no fallback, adapter,
legacy reader, authority conversion or activation permission.

Current behavior belongs to
[XPOINT-NETWORK](../../../docs/architecture/XPOINT-NETWORK-V1.md) and its
accepted decisions. Node consequences and custody configuration belong to
[the operator guide](../operator.md#current-selected-mailbox-exits).
The removal scope and actual checks are recorded in
[the existing checkpoint](../testing/s02-retired-forwarding-2026-10-04.md#s00-continuation-compiled-pma1-providercache-removal-2026-10-05).

Source removal does not delete or reset registered keys, retained signed
lineage, native journals, independent protected floors or installed volumes.
Neutral capacity codec checks remain; they do not restore the retired cache
or qualify shipping/device delivery.
