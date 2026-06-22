namespace XNode.Core.NodeDb;

public sealed record NodeDbPutResult(bool Stored, bool ShouldGossip, string Reason);
