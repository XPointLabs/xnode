using System.Collections.ObjectModel;

namespace XNode.Core.NodeDb;

public sealed class RegisteredRelayCatalogSnapshot
{
    private readonly IReadOnlyList<RouterId> _registeredRelays;
    private readonly IReadOnlyDictionary<RouterId, RelayContact> _contacts;

    internal RegisteredRelayCatalogSnapshot(
        IEnumerable<RouterId> registeredRelays,
        IReadOnlyDictionary<RouterId, RelayContact> contacts)
    {
        var relayIds = registeredRelays.Order().ToArray();
        _registeredRelays = Array.AsReadOnly(relayIds);
        _contacts = new ReadOnlyDictionary<RouterId, RelayContact>(
            contacts.ToDictionary(
                static pair => pair.Key,
                static pair => CloneContact(pair.Value)));
    }

    public IReadOnlyList<RouterId> RegisteredRelays => _registeredRelays;

    public int RegisteredRelayCount => _registeredRelays.Count;

    public RelayContact? GetContact(RouterId routerId) =>
        _contacts.TryGetValue(routerId, out var contact)
            ? CloneContact(contact)
            : null;

    public IReadOnlyList<RelayContact> GetContacts() =>
        _registeredRelays
            .Select(GetContact)
            .Where(static contact => contact is not null)
            .Select(static contact => contact!)
            .ToArray();

    internal static RelayContact CloneContact(RelayContact contact) =>
        contact with { Capabilities = contact.Capabilities.ToArray() };
}
