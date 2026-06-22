namespace XNode.Core.Paths;

public sealed class PathSelector
{
    public SelectedPath? SelectHopsToRemote(
        RouterId pivot,
        PathSelectionOptions options,
        IReadOnlyCollection<RelayContact> relayContacts,
        IReadOnlySet<RouterId> currentEdges,
        Func<RouterId, bool>? isBadForPath = null,
        Random? random = null)
    {
        options.Validate();
        random ??= Random.Shared;
        isBadForPath ??= _ => false;

        var contacts = relayContacts
            .GroupBy(contact => contact.RouterId)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(contact => contact.SignedAt).First());

        if (!contacts.TryGetValue(pivot, out var pivotContact))
        {
            return null;
        }

        var hopsNeeded = options.ClientHops;
        var hops = new List<RelayContact>();
        var excluded = new HashSet<RouterId> { pivot };
        var excludedRanges = new List<Ipv4Prefix>();
        var netmask = options.UniqueHopNetmask;

        if (netmask > 0 && pivotContact.GetIpv4Address() is { } pivotIp)
        {
            excludedRanges.Add(Ipv4Prefix.FromAddress(pivotIp, netmask));
        }

        if (--hopsNeeded <= 0)
        {
            return new SelectedPath(new[] { pivotContact }, WasExtendedForEdgeOverlap: false);
        }

        bool IsAllowedMiddle(RelayContact contact)
        {
            if (excluded.Contains(contact.RouterId))
            {
                return false;
            }

            if (netmask > 0 && contact.GetIpv4Address() is { } ip)
            {
                foreach (var excludedRange in excludedRanges)
                {
                    if (excludedRange.Contains(ip))
                    {
                        return false;
                    }
                }
            }

            return !isBadForPath(contact.RouterId);
        }

        RelayContact? SelectFirstHop(Func<RelayContact, bool> filter)
        {
            var edgeCandidates = currentEdges
                .Select(edge => contacts.TryGetValue(edge, out var contact) ? contact : null)
                .Where(contact => contact is not null)
                .Cast<RelayContact>()
                .Where(contact => filter(contact))
                .ToArray();

            return edgeCandidates.Length == 0 ? null : edgeCandidates[random.Next(edgeCandidates.Length)];
        }

        var wasExtended = false;
        RelayContact? first = null;

        if (netmask > 0)
        {
            first = SelectFirstHop(IsAllowedMiddle);
            if (first is null)
            {
                wasExtended = true;
            }
        }

        first ??= SelectFirstHop(contact => contact.RouterId != pivot && !isBadForPath(contact.RouterId));

        if (first is null)
        {
            wasExtended = true;
            first = pivotContact;
        }

        if (first is null)
        {
            first = SelectFirstHop(contact => !isBadForPath(contact.RouterId));
        }

        if (first is null)
        {
            return null;
        }

        hops.Add(first);
        Exclude(first);
        --hopsNeeded;

        if (wasExtended && hopsNeeded < PathSelectionOptions.MaxBuildLength - 2)
        {
            ++hopsNeeded;
        }

        while (hopsNeeded > 0)
        {
            var candidates = contacts.Values
                .Where(IsAllowedMiddle)
                .ToArray();

            if (candidates.Length == 0)
            {
                return null;
            }

            var selected = candidates[random.Next(candidates.Length)];
            hops.Add(selected);
            Exclude(selected);
            --hopsNeeded;
        }

        hops.Add(pivotContact);
        return new SelectedPath(hops, wasExtended);

        void Exclude(RelayContact contact)
        {
            excluded.Add(contact.RouterId);
            if (netmask > 0 && contact.GetIpv4Address() is { } ip)
            {
                excludedRanges.Add(Ipv4Prefix.FromAddress(ip, netmask));
            }
        }
    }
}
