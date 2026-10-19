using System.Security.Cryptography;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxDiagnosticCodeNameTests
{
    [Theory]
    [InlineData("AuthorityChanged", "CurrentAuthorityChanged")]
    [InlineData("Freshness", "CurrentFreshness")]
    [InlineData("GrantWindow", "CurrentGrantWindow")]
    public void NativeAdmissionPreservesExactExceptionTypeAndOnlyFiniteReason(string reason, string label)
    {
        var error = CurrentMailboxDiagnostics.AdmissionRejection(Enum.Parse<CurrentMailboxAdmissionRejection>(reason));
        Assert.IsType<CryptographicException>(error);
        Assert.Equal(label, CurrentMailboxDiagnostics.AuthorityFailureCheck(error));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            CurrentMailboxDiagnostics.AdmissionRejection((CurrentMailboxAdmissionRejection)255));
    }

    [Theory]
    [InlineData("CurrentMailboxAdmission+<>c__DisplayClass1+<<WithAuthorityAsync>g__CheckAsync|2>d.MoveNext", true)]
    [InlineData("MailboxCurrentOperationLease+<CheckAsync>d__4.MoveNext", true)]
    [InlineData("C:\\private\\secret", false)]
    [InlineData("method\nsecret", false)]
    [InlineData("method;payload=secret", false)]
    [InlineData("", false)]
    public void OnlyBoundedOwnedCodeMetadataCanReachDiagnostic(string value, bool accepted) =>
        Assert.Equal(accepted, CurrentMailboxDiagnostics.IsCodeMethodName(value));

    [Fact]
    public void AuthorityDiagnosticUsesOnlyExactBuiltInFiniteLabel()
    {
        var error = new CryptographicException("DO-NOT-EXPORT");
        error.Data["Deep.MailboxAuthority.Check"] = "GrantNotBefore";
        Assert.Equal("GrantNotBefore", CurrentMailboxDiagnostics.AuthorityFailureCheck(error));
        error.Data["Deep.MailboxAuthority.Check"] = "DO-NOT-EXPORT";
        Assert.Equal("Unclassified", CurrentMailboxDiagnostics.AuthorityFailureCheck(error));
        Assert.False(CurrentMailboxDiagnostics.IsCodeMethodName(new string('a', 241)));
    }
}
