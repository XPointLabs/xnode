using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace XNode.IntegrationTests.Runtime;

public sealed class PinnedSelfIssuedCertificateTests
{
    [Fact]
    public void ExactPinAcceptsSelfIssuedChainErrorOnly()
    {
        using var certificate = CreateCertificate(DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var pin = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());

        Assert.True(HttpPrivacyPeerClient.ValidatePinnedCertificate(
            certificate,
            SslPolicyErrors.RemoteCertificateChainErrors,
            pin));
    }

    [Fact]
    public void NameMismatchAndWrongPinAreRejected()
    {
        using var certificate = CreateCertificate(DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var pin = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
        var wrong = pin.ToArray();
        wrong[0] ^= 0xff;

        Assert.False(HttpPrivacyPeerClient.ValidatePinnedCertificate(
            certificate,
            SslPolicyErrors.RemoteCertificateNameMismatch |
            SslPolicyErrors.RemoteCertificateChainErrors,
            pin));
        Assert.False(HttpPrivacyPeerClient.ValidatePinnedCertificate(
            certificate,
            SslPolicyErrors.RemoteCertificateChainErrors,
            wrong));
    }

    [Fact]
    public void ExpiredPinnedCertificateIsRejected()
    {
        using var certificate = CreateCertificate(DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(-1));
        var pin = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());

        Assert.False(HttpPrivacyPeerClient.ValidatePinnedCertificate(
            certificate,
            SslPolicyErrors.RemoteCertificateChainErrors,
            pin));
    }

    private static X509Certificate2 CreateCertificate(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=seed1.xpoint.network",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("seed1.xpoint.network");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") },
            true));
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
