using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VNetDev.Security.SignHelpers
{
    /// <summary>
    /// X509Certificate extension methods for code signing
    /// </summary>
    public static class X509Certificate2Extensions
    {
        private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";

        /// <summary>
        /// Sign a file
        /// </summary>
        /// <param name="certificate">Signing certificate</param>
        /// <param name="filePath">Path to file</param>
        /// <param name="timestampServerUrl">URL of timestamp server</param>
        /// <param name="signingOption">Option that controls what gets embedded in the signature blob.</param>
        /// <returns><c>True</c> if signing was successful, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Required parameter was not specified</exception>
        /// <exception cref="ArgumentException">File not found</exception>
        /// <exception cref="SigningCertificateException">The certificate was not found or not good for signing.</exception>
        public static bool SignFile(this X509Certificate2 certificate, string filePath,
            string? timestampServerUrl = null,
            SigningOption signingOption = SigningOption.AddFullCertificateChainExceptRoot) =>
            CodeSigning.SignFile(filePath, certificate, timestampServerUrl, signingOption);

        internal static bool IsGoodForSigning(this X509Certificate2 certificate) =>
            certificate.HasPrivateKey && certificate.Extensions
                .Cast<X509Extension>()
                .Where(x => x is X509EnhancedKeyUsageExtension)
                .Cast<X509EnhancedKeyUsageExtension>()
                .Any(x => x.EnhancedKeyUsages
                    .Cast<Oid>()
                    .Any(k => k.Value == CodeSigningOid));
    }
}