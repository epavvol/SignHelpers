namespace VNetDev.Security.SignHelpers
{
    /// <summary>
    /// Defines the options that control what data is embedded in the
    /// signature blob.
    /// </summary>
    public enum SigningOption
    {
        /// <summary>
        /// Embeds only the signer's certificate.
        /// </summary>
        AddOnlyCertificate,

        /// <summary>
        /// Embeds the entire certificate chain.
        /// </summary>
        AddFullCertificateChain,

        /// <summary>
        /// Embeds the entire certificate chain, except for the root
        /// certificate.
        /// </summary>
        AddFullCertificateChainExceptRoot
    }
}