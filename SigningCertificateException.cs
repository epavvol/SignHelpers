using System;

namespace VNetDev.Security.SignHelpers
{
    /// <summary>
    /// Signing certificate exception
    /// </summary>
    public class SigningCertificateException : Exception
    {
        /// <summary>
        /// Default exception constructor
        /// </summary>
        public SigningCertificateException()
        {
        }

        /// <summary>
        /// Message-contained exception constructor
        /// </summary>
        /// <param name="message">Exception message</param>
        public SigningCertificateException(string message) : base(message)
        {
        }
    }
}