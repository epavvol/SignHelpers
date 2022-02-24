using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace VNetDev.Security.SignHelpers
{
    /// <summary>
    /// Code signing helpers class
    /// </summary>
    public static class CodeSigning
    {
        /// <summary>
        /// Sign a file
        /// </summary>
        /// <param name="filePath">Path to file</param>
        /// <param name="certificateThumbprint">Thumbprint of signing certificate</param>
        /// <param name="timestampServerUrl">URL of timestamp server</param>
        /// <param name="storeName">Store of signing certificate</param>
        /// <param name="storeLocation">Store location of signing certificate</param>
        /// <param name="signingOption">Option that controls what gets embedded in the signature blob.</param>
        /// <returns><c>True</c> if signing was successful, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Required parameter was not specified</exception>
        /// <exception cref="ArgumentException">File not found</exception>
        /// <exception cref="SigningCertificateException">The certificate was not found or not good for signing.</exception>
        public static bool SignFile(string filePath, string certificateThumbprint, string? timestampServerUrl = null,
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.LocalMachine,
            SigningOption signingOption = SigningOption.AddFullCertificateChainExceptRoot)
        {
            if (filePath == null) throw new ArgumentNullException(nameof(filePath));
            if (certificateThumbprint == null) throw new ArgumentNullException(nameof(certificateThumbprint));
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            using var certificate = store.Certificates.Cast<X509Certificate2>()
                .FirstOrDefault(x => x.Thumbprint == certificateThumbprint);
            return SignFile(filePath,
                certificate ?? throw new SigningCertificateException(
                    $"Certificate with thumbprint {certificateThumbprint} was not found in {storeLocation}\\{storeName}"),
                timestampServerUrl,
                signingOption);
        }

        /// <summary>
        /// Sign a file
        /// </summary>
        /// <param name="filePath">Path to file</param>
        /// <param name="certificate">Signing certificate</param>
        /// <param name="timestampServerUrl">URL of timestamp server</param>
        /// <param name="signingOption">Option that controls what gets embedded in the signature blob.</param>
        /// <returns><c>True</c> if signing was successful, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Required parameter was not specified</exception>
        /// <exception cref="ArgumentException">File not found</exception>
        /// <exception cref="SigningCertificateException">The certificate was not found or not good for signing.</exception>
        public static bool SignFile(string filePath, X509Certificate2 certificate, string? timestampServerUrl = null,
            SigningOption signingOption = SigningOption.AddFullCertificateChainExceptRoot)
        {
            if (filePath == null) throw new ArgumentNullException(nameof(filePath));
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (!File.Exists(filePath)) throw new ArgumentException("File not found", nameof(filePath));
            if (!certificate.IsGoodForSigning())
                throw new SigningCertificateException("Certificate is not good for signing");

            var result = false;
            var pSignInfo = IntPtr.Zero;

            try
            {
                var signInfo = InitSignInfoStruct(filePath, certificate, timestampServerUrl, signingOption);
                pSignInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf(signInfo));
                Marshal.StructureToPtr(signInfo, pSignInfo, false);

                result = CryptDigitalSign(
                    0x0001,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    pSignInfo,
                    IntPtr.Zero);

                if (signInfo.pSignExtInfo != IntPtr.Zero)
                {
                    Marshal.DestroyStructure<CryptUiWizDigitalSignExtendedInfo>(signInfo.pSignExtInfo);
                    Marshal.FreeCoTaskMem(signInfo.pSignExtInfo);
                }
            }
            finally
            {
                Marshal.DestroyStructure<CryptUiWizDigitalSignInfo>(pSignInfo);
                Marshal.FreeCoTaskMem(pSignInfo);
            }

            return result;
        }

        private static CryptUiWizDigitalSignInfo InitSignInfoStruct(string fileName,
            X509Certificate2 certificate,
            string? timeStampServerUrl,
            SigningOption option,
            string? hashAlgorithm = null)
        {
            var signInfo = new CryptUiWizDigitalSignInfo();

            signInfo.dwSize = (uint)Marshal.SizeOf(signInfo);
            signInfo.dwSubjectChoice = 0x01;
            signInfo.pwszFileName = fileName;
            signInfo.dwSigningCertChoice = 0x01;
            signInfo.pSigningCertContext = certificate.Handle;
            signInfo.pwszTimestampURL = timeStampServerUrl;
            signInfo.dwAdditionalCertChoice = option switch
            {
                SigningOption.AddOnlyCertificate => 0u,
                SigningOption.AddFullCertificateChain => 1u,
                SigningOption.AddFullCertificateChainExceptRoot => 2u,
                _ => 2u
            };

            var extendedSignInfo = new CryptUiWizDigitalSignExtendedInfo();

            extendedSignInfo.dwSize = (uint)Marshal.SizeOf(extendedSignInfo);
            extendedSignInfo.dwAttrFlagsNotUsed = 0;
            extendedSignInfo.pwszDescription = string.Empty;
            extendedSignInfo.pwszMoreInfoLocation = string.Empty;
            extendedSignInfo.pszHashAlg = null;
            extendedSignInfo.pwszSigningCertDisplayStringNotUsed = IntPtr.Zero;
            extendedSignInfo.hAdditionalCertStoreNotUsed = IntPtr.Zero;
            extendedSignInfo.psAuthenticatedNotUsed = IntPtr.Zero;
            extendedSignInfo.psUnauthenticatedNotUsed = IntPtr.Zero;

            var pExtendedSignInfoBuffer = Marshal.AllocCoTaskMem(Marshal.SizeOf(extendedSignInfo));
            Marshal.StructureToPtr(extendedSignInfo, pExtendedSignInfoBuffer, false);
            signInfo.pSignExtInfo = pExtendedSignInfoBuffer;

            return signInfo;
        }

        [DllImport("cryptUI.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CryptUIWizDigitalSign")]
        private static extern bool CryptDigitalSign(uint dwFlags,
            IntPtr hwndParentNotUsed,
            IntPtr pwszWizardTitleNotUsed,
            IntPtr pDigitalSignInfo,
            IntPtr ppSignContextNotUsed);
    }
}