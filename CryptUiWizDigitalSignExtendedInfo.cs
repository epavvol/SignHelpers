using System;
using System.Runtime.InteropServices;

namespace VNetDev.Security.SignHelpers
{
    internal struct CryptUiWizDigitalSignExtendedInfo
    {
        internal uint dwSize;
        internal uint dwAttrFlagsNotUsed;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string pwszDescription;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string pwszMoreInfoLocation;

        [MarshalAs(UnmanagedType.LPStr)]
        internal string? pszHashAlg;

        internal IntPtr pwszSigningCertDisplayStringNotUsed; // LPCWSTR
        internal IntPtr hAdditionalCertStoreNotUsed; // HCERTSTORE
        internal IntPtr psAuthenticatedNotUsed; // PCRYPT_ATTRIBUTES
        internal IntPtr psUnauthenticatedNotUsed; // PCRYPT_ATTRIBUTES
    }
}