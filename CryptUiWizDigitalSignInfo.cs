using System;
using System.Runtime.InteropServices;

namespace VNetDev.Security.SignHelpers
{
    internal struct CryptUiWizDigitalSignInfo
    {
        internal uint dwSize;
        internal uint dwSubjectChoice;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string pwszFileName;

        internal uint dwSigningCertChoice;
        internal IntPtr pSigningCertContext;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string? pwszTimestampURL;

        internal uint dwAdditionalCertChoice;
        internal IntPtr pSignExtInfo;
    }
}