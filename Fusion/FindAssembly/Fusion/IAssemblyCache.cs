using System;
using System.Runtime.InteropServices;

namespace FindAssembly.Fusion {

    /// <summary>
    /// Represents the global assembly cache for use by the fusion technology.
    /// </summary>
    [ComImport, Guid("E707DCDE-D1CD-11D2-BAB9-00C04F8ECEAE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAssemblyCache {

        /// <summary>
        /// Uninstalls the specified assembly from the global assembly cache.
        /// </summary>
        /// <param name="dwFlags"> Flags defined in Fusion.idl.</param>
        /// <param name="pszAssemblyName">The name of the assembly to uninstall.</param>
        /// <param name="pRefData">A FUSION_INSTALL_REFERENCE structure that contains the installation data for the assembly.</param>
        /// <param name="pulDisposition">One of the disposition values defined in Fusion.idl. Possible values include the following:
        /// <list type="bullet">
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED (1)</item>
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE (2)</item>
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED (3)</item>
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING (4)</item>
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES (5)</item>
        /// <item>IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND (6)</item>
        /// </list>
        /// </param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint UninstallAssembly(
            uint dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName,
            [MarshalAs(UnmanagedType.LPArray)] FUSION_INSTALL_REFERENCE[] pRefData,
            out uint pulDisposition
        );

        /// <summary>
        /// Gets the requested data about the specified assembly.
        /// </summary>
        /// <param name="dwFlags">Flags defined in Fusion.idl. The following values are supported: 
        /// <list>
        /// <item>QUERYASMINFO_FLAG_VALIDATE (0x00000001)</item>
        /// <item>QUERYASMINFO_FLAG_GETSIZE (0x00000002)</item>
        /// </list>
        /// </param>
        /// <param name="pszAssemblyName">The name of the assembly for which data will be retrieved.</param>
        /// <param name="pAsmInfo">An ASSEMBLY_INFO structure that contains data about the assembly.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint QueryAssemblyInfo(
            uint dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName,
            ref ASSEMBLY_INFO pAsmInfo
        );

        /// <summary>
        /// Gets a reference to a new IAssemblyCacheItem object.
        /// </summary>
        /// <param name="dwFlags">Flags defined in Fusion.idl. The following values are supported: 
        /// <list type="bullet">
        /// <item>IASSEMBLYCACHE_INSTALL_FLAG_REFRESH (0x00000001)</item>
        /// <item>IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH (0x00000002)</item>
        /// </list>
        /// </param>
        /// <param name="pvReserved">Reserved for future extensibility. pvReserved must be a null reference.</param>
        /// <param name="ppAsmItem">The returned IAssemblyCacheItem pointer.</param>
        /// <param name="pszAssemblyName">Uncanonicalized, comma-separated name=value pairs.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint CreateAssemblyCacheItem(
            uint dwFlags,
            IntPtr pvReserved,
            out IAssemblyCacheItem ppAsmItem,
            [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName
        );

        /// <summary>
        /// Reserved for internal use by the fusion technology.
        /// </summary>
        /// <param name="ppAsmScavenger">The returned IUnknown pointer.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint CreateAssemblyScavenger([MarshalAs(UnmanagedType.IUnknown)] out object ppAsmScavenger);

        /// <summary>
        /// Installs the specified assembly in the global assembly cache.
        /// </summary>
        /// <param name="dwFlags">Flags defined in Fusion.idl. The following values are supported:
        /// <list type="bullet">
        /// <item>IASSEMBLYCACHE_INSTALL_FLAG_REFRESH (0x00000001)</item>
        /// <item>IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH (0x00000002)</item>
        /// </list>
        /// </param>
        /// <param name="pszManifestFilePath">The path to the manifest for the assembly to install.</param>
        /// <param name="pRefData">A FUSION_INSTALL_REFERENCE structure that contains data for the installation.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint InstallAssembly(
            uint dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string pszManifestFilePath,
            [MarshalAs(UnmanagedType.LPArray)] FUSION_INSTALL_REFERENCE[] pRefData
        );
    }
}
