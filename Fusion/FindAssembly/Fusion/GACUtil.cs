using System;
using System.Text;
using FindAssembly.Win32;
using System.Runtime.InteropServices;

namespace FindAssembly.Fusion {

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FUSION_INSTALL_REFERENCE {
        public uint cbSize;
        public uint dwFlags;
        public Guid guidScheme;
        public string szIdentifier;
        public string szNonCannonicalData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ASSEMBLY_INFO {
        public uint cbAssemblyInfo;
        public uint dwAssemblyFlags;
        public ulong uliAssemblySizeInKB;
        public IntPtr pszCurrentAssemblyPathBuf;
        public uint cchBuf;
    }

    public struct ASSEMBLY_VERSION {
        public short wMajor;
        public short wMinor;
        public short wBuild;
        public short wRevision;
    }

    public struct ASSEMBLY_IDENTITY {
        public string szName;
        public string szGacPath;
        public string szVersion;
    }

    public enum ASM_CACHE_FLAGS : uint {
        ASM_CACHE_ZAP = 0x1,
        ASM_CACHE_GAC = 0x2,
        ASM_CACHE_DOWNLOAD = 0x4,
        ASM_CACHE_ROOT = 0x8,
        ASM_CACHE_ROOT_EX = 0x80
    }

    public class GACUtil {

        public const uint IASSEMBLYCACHE_INSTALL_FLAG_REFRESH = 0x00000001;
        public const uint IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH = 0x00000002;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED = 0x00000001;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE = 0x00000002;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED = 0x00000003;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING = 0x00000004;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES = 0x00000005;
        public static uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND = 0x00000006;
        public static uint QUERYASMINFO_FLAG_VALIDATE = 0x00000001;
        public static uint QUERYASMINFO_FLAG_GETSIZE = 0x00000002;
        public static uint ASSEMBLYINFO_FLAG_INSTALLED = 0x00000001;
        public static uint ASSEMBLYINFO_FLAG_PAYLOADRESIDENT = 0x00000002;

        private IAssemblyEnum pIAssemblyEnum { get; set; }
        private IAssemblyCache pIAssemblyCache { get; set; }

        /// <summary>
        /// Constructor. Initialise IAssemblyEnum and IAssemblyCache.
        /// </summary>
        public GACUtil() {
            uint hr = Functions.CreateAssemblyEnum(out IAssemblyEnum pIAssemblyEnum, IntPtr.Zero, null, ASM_CACHE_FLAGS.ASM_CACHE_GAC, IntPtr.Zero);
            if (!Macros.SUCCEEDED(hr) || pIAssemblyEnum == null)
                throw new Exception("[-] Unable to create IAssemblyEnum interface.");
            this.pIAssemblyEnum = pIAssemblyEnum;

            hr = Functions.CreateAssemblyCache(out IAssemblyCache pIAssemblyCache, 0);
            if (!Macros.SUCCEEDED(hr) || pIAssemblyCache == null)
                throw new Exception("[-] Unable to create fusion!IAssemblyEnum interface.");
            this.pIAssemblyCache = pIAssemblyCache;
        }

        /// <summary>
        /// Destructor. Release IAssemblyEnum and IAssemblyCache
        /// </summary>
        ~GACUtil() {
            if (this.pIAssemblyEnum != null)
                Marshal.ReleaseComObject(this.pIAssemblyEnum);
            if (this.pIAssemblyCache != null)
                Marshal.ReleaseComObject(this.pIAssemblyCache);
        }

        /// <summary>
        /// Parse all the Assemblies from the Global Assembly Cache (GAC). 
        /// </summary>
        /// <param name="wszFilter">Assembly to find.</param>
        /// <param name="wMajor">Major version of the Assembly to find</param>
        /// <param name="pAssemblyIdentity">Pointer to an ASSEMBLY_IDENTITY structure.</param>
        /// <returns>Whether the function successfully executed</returns>
        private uint ParseAllAssembliesInternal(string wszFilter, short wMajor, ref ASSEMBLY_IDENTITY pAssemblyIdentity) {
            // Parse all assemblies
            while (this.pIAssemblyEnum.GetNextAssembly(IntPtr.Zero, out IAssemblyName pIassemblyName, 0) == 0) {
                string wszAssemblyName = "";
                this.GetAssemblyName(ref pIassemblyName, ref wszAssemblyName);

                string wszAssemblyGacPath = "";
                this.GetAssemblyGACPath(ref wszAssemblyName, ref wszAssemblyGacPath);

                ASSEMBLY_VERSION AssemblyVersion = new ASSEMBLY_VERSION();
                this.GetAssemblyVersion(ref pIassemblyName, ref AssemblyVersion);

                // Search for an Assembly
                if ((!string.IsNullOrEmpty(wszFilter) && wszFilter.Equals(wszAssemblyName)) && (wMajor != 0) && wMajor == AssemblyVersion.wMajor) {
                    if (pAssemblyIdentity.Equals(null))
                        return Macros.E_FAIL;

                    pAssemblyIdentity.szName = wszFilter;
                    pAssemblyIdentity.szGacPath = wszAssemblyGacPath;
                    pAssemblyIdentity.szVersion = AssemblyVersion.wMajor + "." + AssemblyVersion.wMinor + "." + AssemblyVersion.wBuild + "." + AssemblyVersion.wRevision;
                    return Macros.S_OK;
                }
            }

            if (!string.IsNullOrEmpty(wszFilter))
                return Macros.E_FAIL;
            return Macros.S_OK;
        }

        /// <summary>
        /// Parse all the Assemblies from the Global Assembly Cache (GAC).
        /// </summary>
        /// <returns>Whether the function successfully executed.</returns>
        public uint ParseAllAssemblies() {
            ASSEMBLY_IDENTITY dummy = new ASSEMBLY_IDENTITY();

            this.pIAssemblyEnum.Reset();
            return this.ParseAllAssembliesInternal(null, 0, ref dummy);
        }

        /// <summary>
        /// Find an Assembly from the Global Assembly Cache (GAC).
        /// </summary>
        /// <param name="wszAssemblyName">Name of the Assembly to find.</param>
        /// <param name="wMajor">Major version of the Assembly to find.</param>
        /// <param name="pAssemblyIdentity">Pointer to an ASSEMBLY_IDENTITY structure.</param>
        /// <returns></returns>
        public uint FindAssembly(string wszAssemblyName, short wMajor, ref ASSEMBLY_IDENTITY pAssemblyIdentity) {
            if (wszAssemblyName == null || pAssemblyIdentity.Equals(null))
                return Macros.E_FAIL;

            this.pIAssemblyEnum.Reset();
            return this.ParseAllAssembliesInternal(wszAssemblyName, wMajor, ref pAssemblyIdentity);
        }

        /// <summary>
        /// Get the name of an Assembly.
        /// </summary>
        /// <param name="pIAssemblyName">Pointer to an IAssemblyName interface.</param>
        /// <param name="wszAssemblyName">Pointer to the name of the Assembly.</param>
        /// <returns>Whether the function successfully executed.</returns>
        public uint GetAssemblyName(ref IAssemblyName pIAssemblyName, ref string wszAssemblyName) {
            if (pIAssemblyName == null)
                return Macros.E_FAIL;

            uint uBufferSize = 0;
            pIAssemblyName.GetName(ref uBufferSize, null);
            if (uBufferSize == 0)
                return Macros.E_FAIL;

            StringBuilder bob = new StringBuilder((int)uBufferSize);
            uint hr = pIAssemblyName.GetName(ref uBufferSize, bob);
            if (!Macros.SUCCEEDED(hr))
                return Macros.E_FAIL;

            wszAssemblyName = bob.ToString();
            return Macros.S_OK;
        }

        /// <summary>
        /// Get the path of the Assembly in the Global Assembly Cache (GAC).
        /// </summary>
        /// <param name="wszAssemblyName">Pointer to the name of the assembly to query information.</param>
        /// <param name="wszAssemblyGacPath">Pointer to the path of the assembly in the GAC.</param>
        /// <returns>Whether the function successfully executed.</returns>
        public uint GetAssemblyGACPath(ref string wszAssemblyName, ref string wszAssemblyGacPath) {
            if (this.pIAssemblyCache == null || wszAssemblyName == null)
                return Macros.E_FAIL;

            // Get buffer size
            ASSEMBLY_INFO AssemblyInfo = new ASSEMBLY_INFO();
            pIAssemblyCache.QueryAssemblyInfo(QUERYASMINFO_FLAG_GETSIZE, wszAssemblyName, ref AssemblyInfo);
            if (AssemblyInfo.cchBuf == 0)
                return Macros.E_FAIL;

            // Get value
            AssemblyInfo.pszCurrentAssemblyPathBuf = Marshal.AllocHGlobal((int)AssemblyInfo.cchBuf * 2);
            uint hr = pIAssemblyCache.QueryAssemblyInfo(QUERYASMINFO_FLAG_VALIDATE, wszAssemblyName, ref AssemblyInfo);
            if (!Macros.SUCCEEDED(hr))
                return Macros.E_FAIL;

            // Copy value
            wszAssemblyGacPath = Marshal.PtrToStringUni(AssemblyInfo.pszCurrentAssemblyPathBuf);
            Marshal.FreeHGlobal(AssemblyInfo.pszCurrentAssemblyPathBuf);
            return Macros.S_OK;
        }

        /// <summary>
        /// Get the version of an Assembly.
        /// </summary>
        /// <param name="pIAssemblyName">Pointer to an IAssemblyName interface.</param>
        /// <param name="pAssemblyVersion">Pointer to an ASSEMBLY_VERSION structure.</param>
        /// <returns>Whether the function successfully executed.</returns>
        public uint GetAssemblyVersion(ref IAssemblyName pIAssemblyName, ref ASSEMBLY_VERSION pAssemblyVersion) {
            if (pIAssemblyName == null || pAssemblyVersion.Equals(null))
                return Macros.E_FAIL;

            pIAssemblyName.GetVersion(out uint dwHigh, out uint dwLow);
            pAssemblyVersion.wMajor = (short)(dwHigh >> 0x10);
            pAssemblyVersion.wMinor = (short)(dwHigh & 0xff);
            pAssemblyVersion.wBuild = (short)(dwLow >> 0x10);
            pAssemblyVersion.wRevision = (short)(dwLow & 0xff);
            return Macros.S_OK;
        }
    }
}
