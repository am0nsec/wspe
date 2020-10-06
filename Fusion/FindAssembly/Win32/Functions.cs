using System;
using FindAssembly.Fusion;
using System.Runtime.InteropServices;

namespace FindAssembly.Win32 {
    internal class Functions {

        [DllImport("fusion.dll", CharSet = CharSet.Auto)]
        [PreserveSig]
        public static extern uint CreateAssemblyEnum(
            out IAssemblyEnum ppEnum,
            IntPtr pUnkReserved,
            IAssemblyName pName,
            ASM_CACHE_FLAGS dwFlags,
            IntPtr pvReserved
        );

        [DllImport("fusion.dll", CharSet = CharSet.Auto)]
        [PreserveSig]
        public static extern uint CreateAssemblyCache(
            out IAssemblyCache ppAsmCache,
            uint dwReserved
        );
    }
}
