using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PInvoke {
    internal sealed class Program {
        /// <summary>
        /// Delegate used to get the address of the PEB structure.
        /// </summary>
        /// <returns>Address of the PEB structure.</returns>
        private delegate IntPtr GetPEBDelegate();

        /// <summary>
        /// More information about the different flags here: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
        /// </summary>
        private static Int32 MEM_COMMIT { get; } = 0x00001000;
        private static Int32 MEM_RESERVE { get; } = 0x00002000;
        private static Int32 MEM_RESET { get; } = 0x00080000;
        private static Int32 MEM_RESET_UNDO { get; } = 0x1000000;
        private static Int32 MEM_LARGE_PAGES { get; } = 0x20000000;
        private static Int32 MEM_PHYSICAL { get; } = 0x00400000;
        private static Int32 MEM_TOP_DOWN { get; } = 0x00100000;
        private static Int32 MEM_WRITE_WATCH { get; } = 0x00200000;

        /// <summary>
        /// More information about the different flags here: https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        /// </summary>
        private static Int32 PAGE_EXECUTE { get; } = 0x10;
        private static Int32 PAGE_EXECUTE_READ { get; } = 0x20;
        private static Int32 PAGE_EXECUTE_READWRITE { get; } = 0x40;
        private static Int32 PAGE_EXECUTE_WRITECOPY { get; } = 0x80;
        private static Int32 PAGE_NOACCESS { get; } = 0x01;
        private static Int32 PAGE_READONLY { get; } = 0x02;
        private static Int32 PAGE_READWRITE { get; } = 0x04;
        private static Int32 PAGE_WRITECOPY { get; } = 0x08;
        private static Int32 PAGE_TARGETS_INVALID { get; } = 0x40000000;
        private static Int32 PAGE_TARGETS_NO_UPDATE { get; } = 0x40000000;
        private static Int32 PAGE_GUARD { get; } = 0x100;
        private static Int32 PAGE_NOCACHE { get; } = 0x200;
        private static Int32 PAGE_WRITECOMBINE { get; } = 0x400;

        /// <summary>
        /// Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
        /// Memory allocated by this function is automatically initialized to zero.
        /// Link: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
        /// </summary>
        /// <param name="lpAddress">The starting address of the region to allocate.</param>
        /// <param name="dwSize">The size of the region, in bytes.</param>
        /// <param name="flAllocationType">The type of memory allocation.</param>
        /// <param name="flProtect">The memory protection for the region of pages to be allocated.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            Int32  dwSize,
            Int32  flAllocationType,
            Int32  flProtect
        );

        /// <summary>
        /// Changes the protection on a region of committed pages in the virtual address space of the calling process.
        /// </summary>
        /// <param name="lpAddress">A pointer an address that describes the starting page of the region of pages whose access protection attributes are to be changed.</param>
        /// <param name="dwSize">The size of the region whose access protection attributes are to be changed, in bytes.</param>
        /// <param name="flNewProtect">The memory protection option.</param>
        /// <param name="lpflOldProtect">A pointer to a variable that receives the previous access protection value of the first page in the specified region of pages.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(
            IntPtr    lpAddress,
            Int32     dwSize,
            Int32     flNewProtect,
            ref Int32 lpflOldProtect
        );

        /// <summary>
        /// Program entry point.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        static void Main(string[] args) {
            Span<byte> asm = stackalloc byte[10] {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // MOV RAX, GS:[0x60]
                0xC3                                                   // RET
            };

            // Allocate memory
            IntPtr lpAddress = VirtualAlloc(IntPtr.Zero, asm.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Debug.Assert(lpAddress != IntPtr.Zero, "[-] Error while allocating memory: kernl32!VirtualAlloc.");

            // Write asm in memory
            Marshal.Copy(asm.ToArray(), 0, lpAddress, asm.Length);

            // Change memory permissions
            Int32 lpflOldProtect = 0;
            bool success = VirtualProtect(lpAddress, asm.Length, PAGE_EXECUTE_READ, ref lpflOldProtect);
            Debug.Assert(success || lpflOldProtect == 4, "[-] Error while changing the memory permissions of the allocation memory.");

            // Create delegate
            GetPEBDelegate GetPEB = Marshal.GetDelegateForFunctionPointer<GetPEBDelegate>(lpAddress);
            IntPtr PEBAddressPtr = GetPEB();
            Debug.Assert(PEBAddressPtr != IntPtr.Zero, "[-] Error while retrieving the address of the PEB structure.");

            // Pull the structure out of memory
            PEB _PEB = Marshal.PtrToStructure<PEB>(PEBAddressPtr);
            Debug.Assert(_PEB.Equals(default(PEB)), "[-] Error while pulling out the structure from memory");
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct LIST_ENTRY {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct PEB {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public IntPtr Mutant;
        public IntPtr ImageBaseAddress;
        public IntPtr Ldr;
        public IntPtr ProcessParameters;
        public IntPtr SubSystemData;
        public IntPtr ProcessHeap;
        public IntPtr FastPebLock;
        public IntPtr AtlThunkSListPtr;
        public IntPtr IFEOKey;
        public uint CrossProcessFlags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding1;
        public IntPtr KernelCallbackTable;
        public uint SystemReserved;
        public uint AtlThunkSListPtr32;
        public IntPtr ApiSetMap;
        public uint TlsExpansionCounter;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding2;
        public IntPtr TlsBitmap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public uint[] TlsBitmapBits;
        public IntPtr ReadOnlySharedMemoryBase;
        public IntPtr SharedData;
        public IntPtr ReadOnlyStaticServerData;
        public IntPtr AnsiCodePageData;
        public IntPtr OemCodePageData;
        public IntPtr UnicodeCaseTableData;
        public uint NumberOfProcessors;
        public uint NtGlobalFlag;
        public ulong CriticalSectionTimeout;
        public ulong HeapSegmentReserve;
        public ulong HeapSegmentCommit;
        public ulong HeapDeCommitTotalFreeThreshold;
        public ulong HeapDeCommitFreeBlockThreshold;
        public uint NumberOfHeaps;
        public uint MaximumNumberOfHeaps;
        public IntPtr ProcessHeaps;
        public IntPtr GdiSharedHandleTable;
        public IntPtr ProcessStarterHelper;
        public uint GdiDCAttributeList;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding3;
        public IntPtr LoaderLock;
        public uint OSMajorVersion;
        public uint OSMinorVersion;
        public ushort OSBuildNumber;
        public ushort OSCSDVersion;
        public uint OSPlatformId;
        public uint ImageSubsystem;
        public uint ImageSubsystemMajorVersion;
        public uint ImageSubsystemMinorVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding4;
        public ulong ActiveProcessAffinityMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]
        public uint[] GdiHandleBuffer;
        public IntPtr PostProcessInitRoutine;
        public IntPtr TlsExpansionBitmap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public uint[] TlsExpansionBitmapBits;
        public uint SessionId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding5;
        public ulong AppCompatFlags;
        public ulong AppCompatFlagsUser;
        public IntPtr pShimData;
        public IntPtr AppCompatInfo;
        public UNICODE_STRING CSDVersion;
        public IntPtr ActivationContextData;
        public IntPtr ProcessAssemblyStorageMap;
        public IntPtr SystemDefaultActivationContextData;
        public IntPtr SystemAssemblyStorageMap;
        public ulong MinimumStackCommit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public IntPtr[] SparePointers;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public uint[] SpareUlongs;
        public IntPtr WerRegistrationData;
        public IntPtr WerShipAssertPtr;
        public IntPtr pUnused;
        public IntPtr pImageHeaderHash;
        public uint TracingFlags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding6;
        public ulong CsrServerReadOnlySharedMemoryBase;
        public ulong TppWorkerpListLock;
        public LIST_ENTRY TppWorkerpList;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public ulong[] WaitOnAddressHashTable;
        public IntPtr TelemetryCoverageHeader;
        public uint CloudFileFlags;
        public uint CloudFileDiagFlags;
        public byte PlaceholderCompatibilityMode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public byte[] PlaceholderCompatibilityModeReserved;
        public IntPtr LeapSecondData;
        public uint LeapSecondFlags;
        public uint NtGlobalFlag2;
    }
}
