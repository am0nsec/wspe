using System;
using System.Runtime.InteropServices;

namespace GetProcessEnvironmentBlock {
    public sealed class Program {
        static void Main(string[] args) {
            Console.WriteLine("[>] Copyright (C) 2020 Paul Laine (@am0nsec)");
            Console.WriteLine("[>] Get PEB w/ C#");
            Console.WriteLine("   ----------------------------------------\n");

            // ASM to get the PEB
            Span<byte> stub = stackalloc byte[10] {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // MOV RAX, GS:[0x60]
                0xC3                                                   // RET
            };

            // Execute the ASM and get the PEB address
            Console.WriteLine("[>] Get the address of the PEB:");
            IntPtr pPebAddress = IntPtr.Zero;
            unsafe {
                fixed (byte* ptr = &MemoryMarshal.GetReference(stub)) {
                    GetPebDelegate func = Marshal.GetDelegateForFunctionPointer<GetPebDelegate>((IntPtr)ptr);

                    if (!VirtualProtect((IntPtr)ptr, stub.Length, 0x40, out uint lpflOldProtect)) {
                        Console.WriteLine("[-] Unable to find change memory page permission");
                        return;
                    }

                    pPebAddress = func();
                    if (pPebAddress == IntPtr.Zero) {
                        Console.WriteLine("[-] Unable to find PEB address");
                        return;
                    }
                }
            }
            Console.WriteLine("  - 0x{0:x16}", pPebAddress.ToInt64());

            // Get the structure from memory
            PEB _PEB = new PEB();
            _PEB = Marshal.PtrToStructure<PEB>(pPebAddress);
            if (_PEB.Equals(default(PEB))) {
                Console.WriteLine("[-] Invalid PEB structure returned");
                return;
            }

            // Get some info
            Console.WriteLine("\n[>] Extract few data:");
            Console.WriteLine($"  - BeingDebugged:     {_PEB.BeingDebugged.ToString()}");
            Console.WriteLine($"  - Mutant:            0x{_PEB.Mutant.ToString("X16")}");
            Console.WriteLine($"  - ImageBaseAddress:  0x{_PEB.ImageBaseAddress.ToString("X16")}");
            Console.WriteLine($"  - Ldr:               0x{_PEB.Ldr.ToString("X16")}");
            Console.WriteLine($"  - OSMajorVersion:    {_PEB.OSMajorVersion}");
            Console.WriteLine($"  - SessionId:         {_PEB.SessionId}");

#if DEBUG
            Console.ReadKey();
#endif
        }

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetPebDelegate();

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct LIST_ENTRY {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PEB {
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
