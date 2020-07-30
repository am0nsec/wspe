using System;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;


namespace JITCompilation {
        internal sealed class Program {

        /// <summary>
        /// Used for mutual-exclusion lock.
        /// </summary>
        private static object Mutex = new object();

        /// <summary>
        /// Delegate used to get the address of the PEB structure.
        /// </summary>
        /// <returns>Address of the PEB structure.</returns>
        private delegate IntPtr GetPEBDelegate();

        /// <summary>
        /// Program entry point.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        static void Main(string[] args) {
            // Find the method
            MethodInfo method = typeof(JITCompilation.Program).GetMethod(nameof(JITCompilation.Program.Stub), BindingFlags.NonPublic | BindingFlags.Static);
            Debug.Assert(method != null, "[-] Can't find the method to JIT compile.");

            // JIT compile the method
            IntPtr ManagedMethodPtr = method.MethodHandle.GetFunctionPointer();
            if (Util.IsByteCallProcedure(ManagedMethodPtr)) {
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
                Debug.Assert(Util.IsByteJmpProcedure(ManagedMethodPtr), "[-] Error while JIT compiling the method.");
            }

            // Get the address of the un-managed function
            UInt64 offset = (UInt64)ManagedMethodPtr - (UInt64)Marshal.ReadInt32(ManagedMethodPtr, 1);
            while (offset % 16 != 0)
                offset++;
            IntPtr UnmanagedMethodPtr = (IntPtr)offset;
            Debug.Assert(UnmanagedMethodPtr != IntPtr.Zero, "[-] Error while retrieving address of the un-managed method.");

            // Inject and execute the code
            IntPtr PEBAddressPtr = IntPtr.Zero;
            lock (Mutex) {
                 Span<byte> asm = stackalloc byte[10] {
                    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // MOV RAX, GS:[0x60]
                    0xC3                                                   // RET
                 };

                Marshal.Copy(asm.ToArray(), 0, UnmanagedMethodPtr, asm.Length);
                Debug.Assert(Marshal.ReadByte(UnmanagedMethodPtr, 0) == 0x65, "[-] Error while overwriting un-managed method code.");
                Debug.Assert(Marshal.ReadByte(UnmanagedMethodPtr, 9) == 0xC3, "[-] Error while overwriting un-managed method code.");

                GetPEBDelegate GetPEB = Marshal.GetDelegateForFunctionPointer<GetPEBDelegate>(UnmanagedMethodPtr);
                PEBAddressPtr = GetPEB();
                Debug.Assert(PEBAddressPtr != IntPtr.Zero, "[-] Error while retrieving the address of the PEB structure.");
            };

            // Pull the structure out of memory
            PEB _PEB = Marshal.PtrToStructure<PEB>(PEBAddressPtr);
            Debug.Assert(_PEB.Equals(default(PEB)), "[-] Error while pulling out the structure from memory");
        }

        /// <summary>
        /// This method will be JIT Compiled to generate RWX memory region.
        /// DO NOT USE.
        /// </summary>
        /// <returns>In this case the address of the PEB structure.</returns>
        private static IntPtr Stub() {
            throw new NotImplementedException();
        }
    }

    internal sealed class Util {
        /// <summary>
        /// Check if the address points to a CALL instruction.
        /// </summary>
        /// <param name="pointer">The address of an instruction.</param>
        /// <returns>Whether the address points to a CALL instruction.</returns>
        public static bool IsByteCallProcedure(IntPtr pointer) {
            if (pointer == IntPtr.Zero)
                return false;

            byte opcode = Marshal.ReadByte(pointer);
            switch (opcode) {
                case 0x9A: // CALL far
                case 0xE8: // CALL near
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Check if the address points to a JMP instruction.
        /// </summary>
        /// <param name="pointer">The address of an instruction.</param>
        /// <returns>Whether the address points to a JMP instruction.</returns>
        public static bool IsByteJmpProcedure(IntPtr pointer) {
            if (pointer == IntPtr.Zero)
                return false;

            byte opcode = Marshal.ReadByte(pointer);
            switch (opcode) {
                case 0xE9: // JMP near
                case 0xEA: // JMP far
                case 0xEB: // JMP short
                    return true;
                default:
                    return false;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr Buffer;
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
