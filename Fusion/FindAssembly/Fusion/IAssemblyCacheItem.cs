using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace FindAssembly.Fusion {

    [ComImport, Guid("9E3AAEB4-D1CD-11D2-BAB9-00C04F8ECEAE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAssemblyCacheItem {

        /// <summary>
        /// Allows the assembly in the global assembly cache to perform cleanup operations before it is released.
        /// </summary>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint AbortItem();

        /// <summary>
        /// Commits the cached assembly reference to memory.
        /// </summary>
        /// <param name="dwFlags">Flags defined in Fusion.idl.</param>
        /// <param name="pulDisposition">A value that indicates the result of the operation.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint Commit(
           uint dwFlags,
           ref ulong pulDisposition
        );

        /// <summary>
        /// Creates a stream with the specified name and format.
        /// </summary>
        /// <param name="dwFlags">Flags defined in Fusion.idl.</param>
        /// <param name="pszAssemblyName">The name of the stream to be created.</param>
        /// <param name="dwFormat">The format of the file to be streamed.</param>
        /// <param name="dwFormatFlags">Format-specific flags defined in Fusion.idl.</param>
        /// <param name="ppIStream">A pointer to the address of the returned IStream instance.</param>
        /// <param name="puliMaxSize">The maximum size of the stream referenced by ppIStream.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint CreateStream(
            uint dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszAssemblyName,
            uint dwFormat,
            uint dwFormatFlags,
            out IStream ppIStream,
            ref long puliMaxSize
        );
    }
}
