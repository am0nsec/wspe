using System;
using System.Runtime.InteropServices;

namespace FindAssembly.Fusion {

    /// <summary>
    /// Represents an enumerator for an array of IAssemblyName objects.
    /// </summary>
    [ComImport, Guid("21B8916C-F28E-11D2-A473-00C04F8EF448")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAssemblyEnum {

        /// <summary>
        /// Gets a pointer to the next IAssemblyName contained in this IAssemblyEnum object.
        /// </summary>
        /// <param name="pvReserved">Reserved for future extensibility. pvReserved must be a null reference.</param>
        /// <param name="ppName">The returned IAssemblyName pointer.</param>
        /// <param name="dwFlags">Reserved for future extensibility. dwFlags must be 0 (zero).</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint GetNextAssembly(
            IntPtr pvReserved,
            out IAssemblyName ppName,
            uint dwFlags
        );

        /// <summary>
        /// Resets this IAssemblyEnum object to its starting position.
        /// </summary>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint Reset();

        /// <summary>
        /// Creates a shallow copy of this IAssemblyEnum object.
        /// </summary>
        /// <param name="ppEnum">A pointer to the copy.</param>
        /// <returns>HRESULT</returns>
        [PreserveSig]
        uint Clone(
            out IAssemblyEnum ppEnum
        );
    }
}
