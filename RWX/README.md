## Read (R), Writable (W), Executable (X) ##

Collection of .NET Core C# code to generate Read, Writable and Executable memory region.

In each examples, the following code is injected and executed:
```csharp
Span<byte> asm = stackalloc byte[10] {
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // MOV RAX, GS:[0x60]
    0xC3                                                   // RET
};
```

This assembly code is used to the the address of the Process Environment Block (PEB) structure.
