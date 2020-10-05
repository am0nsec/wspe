using System;
using System.Reflection;
using FindAssembly.Fusion;

namespace FindAssembly {
    internal sealed class Program {
        static void Main(string[] args) {
            Console.WriteLine("\nFind and load .NET Framework Assembly from the GAC");
            Console.WriteLine("Copyright (C) 2020 Paul Laine (@am0nsec)");
            Console.WriteLine("https://ntamonsec.blogpost.com\n");

            if (args.Length != 2) {
                Console.WriteLine("usage: FindAssembly.exe <1> <2>");
                Console.WriteLine("\t 1- The name of the .NET Framework Assembly to find.");
                Console.WriteLine("\t 2- The major version of the .NET Framework Assembly.\n");

                Console.WriteLine("example: \n");
                Console.WriteLine("\t FindAssembly.exe System.Management.Automation 3\n");
                return;
            }
            string szAssemblyName = args[0];
            Int16 i16Version = Convert.ToInt16(args[1]);

            // Find the System.Management.Automation Assembly
            GACUtil gac = new GACUtil();
            ASSEMBLY_IDENTITY AssemblyIdentity = new ASSEMBLY_IDENTITY();
            gac.FindAssembly(szAssemblyName, i16Version, ref AssemblyIdentity);
            Console.WriteLine($"Assembly path: \n{AssemblyIdentity.szGacPath}\n");

            // Load the assembly into new application domain
            AppDomain domain = AppDomain.CreateDomain("C367F796-8B63-461D-A058-2CCD657F1891");
            Assembly assembly = domain.Load(AssemblyName.GetAssemblyName(AssemblyIdentity.szGacPath));

            // List all types
            if (assembly != null) {
                Console.WriteLine("Exported Types:");
                foreach (Type t in assembly.GetExportedTypes())
                    Console.WriteLine($"\t {t.Name}");

                AppDomain.Unload(domain);
            } else {
                Console.WriteLine("Assembly not loaded!");
            }
#if DEBUG
            Console.ReadKey();
#endif
        }
    }
}
