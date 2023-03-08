# Maraca

Simple D/Invoke Process Hollower that I ported over from my P/Invoke one written in OSEP as practice for the CRTO2 course. 

##  Usage

Usage is simple. Clone the repository and generate some shellcode using msfvenom or your chosen provider. Some example calc shellcode has been placed in the repository already.

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
```

Encrypt the shellcode with your chosen key.

```bash
python3 encryption.py flareon shellcode.bin
```

Open the DInvokeHollow Solution file (.sln) in Visual Studio and add references in the Solution Explorer to the two .dll files included.

![Add References](images/references.png)

Also add the dnMerge NuGet package to the solution so that we can use the exe without having the transport the .dll files with it. Go to References -> Manage NuGet Packages and add it from there.

![Add NuGet](images/dnmerge.PNG)

Copy the encrypted shellcode output into the Program.cs file by replacing the placeholder shellcode and then build!

## Caveat
Don't expect this to beat defender or anything. It's very simple and just uses dynamic invocation of APIs at runtime and the stock minified D/Invoke from Rastamouse.

## TODO
- [x] Modify D/Invoke with standard dynamic invocation to use NT calls rather than calls from Kernel32.
- [ ] Add an option to use manual mapping of NTDLL into memory rather than dynamic invocation
- [ ] Add an option to use direct syscalls via GetSyscallStub as further practice
- [ ] Update README when done to include all the necessary D/Invoke DLLs
- [ ] Clean up Win32.cs and remove unnecessary structs and declarations 

My next step is to modify it to use lower level APIs and manual mapping of ntdll into a virtual address space to try and push evasion knowledge further!

## FAQ

- Why's it called Maraca?

Everyone manages to think of some shit hot name for their tool and I just couldn't so I just googled hollow things and saw a Maraca, now here we are