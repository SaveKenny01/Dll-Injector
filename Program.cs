using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace DLLInject
{
    class Inject
    {
        //============== CONSTANTS & DECLARATIONS ==================
        //||                                                      ||
        //==========================================================

        private const uint TH32CS_SNAPMODULE = 0x00000008;              //  Const for take snapshot to get list of modules

        private const uint PROCESS_CREATE_THREAD = 0X0002;              //
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;          //
        private const uint PROCESS_VM_OPERATION = 0X0008;               // Consts for open process with priveleges
        private const uint PROCESS_VM_WRITE = 0X0020;                   //
        private const uint PROCESS_VM_READ = 0X0010;                    //

        private const uint MEM_COMMIT = 0x1000;                         // 
        private const uint MEM_RESERVE = 0x2000;                        // Consts for memmory
        const uint PAGE_READWRITE = 0x04;
        const uint MEM_RELEASE = 0x8000;                                // Const for free up memory


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);       // Make process module snapshot (needed for search kernel32 module in current process)

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);             // Take first module from snapshot & -> ref to MODULEENTRY32

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);              // Take next module from snapshot  & -> ref to MODULEENTRY32

        [DllImport("kernel32", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);                                         // Close handle (dont forget about this or you will have memory leak)

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct MODULEENTRY32                                                             // Structur MODULEENTRY32. (where module32Next will be sent)
        {
            public uint dwSize;

            public uint th32ModuleID;

            public uint th32ProcessID;

            public uint GlblcntUsage;

            public uint ProccntUsage;

            public IntPtr modBaseAddr;

            public uint modBaseSize;

            public IntPtr hModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);           // open process with needed priveleges for take hProcess

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpAddress);                                  // Address function in module/dll

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);                                              // take handle module

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);         // Allocation memory for write there dll path

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);          // Write dll path to memory of process

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);          // To run code inside another process

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);          // Check result thread

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);        // Wait for the thread complete

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);          // Chek architecture process (64-bit dll cant be injected to 32-bit process)

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwFreeType, uint dwFreeTupe);      //  Free up memory after inject (for dll path) to avoid leaks


        public static (IntPtr kernel32Base, uint kernel32Size) FindKernel32InProcess(int ProcessID)     // Find address and size kernel32 in remote process (The function LoadLibraryW/A is location inside kernel32 module)
        {
            IntPtr snapshot = IntPtr.Zero;
            IntPtr kernel32Base = IntPtr.Zero;
            uint kernel32Size = 0;

            try
            {
                snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (uint)ProcessID);

                if (snapshot == IntPtr.Zero || snapshot.ToInt64() == -1)        // Check if snapshot is zero?
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] Error snapshot: {error}");
                    return (IntPtr.Zero, 0);
                }

                MODULEENTRY32 lpme = new MODULEENTRY32();                   
                lpme.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (!Module32First(snapshot, ref lpme))                         // Check if moduleFirst is zero?
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] Error 32First: {error}");
                    return (IntPtr.Zero, 0);
                }
                do
                {
                    Console.WriteLine($"Module: {lpme.szModule}");
                    if (lpme.szModule.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase))       //
                    {                                                                                   //  
                        kernel32Base = lpme.modBaseAddr;                                                //
                        kernel32Size = lpme.modBaseSize;                                                //  do -> if szModule(name) != kernel32 -> while -> take next module -> do....
                        Console.WriteLine($"kernel32 was found!!");                                     //
                        break;
                    }
                }
                while (Module32Next(snapshot, ref lpme));                   // Loop through the loaded modules until find kernel32


                if (kernel32Base == IntPtr.Zero)                            // Check if kernel32Base(address) is zero?
                {
                    Console.WriteLine("[!] Error: kernel32 not found!");            
                    return (IntPtr.Zero, 0);
                }
                Console.WriteLine($"Kernel32 address: {kernel32Base}");
                return (kernel32Base, kernel32Size);

            }
            finally
            {
                if (snapshot != IntPtr.Zero && snapshot.ToInt64() != -1)
                {
                    CloseHandle(snapshot);                                          // Close handle, dont forget this!
                }
            }

        }
        public static bool IsAdmin()                                                    // Check Admin privileges 
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void SysInfo(string TargetName, string DLLPath, bool IsProcess32Bit)              // Infromation about system (just for info)
        {
            bool compatibility;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[========== System info ==========]");
            Console.ResetColor();
            Console.WriteLine($"OC: {Environment.OSVersion}");
            Console.WriteLine($"Architecture OC: {(Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit")}");
            Console.WriteLine($"Process name: {TargetName}");
            Console.WriteLine($"Architecture Proccess: {(IsProcess32Bit ? "32-bit" : "64-bit")}"); 
            Console.WriteLine($"Architecture Dll: {(Is64BitDll(DLLPath) ? "64-bit" : "32-bit")}");
            Console.WriteLine($"Is Administrator: {(IsAdmin() ? "yes" : "no" )}");
            if (IsProcess32Bit == Is64BitDll(DLLPath))                                                     // Check compatibility ( IsWow64Process (true) = 32bit, Is64BitDll (true) = 64bit
            {
                Console.WriteLine($"Dll and process compatibility: no");
                Console.WriteLine("[!] Warning! Current process is not compatible with Dll!");
                Console.WriteLine($"Architecture Dll: {(Is64BitDll(DLLPath) ? "64-bit" : "32-bit")}");
                Console.WriteLine($"Architecture Proccess: {(IsProcess32Bit ? "32-bit" : "64-bit")}");
                while (true)
                {
                    Console.WriteLine("Injection will not work, contimue? [ y ] [ n ]");
                    string input = Console.ReadLine().ToLower();
                    if (input == "y" || input == "yes")
                    {
                        break;
                    }
                    if (input == "n" || input == "no")
                    {
                        return;
                    }
                    else { continue; }
                }
            }
            else { Console.WriteLine($"Dll and process compatibility: yes"); }
        }
        public static (string TargetName, Process TargetProcess) ChoiceProcess()            // Select target process
        {
            string TargetName = "";
            Process TargetProcess = null;

            while (true)
            {
                Console.WriteLine("[-] Select Name or PID of Target Process:");
                string input = Console.ReadLine().Trim();                              
                if (int.TryParse(input, out int pid))                               // Try search process by id
                {
                    try
                    {
                        TargetProcess = Process.GetProcessById(pid);
                        TargetName = TargetProcess.ProcessName;
                        return (TargetName, TargetProcess);
                        
                    }
                    catch { Console.WriteLine($"[!] Process with PID:{pid} not found"); Console.WriteLine(); }
                }
                else
                {
                    Process[] processes = Process.GetProcessesByName(input.ToLower());                      // Try search by name

                    if (processes.Length > 0)
                    {
                        for (int i = 0; i < processes.Length; i++)
                        {
                            try
                            {
                                Console.WriteLine($"  [{i}] PID: {processes[i].Id}, Session: {processes[i].SessionId}");
                            }
                            catch { Console.WriteLine($"Process with Name:{input} not found"); Console.WriteLine(); }
                        }
                        Console.WriteLine($"Select index of Process (0-{processes.Length - 1})");
                        if (int.TryParse(Console.ReadLine(), out int index) && index >= 0 && index < processes.Length)                 // Show all found process with assingned id
                        {
                            TargetProcess = processes[index];
                            TargetName = input;
                            return (TargetName, TargetProcess);
                        }
                        else { Console.WriteLine("[!] Error Process is not detection!"); Console.WriteLine(); }
                    }

                    else
                    {https://github.com/SaveKenny01/Dll-Injector/issues
                        if (input.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))                         // Try search whithout "exe" & ignore register
                        {
                            input = new string(input[..^4]);
                            processes = Process.GetProcessesByName(input);

                            if (processes.Length > 0)
                            {
                                for (int i = 0; i < processes.Length; i++)
                                {
                                    try
                                    {
                                        Console.WriteLine($"  [{i}] PID: {processes[i].Id}, Session: {processes[i].SessionId}");
                                    }
                                    catch { Console.WriteLine($"[!] Process Named:{input} was found, but program could not get its Id. Check is target process is running or use process Id"); Console.WriteLine(); }
                                }
                                Console.WriteLine($"[!] Enter index of Process ({0 - processes.Length - 1})");
                                if (int.TryParse(Console.ReadLine(), out int index) && index >= 0 && index < processes.Length)
                                {
                                    TargetProcess = processes[index];
                                    TargetName = input;
                                    return (TargetName, TargetProcess);
                                }
                                else { Console.WriteLine("[!] Error Process choice!"); Console.WriteLine(); }
                            }

                        }
                        else { Console.WriteLine($"[!] Process Named:{input} not found!"); Console.WriteLine(); }
                    }
                }
                continue;
                
            }
            

        }
        public static void RunningProcess()                                             // Show first 20 processes, just for example
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[========== First 20 processes ==========]");
            Console.ResetColor();
            Process[] processes = Process.GetProcesses();
            int count = 0;
            foreach(Process p in processes)
            {
                try
                {
                    if (count++ >= 20)
                    {
                        break;
                    }
                    else
                    {
                        string name = p.ProcessName;
                        int pid = p.Id;
                        string session = p.SessionId.ToString();

                        Console.WriteLine($"  [{pid}] {name,-20} Session:{session,-3}");
                    }
                }
                catch { Console.WriteLine("[!] Failed to get list of Process!"); }
            }
        }
        static bool Is64BitDll(string DLLPath)                              // Check architecture dll, if procces architecture is 32-bit - dll needed the same architecture
        {
            try
            {
                using (var fs = new FileStream(DLLPath, FileMode.Open, FileAccess.Read))
                using (var br = new BinaryReader(fs))
                {
                    fs.Seek(0x3C, SeekOrigin.Begin);                // Cheak PE headers
                    int peOffset = br.ReadInt32();

                    fs.Seek(peOffset + 4, SeekOrigin.Begin);        // Check machine in header
                    ushort machine = br.ReadUInt16();

                    switch (machine)
                    {
                        case 0x014C:                //32-bit
                            return false;
                        case 0x8664:                // 64-bit
                            return true;
                        case 0x01C4:                // 32-bit
                            return false;
                        case 0xAA64:                // 64-bit
                            return true;
                        default:                    // Default - 64-bit, more likely
                            return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error checking architecture: {ex.Message}!");
                return false;
            }
        }
        public static string DllInfo(string DLLPath)                // Full info about dll
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[========== Dll Info ==========]");
            Console.ResetColor();
            try
            {
                FileInfo dllInfo = new FileInfo(DLLPath);
                Console.WriteLine($"Path: {DLLPath}");
                Console.WriteLine($"Size: {dllInfo.Length} bytes");
                Console.WriteLine($"Last modification: {dllInfo.LastWriteTime}");
                bool isDll64Bit = Is64BitDll(DLLPath);
                Console.WriteLine($"Architecture: {(isDll64Bit ? "64-bit" : "32-bit")}");
                return (isDll64Bit ? "64-bit" : "32-bit");
            }
            catch{ Console.WriteLine("[!] Error dll information!"); return string.Empty; }
        }

        public static bool ProcessInfo(IntPtr HandleProcess, Process TargetProcess)        // Full info about target process
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[========== Target Process info ==========]");
            Console.ResetColor();
            bool IsProcessWow64 = false;
            Console.WriteLine($"Name: {TargetProcess.ProcessName}");
            Console.WriteLine($"Process Id: {TargetProcess.Id}");
            Console.WriteLine($"Session: {TargetProcess.SessionId}");
            Console.WriteLine($"Priority: {TargetProcess.BasePriority}");
            try
            {
                if (IsWow64Process(HandleProcess, out IsProcessWow64))
                {
                    Console.WriteLine($"Architecture:{(IsProcessWow64 ? "32-bit" : "64-bit")}");        // Check architecture current process 
                }
            }
            catch { Console.WriteLine("Architecture: ???"); }

            try
            {
                string Path = TargetProcess.MainModule?.ModuleName ?? "unavailable";                    // Try find path to main file
                Console.WriteLine($"File path: {Path}");
                return IsProcessWow64;
            }
            catch { return true; }

        }
        public static void Main(string[] args)
        {
            Console.Title = "Diagnostic DLL Injector";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                        DLL Injector                      ║");
            Console.WriteLine("║                        Version 1.0!                      ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
            Console.ResetColor();

            bool isAdministrator = IsAdmin();
            if (!isAdministrator)
            {
                Console.WriteLine("[!] The program is not running as administrator, some functions may work not correctly/not work. Please start as administrator!");
                Console.WriteLine();
            }
            string DLLPath;
            while (true)
            {
                Console.WriteLine("[-] Enter full Path dll:");
                DLLPath = Console.ReadLine()?.Trim('"', ' ');       // Save path without (' ') / (" ")
                if (DLLPath == null)
                {
                    Console.WriteLine("[!] Dll address cant be empty!");
                }
                if (!File.Exists(DLLPath) || string.IsNullOrEmpty(DLLPath))     // Check if dll path is available?
                {
                    Console.WriteLine("[!] Path not found!");
                    continue;
                }
                else { break; }
            }
            Console.WriteLine();

            DllInfo(DLLPath);                   
            Console.WriteLine();
            
            RunningProcess();
            (string TargetName, Process TargetProcess) = ChoiceProcess();
            Console.WriteLine();

            int CurrentProcess = TargetProcess.Id;

            IntPtr HandleProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, CurrentProcess);       // Open process with needed privileges -> hHandle process
            if (HandleProcess == IntPtr.Zero)
            {
                Console.WriteLine("[!] ERROR: OpenProcess!");
                return;
            }

            bool IsProcess32bit = ProcessInfo(HandleProcess, TargetProcess);   // Check process architecture(use function ProcessInfo) with handle
            Console.WriteLine();

            SysInfo(TargetName, DLLPath, IsProcess32bit);               // Show system info & check comatibility dll with process
            Console.WriteLine();

            while (true)
            {
                Console.WriteLine("The system is ready, inject dll? [ y ] [ n ]");
                string input = Console.ReadLine().ToLower();
                if (input == "y" || input == "yes")
                {
                    Console.WriteLine("[-] Starting inject...");
                    Console.WriteLine();
                    break;
                }
                else if(input == "n" || input == "no")
                {
                    return;
                }
                else { continue; }
            }


            //======================= INJECT ===========================
            //||                                                      ||
            //==========================================================
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[========== Inject ==========]");
            Console.ResetColor();
            byte[] dllPath = Encoding.Unicode.GetBytes(DLLPath + "\0");                 // Get bytes from dll path to write them into the process memory + 0 simbol

            try
            {
                (IntPtr remoteKernel32Base, uint remoteKernel32Size) = FindKernel32InProcess(CurrentProcess);
                Console.WriteLine();

                IntPtr localKernel32Base = GetModuleHandle("kernel32.dll");

                IntPtr localLoadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

                long offsetInsideKernel32 = localLoadLibraryAddr.ToInt64() - localKernel32Base.ToInt64();               

                Console.WriteLine("[-] Search location LoadLibraryW...");
                IntPtr remoteLoadLibraryW = new IntPtr(remoteKernel32Base.ToInt64() + offsetInsideKernel32);            // Search loadLibraryW. (local loadLibraryW address in kernel dll = remote loadLibraryW address in kernel32
                                                                                                                        // so remote loadLibraryW in process = remote kernel32 address + (loadLibraryW - kernel32Base)
                if (remoteLoadLibraryW == IntPtr.Zero)
                {
                    Console.WriteLine($"[!] Error, remoteLoadLibraryW = Zero!");                                        // I will use LoadLibraryW(Unicode) because automatic detection of the system may fail (as it happened with me), unicode more stable.
                    return;                                                                                             // If you want use ACII - use LoadLibraryA 
                }

                long kernel32EndAddr = remoteKernel32Base.ToInt64() + (long)remoteKernel32Size;
                if (remoteLoadLibraryW.ToInt64() >= kernel32EndAddr && remoteLoadLibraryW.ToInt64() < remoteKernel32Base.ToInt64())
                {
                    Console.WriteLine($"[!] Error: miss protection(remote address LoadLibrary is outside kernel32!");
                    return;
                }
                else { Console.WriteLine("[-] Successfully!"); }
                Console.WriteLine();


                Console.WriteLine("[-] Memory allocation...");
                IntPtr AllocMem = VirtualAllocEx(HandleProcess, IntPtr.Zero, (uint)dllPath.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);       // To allocate memory in target process, later we will write there dll path there so that LoadLibraryW can load the dll using this path
                if (AllocMem == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Error, AllocMem = Zero!");
                    return;
                }
                else { Console.WriteLine("[-] Successfully!"); }
                Console.WriteLine();


                UIntPtr bytesWritten;
                Console.WriteLine("[-] Writing Path to dll into the memory...");
                bool resultWrite = WriteProcessMemory(HandleProcess, AllocMem, dllPath, (uint)dllPath.Length, out bytesWritten);                    // Write the dll path into the allocated memory in the target process (now LoadLibrary can read this path)
                if (!resultWrite)                                                                                           
                {
                    Console.WriteLine("[!] Error in WriteProcessMemory");                                                                           // Check result after all operation
                    return;
                }
                else if (bytesWritten == UIntPtr.Zero)
                {
                    Console.WriteLine("[!] Error WriteProcessMemory, bytesWritten = 0");
                    return;
                }
                else { Console.WriteLine("[-] Successfully!"); }
                Console.WriteLine();

                Console.WriteLine("[-] Create remote thread...");
                IntPtr hRemoatThread = CreateRemoteThread(HandleProcess, IntPtr.Zero, 0, remoteLoadLibraryW, AllocMem, 0, IntPtr.Zero);             // To create a remoat thread in the process that will call LoadLibraryW with path (this will load dll)
                if (hRemoatThread == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Error in CreateRemoteThread");
                    return;
                }
                else { Console.WriteLine("[-] Successfully!"); }
                Console.WriteLine();

                //===================== TESTING RESULT =====================
                //||                                                      ||
                //==========================================================
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[==========Check result==========]");
                Console.ResetColor();
                uint waitResult = WaitForSingleObject(hRemoatThread, 10000);                    // check result from LoadLibraryW (0 = default)

                switch (waitResult)
                {
                    case 0x00000000: 
                        Console.WriteLine($"[-] Stream normaly ended!");
                        break;
                    case 0x00000102: 
                        Console.WriteLine($"[!] Wait timeout (10 seconds)!");
                        break;
                    case 0xFFFFFFFF: 
                        Console.WriteLine($"[!] Timeout error!");
                        break;
                    default:
                        Console.WriteLine($"[!] Unknown expaction result: 0x{waitResult:X}!");
                        break;
                }
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[==========Get result==========]");
                Console.ResetColor();
                bool exitCodeResult = GetExitCodeThread(hRemoatThread, out uint exitCode);              // Get exit code (exit code - base address of loaded dll, exit code 0 - error)
                                                                                                        // else - exit code - default
                if (exitCodeResult)
                {
                    Console.WriteLine($"[-] Return code LoadLibrary: 0x{exitCode:X}");

                    if (exitCode == 0)
                    {
                        Console.WriteLine($"[!] Error: LoadLibrary return NULL (DLL not loaded)!");

                        IntPtr getLastErrorAddr = GetProcAddress(localKernel32Base, "GetLastError");
                        if (getLastErrorAddr != IntPtr.Zero)
                        {
                            IntPtr hErrorThread = CreateRemoteThread(HandleProcess, IntPtr.Zero, 0, getLastErrorAddr, IntPtr.Zero, 0, IntPtr.Zero);
                                                                    

                            if (hErrorThread != IntPtr.Zero)                                    // Tring to catch last error 
                            {
                                WaitForSingleObject(hErrorThread, 2000);
                                GetExitCodeThread(hErrorThread, out uint lastError);
                                CloseHandle(hErrorThread);

                                Console.WriteLine($"[!] Error Cod in Target Process: {lastError}");
                            }
                        }
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
                        Console.WriteLine("║                  DLL was not loaded...                   ║");
                        Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
                        Console.ResetColor();
                        Console.WriteLine("Something broke... If you know how to fix it - write to me on GitHub:");
                        Console.WriteLine("https://github.com/SaveKenny01/Dll-Injector/issues");
                    }
                    else
                    {
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
                        Console.WriteLine("║                  DLL load successfully!                  ║");
                        Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
                        Console.ResetColor();
                    }
                    
                }
                else
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
                    Console.WriteLine("║                  DLL was not loaded...                   ║");
                    Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
                    Console.ResetColor();
                    Console.WriteLine("Something broke... If you know how to fix it - write to me on GitHub:");
                    Console.WriteLine("https://github.com/SaveKenny01/Dll-Injector/issues");
                }
                try
                {
                    VirtualFreeEx(HandleProcess, AllocMem, UIntPtr.Zero, MEM_RELEASE);                                  // free up memory
                }
                catch { Console.WriteLine("[!] Error: allocate memory is not freed"); }
                try
                {
                    CloseHandle(hRemoatThread);                                                                         // Close handle of remoat thread for LoadLibraryW
                }
                catch { Console.WriteLine("[!] Error: hRemoatThread was not closed!"); }

            }

            finally { if (HandleProcess != IntPtr.Zero && HandleProcess.ToInt64() != -1) { CloseHandle(HandleProcess); } }                          //Close handle of current process
            Console.ReadLine();
        }
    }
}
       
