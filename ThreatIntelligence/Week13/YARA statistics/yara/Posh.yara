rule Windows_API_Function
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects the presence of a number of Windows API functionality often seen within embedded executables. When this signature alerts on an executable, it is not an indication of malicious behavior. However, if seen firing in other file types, deeper investigation may be warranted."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://en.wikipedia.org/wiki/Windows_API"
        labs_reference = "https://labs.inquest.net/dfi/hash/f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"
        labs_pivot     = "N/A"
        samples        = "f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"

	strings:
			$magic  = "INQUEST-PII="
	$api_00 = "LoadLibraryA" nocase ascii wide
    $api_01 = "ShellExecuteA" nocase ascii wide
    $api_03 = "GetProcAddress" nocase ascii wide
    $api_04 = "GetVersionExA" nocase ascii wide
    $api_05 = "GetModuleHandleA" nocase ascii wide
    $api_06 = "OpenProcess" nocase ascii wide
    $api_07 = "GetWindowsDirectoryA" nocase ascii wide
    $api_08 = "lstrcatA" nocase ascii wide
    $api_09 = "GetSystemDirectoryA" nocase ascii wide
    $api_10 = "WriteFile" nocase ascii wide
    $api_11 = "ReadFile" nocase ascii wide
    $api_12 = "GetFileSize" nocase ascii wide
    $api_13 = "CreateFileA" nocase ascii wide
    $api_14 = "DeleteFileA" nocase ascii wide
    $api_15 = "CreateProcessA" nocase ascii wide
    $api_16 = "GetCurrentProcessId" nocase ascii wide
    $api_17 = "RegOpenKeyExA" nocase ascii wide
    $api_18 = "GetStartupInfoA" nocase ascii wide
    $api_19 = "CreateServiceA" nocase ascii wide
    $api_20 = "CopyFileA" nocase ascii wide
    $api_21 = "GetModuleFileNameA" nocase ascii wide
    $api_22 = "IsBadReadPtr" nocase ascii wide
    $api_23 = "CreateFileW" nocase ascii wide
    $api_24 = "SetFilePointer" nocase ascii wide
    $api_25 = "VirtualAlloc" nocase ascii wide
    $api_26 = "AdjustTokenPrivileges" nocase ascii wide
    $api_27 = "CloseHandle" nocase ascii wide
    $api_28 = "CreateFile" nocase ascii wide
    $api_29 = "GetProcAddr" nocase ascii wide
    $api_30 = "GetSystemDirectory" nocase ascii wide
    $api_31 = "GetTempPath" nocase ascii wide
    $api_32 = "GetWindowsDirectory" nocase ascii wide
    $api_33 = "IsBadReadPtr" nocase ascii wide
    $api_34 = "IsBadWritePtr" nocase ascii wide
    $api_35 = "LoadLibrary" nocase ascii wide
    $api_36 = "ReadFile" nocase ascii wide
    $api_37 = "SetFilePointer" nocase ascii wide
    $api_38 = "ShellExecute" nocase ascii wide
    $api_39 = "UrlDownloadToFile" nocase ascii wide
    $api_40 = "WinExec" nocase ascii wide
    $api_41 = "WriteFile" nocase ascii wide
    $api_42 = "StartServiceA" nocase ascii wide
    $api_43 = "VirtualProtect" nocase ascii wide
	condition:
			any of ($api*)
    and not $magic in (filesize-30..filesize)
    and not 
    (
        /* trigger = 'MZ' */
        (uint16be(0x0) == 0x4d5a)
        or
        /* trigger = 'ZM' */
        (uint16be(0x0) == 0x5a4d)
        or
        /* trigger = 'PE' */
        (uint16be(uint32(0x3c)) == 0x5045)
    )
}

rule Base64_Encoded_URL
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature fires on the presence of Base64 encoded URI prefixes (http:// and https://) across any file. The simple presence of such strings is not inherently an indicator of malicious content, but is worth further investigation."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs R&D"
        labs_reference = "https://labs.inquest.net/dfi/sha256/114366bb4ef0f3414fb1309038bc645a7ab2ba006ef7dc2abffc541fcc0bb687"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Base64%20Encoded%20URL"
        samples        = "114366bb4ef0f3414fb1309038bc645a7ab2ba006ef7dc2abffc541fcc0bb687"

	strings:
			$httpn  = /(aHR\x30cDovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwOi\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHA\x36Ly[\x2b\x2f\x38-\x39])/
	$httpw  = /(aAB\x30AHQAcAA\x36AC\x38AL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAOgAvAC[\x2b\x2f\x38-\x39])/
	$httpsn = /(aHR\x30cHM\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwczovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHBzOi\x38v[\x2b\x2f-\x39A-Za-z])/
    $httpsw = /(aAB\x30AHQAcABzADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwAHMAOgAvAC[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAcwA\x36AC\x38AL[\x2b\x2f-\x39w-z])/
	condition:
			any of them and not (uint16be(0x0) == 0x4d5a)
}

rule Empire_PowerShell_Framework_Gen4 {
   meta:
      description = "Detects Empire component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "743c51334f17751cfd881be84b56f648edbdaf31f8186de88d094892edc644a9"
      hash2 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash4 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
      hash6 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash7 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
      hash8 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash9 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
      hash10 = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
   strings:
      $s1 = "Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii
      $s2 = "# Get a handle to the module specified" fullword ascii
      $s3 = "$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))" fullword ascii
      $s4 = "$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Get_Keystrokes {
   meta:
      description = "Detects Empire component - file Get-Keystrokes.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
   strings:
      $s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - file Invoke-Mimikatz.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
      $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen1 {
   meta:
      description = "Detects Empire component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash3 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash4 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash5 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "Write-BytesToMemory -Bytes $Shellcode" ascii
      $s2 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen2 {
   meta:
      description = "Detects Empire component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash6 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash8 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $x1 = "$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)" fullword ascii
      $s20 = "#Shellcode: CallDllMain.asm" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen3 {
   meta:
      description = "Detects Empire component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash3 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash4 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "if (($PEInfo.FileType -ieq \"DLL\") -and ($RemoteProcHandle -eq [IntPtr]::Zero))" fullword ascii
      $s2 = "remote DLL injection" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_CredentialInjection_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle" fullword ascii
      $s2 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-DCSync.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "$Shellcode1 += 0x48" fullword ascii
      $s2 = "$PEHandle = [IntPtr]::Zero" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 3000KB and 1 of them ) or all of them
}

rule HKTL_NET_GUID_PoshC2_Misc {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/PoshC2_Misc"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
        $typelibguid0up = "85773EB7-B159-45FE-96CD-11BAD51DA6DE" ascii wide
        $typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
        $typelibguid1up = "9D32AD59-4093-420D-B45C-5FFF391E990D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule Hacktool_Strings_p0wnedShell : FILE {
   meta:
      description = "Detects strings found in Runspace Post Exploitation Toolkit"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      modified = "2023-02-10"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
      nodeepdive = 1
   strings:
      $x1 = "Invoke-TokenManipulation" fullword ascii
      $x2 = "windows/meterpreter" fullword ascii
      $x3 = "lsadump::dcsync" fullword ascii
      $x4 = "p0wnedShellx86" fullword ascii
      $x5 = "p0wnedShellx64" fullword ascii
      $x6 = "Invoke_PsExec()" fullword ascii
      $x7 = "Invoke-Mimikatz" fullword ascii
      $x8 = "Invoke_Shellcode()" fullword ascii
      $x9 = "Invoke-ReflectivePEInjection" ascii

      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Copyright Elasticsearch B.V." ascii wide
      $fp3 = "Attack Information: Invoke-Mimikatz" ascii /* Check Point help files */
      $fp4 = "a30226 || INDICATOR-SHELLCODE Metasploit windows/meterpreter stage transfer attempt" /* snort message ID */
      $fp5 = "use strict"
   condition:
      filesize < 20MB
      and 1 of ($x*)
      and not 1 of ($fp*)
}

rule Invoke_Mimikatz {
	meta:
		description = "Detects Invoke-Mimikatz String"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		date = "2016-08-03"
		hash1 = "f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67"
	strings:
		$x2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii
      $x3 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii
	condition:
      1 of them
}

rule power_pe_injection
{
   meta:
      description      = "PowerShell with PE Reflective Injection"
      author         = "Benjamin DELPY (gentilkiwi)"
   strings:
      $str_loadlib   = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
   condition:
      $str_loadlib
}

rule Empire_Invoke_Mimikatz {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"
	strings:
		$s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii 
		$s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii 
		$s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii 
	condition:
		filesize < 2500KB and 2 of them
}


rule SUSP_PowerShell_String_K32_RemProcess {
   meta:
      description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/nccgroup/redsnarf"
      date = "2018-03-31"
      hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
      hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
   strings:
      $x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
      $x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
      $s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
      $s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
      $s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
      $s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
      $s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 6000KB and 1 of them
}

rule ps1_toolkit_Invoke_Mimikatz {
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
		$s3 = "privilege::debug exit" ascii
		$s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
		$s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
		$s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}

rule Suspicious_PowerShell_WebDownload_1 : HIGHVOL FILE {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      modified = "2022-07-27"
      nodeepdive = 1
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
      $s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
      $s3 = "system.net.webclient).downloadfile('http" ascii nocase
      $s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
      $s5 = "GetString([Convert]::FromBase64String(" ascii nocase

      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
      $fp3 = " GET /"
      $fp4 = " POST /"
      $fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
      $fp6 = " 404 " /* in web server logs */
      $fp7 = "# RemoteSSHConfigurationScript" ascii /* \.vscode\extensions\ms-vscode-remote.remote-ssh */
      $fp8 = "<helpItems" ascii fullword
      $fp9 = "DownloadFile(\"https://codecov.io/bash" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}

rule Windows_Hacktool_Mimikatz_355d5d3a {
    meta:
        author = "Elastic Security"
        id = "355d5d3a-e50e-4614-9a84-0da668c40852"
        fingerprint = "9a23845ec9852d2490171af111612dc257a6b21ad7fdfd8bf22d343dc301d135"
        creation_date = "2021-04-14"
        last_modified = "2021-08-23"
        description = "Detection for Invoke-Mimikatz"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "945245ca795e0a3575ee4fdc174df9d377a598476c2bf4bf0cdb0cde4286af96"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "$PEBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $a2 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $b1 = "Write-BytesToMemory -Bytes $Shellcode"
        $b2 = "-MemoryAddress $GetCommandLineWAddrTemp"
        $b3 = "-MemoryAddress $GetCommandLineAAddrTemp"
        $c1 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword
        $c2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam"
        $c3 = "at: http://blog.gentilkiwi.com"
        $c4 = "on the local computer to dump certificates."
        $c5 = "Throw \"Unable to write shellcode to remote process memory.\"" fullword
        $c6 = "-Command \"privilege::debug exit\" -ComputerName \"computer1\""
        $c7 = "dump credentials without"
        $c8 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword
        $c9 = "two remote computers to dump credentials."
        $c10 = "#If a remote process to inject in to is specified, get a handle to it" fullword
    condition:
        (1 of ($a*) or 2 of ($b*)) or 5 of ($c*)
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}