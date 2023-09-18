rule MSBuild_Mimikatz_Execution_via_XML {
   meta:
      description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
      date = "2016-10-07"
   strings:
      $x1 = "<Project ToolsVersion=" ascii
      $x2 = "</SharpLauncher>" fullword ascii

      $s1 = "\"TVqQAAMAAAA" ascii
      $s2 = "System.Convert.FromBase64String(" ascii
      $s3 = ".Invoke(" ascii
      $s4 = "Assembly.Load(" ascii
      $s5 = ".CreateInstance(" ascii
   condition:
      all of them
}
rule Mimikatz_Gen_Strings {
   meta:
      description = "Detects Mimikatz by using some special strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-06-19"
      super_rule = 1
      hash1 = "058cc8b3e4e4055f3be460332a62eb4cbef41e3a7832aceb8119fd99fea771c4"
      hash2 = "eefd4c038afa0e80cf6521c69644e286df08c0883f94245902383f50feac0f85"
      hash3 = "f35b589c1cc1c98c4c4a5123fd217bdf0d987c00d2561992cbfb94bd75920159"
   strings:
      $s1 = "[*] '%s' service already started" fullword wide
      $s2 = "** Security Callback! **" fullword wide
      $s3 = "Try to export a software CA to a crypto (virtual)hardware" fullword wide
      $s4 = "enterpriseadmin" fullword wide
      $s5 = "Ask debug privilege" fullword wide
      $s6 = "Injected =)" fullword wide
      $s7 = "** SAM ACCOUNT **" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
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

rule Empire_lib_modules_credentials_mimikatz_pth {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"
	strings:
		$s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii 
		$s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii 
	condition:
		filesize < 12KB and all of them
}
rule Impacket_Tools_mimikatz {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "smimikatz" fullword ascii
      $s3 = "otwsdlc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
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
rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$s1 = "[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
		$s2 = "if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)" fullword ascii
		$s3 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)" fullword ascii
		$s4 = "Function Import-DllInRemoteProcess" fullword ascii
		$s5 = "FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))" fullword ascii
		$s6 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)" fullword ascii
		$s7 = "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)" fullword ascii
		$s8 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null" fullword ascii
		$s9 = "::FromBase64String('RABvAG4AZQAhAA==')))" ascii
		$s10 = "Write-Verbose \"PowerShell ProcessID: $PID\"" fullword ascii
		$s11 = "[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 3 of them ) or ( 6 of them )
}
rule BadRabbit_Mimikatz_Comp {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      /* Primary\x00m\x00s\x00v */
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them )
}
rule mimikatz_lsass_mdmp{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
   strings:
      $lsass         = "System32\\lsass.exe"   wide nocase
   condition:
      (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}
rule Mimikatz_Memory_Rule_1 : APT {
   meta:
      author = "Florian Roth"
      date = "2014-12-22"
      modified = "2023-02-10"
      score = 70
      nodeepdive = 1
      description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
   strings:
      $s1 = "sekurlsa::wdigest" fullword ascii
      $s2 = "sekurlsa::logonPasswords" fullword ascii
      $s3 = "sekurlsa::minidump" fullword ascii
      $s4 = "sekurlsa::credman" fullword ascii

      $fp1 = "\"x_mitre_version\": " ascii
      $fp2 = "{\"type\":\"bundle\","
      $fp3 = "use strict" ascii fullword
   condition:
      1 of ($s*) and not 1 of ($fp*)
}

rule Mimikatz_Memory_Rule_2 : APT {
   meta:
      description = "Mimikatz Rule generated from a memory dump"
      author = "Florian Roth (Nextron Systems) - Florian Roth"
      score = 80
   strings:
      $s0 = "sekurlsa::" ascii
      $x1 = "cryptprimitives.pdb" ascii
      $x2 = "Now is t1O" ascii fullword
      $x4 = "ALICE123" ascii
      $x5 = "BOBBY456" ascii
   condition:
      $s0 and 1 of ($x*)
}

rule mimikatz : FILE {
   meta:
      description      = "mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
      tool_author      = "Benjamin DELPY (gentilkiwi)"
      modified = "2022-11-16"
   strings:
      $exe_x86_1      = { 89 71 04 89 [0-3] 30 8d 04 bd }
      $exe_x86_2      = { 8b 4d e? 8b 45 f4 89 75 e? 89 01 85 ff 74 }

      $exe_x64_1      = { 33 ff 4? 89 37 4? 8b f3 45 85 c? 74}
      $exe_x64_2      = { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

/*
      $dll_1         = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
      $dll_2         = { c7 0? 10 02 00 00 ?? 89 4? }
*/

      $sys_x86      = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
      $sys_x64      = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

   condition:
      (all of ($exe_x86_*)) or (all of ($exe_x64_*))
      // or (all of ($dll_*))
      or (any of ($sys_*))
}
rule Mimikatz_Logfile
{
   meta:
      description = "Detects a log file generated by malicious hack tool mimikatz"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 80
      date = "2015/03/31"
   strings:
      $s1 = "SID               :" ascii fullword
      $s2 = "* NTLM     :" ascii fullword
      $s3 = "Authentication Id :" ascii fullword
      $s4 = "wdigest :" ascii fullword
   condition:
      all of them
}

rule Mimikatz_Strings {
   meta:
      description = "Detects Mimikatz strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2016-06-08"
      score = 65
   strings:
      $x1 = "sekurlsa::logonpasswords" fullword wide ascii
      $x2 = "List tickets in MIT/Heimdall ccache" fullword ascii wide
      $x3 = "kuhl_m_kerberos_ptt_file ; LsaCallKerberosPackage %08x" fullword ascii wide
      $x4 = "* Injecting ticket :" fullword wide ascii
      $x5 = "mimidrv.sys" fullword wide ascii
      $x6 = "Lists LM & NTLM credentials" fullword wide ascii
      $x7 = "\\_ kerberos -" wide ascii
      $x8 = "* unknow   :" fullword wide ascii
      $x9 = "\\_ *Password replace ->" wide ascii
      $x10 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS KO" ascii wide
      $x11 = "\\\\.\\mimidrv" wide ascii
      $x12 = "Switch to MINIDUMP :" fullword wide ascii
      $x13 = "[masterkey] with password: %s (%s user)" fullword wide
      $x14 = "Clear screen (doesn't work with redirections, like PsExec)" fullword wide
      $x15 = "** Session key is NULL! It means allowtgtsessionkey is not set to 1 **" fullword wide
      $x16 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " fullword wide
   condition:
      (
         ( uint16(0) == 0x5a4d and 1 of ($x*) ) or
         ( 3 of them )
      )
      /* exclude false positives */
      and not pe.imphash() == "77eaeca738dd89410a432c6bd6459907"
}
rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1 {
   meta:
      description = "Detects Mimikatz SkeletonKey in Memory"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
      date = "2020-08-09"
   strings:
      $x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }
   condition:
      1 of them
}

rule HKTL_mimikatz_memssp_hookfn {
   meta:
      description = "Detects Default Mimikatz memssp module in-memory"
      author = "SBousseaden"
      date = "2020-08-26"
      reference = "https://github.com/sbousseaden/YaraHunts/blob/master/mimikatz_memssp_hookfn.yara"
      score = 70
   strings: 
      $xc1 = { 48 81 EC A8 00 00 00 C7 84 24 88 00 00 00 ?? ?? 
               ?? ?? C7 84 24 8C 00 00 00 ?? ?? ?? ?? C7 84 24 
               90 00 00 00 ?? ?? ?? 00 C7 84 24 80 00 00 00 61 
               00 00 00 C7 44 24 40 5B 00 25 00 C7 44 24 44 30 
               00 38 00 C7 44 24 48 78 00 3A 00 C7 44 24 4C 25 
               00 30 00 C7 44 24 50 38 00 78 00 C7 44 24 54 5D 
               00 20 00 C7 44 24 58 25 00 77 00 C7 44 24 5C 5A 
               00 5C 00 C7 44 24 60 25 00 77 00 C7 44 24 64 5A 
               00 09 00 C7 44 24 68 25 00 77 00 C7 44 24 6C 5A 
               00 0A 00 C7 44 24 70 00 00 00 00 48 8D 94 24 80 
               00 00 00 48 8D 8C 24 88 00 00 00 48 B8 A0 7D ?? 
               ?? ?? ?? 00 00 FF D0 } // memssp creds logging function
      // $xc2 = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67} -  mimilsa.log
   condition: 
      $xc1 // you can set condition to $xc1 and not $xc2 to detect non lazy memssp users 
}

rule HKTL_mimikatz_icon {
    meta:
        description = "Detects mimikatz icon in PE file"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        reference = "https://blog.gentilkiwi.com/mimikatz"
        date = "2023-02-18"
        score = 60
        hash1 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"
        hash2 = "1c3f584164ef595a37837701739a11e17e46f9982fdcee020cf5e23bad1a0925"
        hash3 = "c6bb98b24206228a54493274ff9757ce7e0cbb4ab2968af978811cc4a98fde85"
        hash4 = "721d3476cdc655305902d682651fffbe72e54a97cd7e91f44d1a47606bae47ab"
        hash5 = "c0f3523151fa307248b2c64bdaac5f167b19be6fccff9eba92ac363f6d5d2595"
    strings:
        $ico = {79 e1 d7 ff 7e e5 db ff 7f e8 dc ff 85 eb dd ff ba ff f1 ff 66 a0 b6 ff 01 38 61 ff 22 50 75 c3}
    condition:
        uint16(0) == 0x5A4D and
        $ico and
        filesize < 10MB
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
rule OPCLEAVER_mimikatzWrapper
{
	meta:
		description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
	strings:
		$s1 = "mimikatzWrapper"
		$s2 = "get_mimikatz"
	condition:
		all of them
}
rule OPCLEAVER_zhmimikatz
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
	strings:
		$s1 = "MimikatzRunner"
		$s2 = "zhmimikatz"
	condition:
		all of them
}
rule mimikatz_kirbi_ticket
{
    meta:
        description        = "KiRBi ticket for mimikatz"
        author            = "Benjamin DELPY (gentilkiwi); Didier Stevens"

    strings:
        $asn1            = { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
        $asn1_84        = { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

    condition:
        $asn1 at 0 or $asn1_84 at 0
}
rule Chafer_Mimikatz_Custom  {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth (Nextron Systems) / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}
rule Chafer_Packed_Mimikatz {
   meta:
      description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
      author = "Florian Roth (Nextron Systems) / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
   strings:
      $s1 = "Windows Security Credentials" fullword wide
      $s2 = "Minisoft" fullword wide
      $x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( all of ($s*) or $x1 )
}
rule HvS_APT37_mimikatz_loader_DF012 {
   meta:
      description = "Loader for encrypted Mimikatz variant used by APT37"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "42e4a9aeff3744bbbc0e82fd5b93eb9b078460d8f40e0b61b27b699882f521be"
   strings:
      $s1 = ".?AVCEncryption@@" fullword ascii
      $s2 = "afrfa"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 
      (pe.imphash() == "fa0b87c7e07d21001355caf7b5027219") and (all of them)
}
rule mimikatz_sekurlsa {
    strings:
        $s1 = { 33 DB 8B C3 48 83 C4 20 5B C3 }
        $s2 = {83 64 24 30 00 44 8B 4C 24 48 48 8B 0D}
        $s3 = {83 64 24 30 00 44 8B 4D D8 48 8B 0D}
        $s4 = {84 C0 74 44 6A 08 68}
        $s5 = {8B F0 3B F3 7C 2C 6A 02 6A 10 68}
        $s6 = {8B F0 85 F6 78 2A 6A 02 6A 10 68}

    condition:
        all of them
}

rule mimikatz_decryptkeysign {
    strings:
        $s1 = { F6 C2 07 0F 85 0D 1A 02 00 }
        $s2 = { F6 C2 07 0F 85 72 EA 01 00 }
        $s3 = { 4C 8B CB 48 89 44 24 30}
        $s4 = { 4c 89 1b 48 89 43 08 49 89 5b 08 48 8d }

    condition:
        3 of them
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
rule HvS_APT37_mimikatz_loader_DF012 {
   meta:
      description = "Loader for encrypted Mimikatz variant used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "42e4a9aeff3744bbbc0e82fd5b93eb9b078460d8f40e0b61b27b699882f521be"
   strings:
      $s1 = ".?AVCEncryption@@" fullword ascii
      $s2 = "afrfa"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 
      (pe.imphash() == "fa0b87c7e07d21001355caf7b5027219") and (all of them)
}
rule mimikatz_utility_softcell {

   meta:

      description = "Rule to detect Mimikatz utility used in the SoftCell operation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-06-25"
      rule_version = "v1"
      malware_type = "hacktool"
      malware_family = "Hacktool:W32/Mimikatz"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"

   strings:

      $s1 = "livessp.dll" fullword wide 
      $s2 = "\\system32\\tapi32.dll" fullword wide
      $s3 = " * Process Token : " fullword wide
      $s4 = "lsadump" fullword wide
      $s5 = "-nl - skip lsa dump..." fullword wide
      $s6 = "lsadump::sam" fullword wide
      $s7 = "lsadump::lsa" fullword wide
      $s8 = "* NL$IterCount %u, %u real iter(s)" fullword wide
      $s9 = "* Iter to def (%d)" fullword wide
      $s10 = " * Thread Token  : " fullword wide
      $s11 = " * RootKey  : " fullword wide
      $s12 = "lsadump::cache" fullword wide
      $s13 = "sekurlsa::logonpasswords" fullword wide
      $s14 = "(commandline) # %s" fullword wide
      $s15 = ">>> %s of '%s' module failed : %08x" fullword wide
      $s16 = "UndefinedLogonType" fullword wide
      $s17 = " * Username : %wZ" fullword wide
      $s18 = "logonPasswords" fullword wide
      $s19 = "privilege::debug" fullword wide
      $s20 = "token::elevate" fullword wide

      $op0 = { e8 0b f5 00 00 90 39 35 30 c7 02 00 75 34 48 8b }
      $op1 = { eb 34 48 8b 4d cf 48 8d 45 c7 45 33 c9 48 89 44 }
      $op2 = { 48 3b 0d 34 26 01 00 74 05 e8 a9 31 ff ff 48 8b }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( pe.imphash() == "169e02f00c6fb64587297444b6c41ff4" and
      all of them )
}