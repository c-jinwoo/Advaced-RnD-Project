rule CS_encrypted_beacon_x86 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc e8 ?? 00 00 00 }
        $s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }
    condition:
        $s1 at 0 and $s2 in (0..200) and filesize < 300000
}

rule CS_encrypted_beacon_x86_64 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }
    condition:
        $s1 at 0 and filesize < 300000
}

rule CS_beacon {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s2 = "%s as %s\\%s: %d" ascii
        $s3 = "Started service %s on %s" ascii
        $s4 = "beacon.dll" ascii
        $s5 = "beacon.x64.dll" ascii
        $s6 = "ReflectiveLoader" ascii
        $s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
        $s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
        $s9 = "%s (admin)" ascii
        $s10 = "Updater.dll" ascii
        $s11 = "LibTomMath" ascii
        $s12 = "Content-Type: application/octet-stream" ascii
    condition:
        6 of them and filesize < 300000
}

rule CobaltStrike_sleepmask {
	meta:
		description = "Static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
		author = "CodeX"
		date = "2022-07-04"
	strings:
		$sleep_mask = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
	condition:
		$sleep_mask
}

rule artifact_beacon {
   meta:
      description = "from files artifact.exe, beacon.exe"
      date = "2021-04-09"
   strings:
      $s = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
   condition:
      $s
}

rule CobaltStrike_Malleable_C2_GIF : CobaltStrike GIF
{
	meta:
		description = "Detects the Cobalt Strike Malleable C2 fake GIF"
		author = "@nric0"
		reference = "https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/webbug_getonly.profile" 
		version = "2"
		date = "2019-06-30"

	strings:
		$gifmagic = { 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 FF FF FF 21 F9 04 01 00 00 00 2C 00 00 00 00 01 00 01 00 00 02 01 44 00 3B }
	condition:
		filesize > 10KB and $gifmagic at 0
}

rule CobaltStrike_beaconEye { 
  strings:  
    $cobaltStrikeRule64 = {  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 (00|01|02|04|08|10) 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 } 
    $cobaltStrikeRule32 = {  00 00 00 00 00 00 00 00  01 00 00 00 (00|01|02|04|08|10) 00 00 00 01 00 00 00 ?? ?? 00 00  02 00 00 00 ?? ?? ?? ??  02 00 00 00 ?? ?? ?? ??  01 00 00 00 ?? ?? 00 00 }
  condition: any of them
}

rule cobaltstrike_beacon_4_2_sleepMask8
{
meta:
    author = "Elastic"
    description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2."
strings:
    $a_x64 = {89 C2 45 09 C2 74 1F 41 39 C0 76 E9 4C 8B 13 49 89 C3 41 83 E3 07 49 01 C2 46 8A 5C 1B 10 48 FF C0 45 30 1A}
    $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
condition:
     any of them
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-09
   Identifier: MSF Payloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      modified = "2022-08-18"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
   strings:
      $s1 = "export buf=\\" ascii
   condition:
      filesize < 5MB and $s1
}

rule Msfpayloads_msf_2 {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_psh {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_exe {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_exe_2 {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_6 {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7  = ") Step 2" ascii
   condition:
      5 of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_cmd {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or (
         uint32(0) == 0x61356434 and $x1 at 0
      )
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 {
   meta:
      description = "Metasploit Payloads - file msf.hta"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
   strings:
      $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_ref {
   meta:
      description = "Metasploit Payloads - file msf-ref.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
   strings:
      $s1 = "kernel32.dll WaitForSingleObject)," ascii
      $s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
      $s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
      $s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
      $s5 = "= [System.Convert]::FromBase64String(" ascii
      $s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
      $s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii
   condition:
      5 of them
}

rule MAL_Metasploit_Framework_UA {
   meta:
      description = "Detects User Agent used in Metasploit Framework"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
      date = "2018-08-16"
      score = 65
      hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
   strings:
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule HKTL_Meterpreter_inMemory {
   meta:
      description = "Detects Meterpreter in-memory"
      author = "netbiosX, Florian Roth"
      reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
      date = "2020-06-29"
      modified = "2023-04-21"
      score = 85
   strings: 
      $sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
      $sxs1 = "metsrv.x64.dll" ascii fullword
      $ss1 = "WS2_32.dll" ascii fullword
      $ss2 = "ReflectiveLoader" ascii fullword

      $fp1 = "SentinelOne" ascii wide
      $fp2 = "fortiESNAC" ascii wide
      $fp3 = "PSNMVHookMS" ascii wide
   condition: 
      ( 1 of ($sx*) or 2 of ($s*) )
      and not 1 of ($fp*)
}
import "pe"

/* 
 * Description: Ruleset for detecting Deimos C2 Windows agents
 * Author: Fernando Mercês @ Trend Micro FTR
 * 
 * Last updated: 2022-08-05
*/

global private rule deimos_pe {
    condition:
        pe.number_of_sections == 5
        and pe.sections[4].name == ".symtab"
        and filesize >= 6400000 and filesize <= 7700000
}

// 64-bit files

rule deimosc2_agent_win64_https {
    meta:
        description = "Non-obfuscated PE32+ Deimos C2 Agents using HTTPS via http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {65488B0C2528000000488B8900000000488D4424C0483B41100F86D40000004881ECC00000004889AC24B8000000488DAC24B8000000488D7C24580F57C0488D7FE048896C24F0488D6C24F0}
        $http_Post = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        #deimos > 10
        and all of them
}

rule deimosc2_agent_win64_tcp {
    meta:
        description = "Non-obfuscated PE32+ Deimos C2 Agents using TCP via net.Dial() should not have http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {65488B0C2528000000488B8900000000488D4424C0483B41100F86D40000004881ECC00000004889AC24B8000000488DAC24B8000000488D7C24580F57C0488D7FE048896C24F0488D6C24F0}
        $http_Post = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        #deimos > 10
        and $net_Dial
        and not $http_Post
}

private rule deimosc2_agent_win64_colon_decrypt_obfuscated {
    meta:
        description = "Detects gobfuscate XOR decryption 64-bit routine for a single colon character"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $colon = {
            65 48 8B 0C 25 28 00 00 00    // mov     rcx, gs:28h
            48 8B 89 00 00 00 00          // mov     rcx, [rcx+0]
            48 3B 61 10                   // cmp     rsp, [rcx+10h]
            0F 86 81 00 00 00             // jbe     loc_760B5B            
            48 83 EC 40                   // sub     rsp, 40h
            48 89 6C 24 38                // mov     [rsp+40h+var_9+1], rbp
            48 8D 6C 24 38                // lea     rbp, [rsp+40h+var_9+1]
            C6 44 24 36 ??                // mov     [rsp+40h+var_A], 0Bh
            C6 44 24 35 ??                // mov     [rsp+40h+var_B], 31h ; '1'
            C6 44 24 37 00                // mov     byte ptr [rsp+40h+var_9], 0
            31 C0                         // xor     eax, eax
            EB 13
        }
    condition:
        pe.is_64bit()
        and for 1 i in (1..#colon) : (
                uint8(@colon[i] + 44) ^ uint8(@colon[i] + 49) == 0x3a // ':'
            )
}

rule deimosc2_agent_win64_https_obfuscated {
    meta:
        description = "Detects the code piece that checks for a 200 OK return from http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-07-26"
    
    strings:
        $http_ok_check = {
            48 8B 48 40                   // mov     rcx, [rax+40h]
            84 01                         // test    [rcx], al
            48 83 C1 18                   // add     rcx, 18h
            48 8B 58 48                   // mov     rbx, [rax+48h]
            48 89 8C 24 60 01 00 00       // mov     qword ptr [rsp+170h+var_18+8], rcx
            48 89 9C 24 58 01 00 00       // mov     qword ptr [rsp+170h+var_18], rbx
            C6 44 24 6F 01                // mov     [rsp+170h+var_101], 1
            48 81 78 10 C8 00 00 00       // cmp     qword ptr [rax+10h], 0C8h
            0F 85 43 01 00 00
        }

    condition:
        deimosc2_agent_win64_colon_decrypt_obfuscated
        and all of them
}

rule deimosc2_agent_win64_tcp_obfuscated {
    meta:
        description = "Detects the net.Dial() code"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $net_dial = {
            48 8B 44 24 40                // mov     rax, [rsp+0C8h+var_90.len]
            48 8B 4C 24 38                // mov     rcx, [rsp+0C8h+var_90.ptr]
            48 8B 94 24 B0 00 00 00       // mov     rdx, [rsp+0C8h+var_18.ptr]
            48 89 14 24                   // mov     [rsp+0C8h+var_C8.ptr], rdx ; string
            48 8B 54 24 78                // mov     rdx, [rsp+0C8h+var_50]
            48 89 54 24 08                // mov     [rsp+0C8h+var_C8.len], rdx
            48 89 4C 24 10                // mov     [rsp+0C8h+var_B8.ptr], rcx ; string
            48 89 44 24 18                // mov     [rsp+0C8h+var_B8.len], rax
            E8 93 92 DF FF           
        }
        $http_Post  = {65488B0C2528000000488B8900000000488D4424F8483B41100F86FE0100004881EC880000004889AC2480000000488DAC2480000000488B053B884A00488D0D7C24220048890C244889442408488D057BCF1800488944241048C744241804000000488B8424980000004889442420488B8424A00000004889442428488B8424B80000004889442430488B8424C00000004889442438}

    condition:
        deimosc2_agent_win64_colon_decrypt_obfuscated
        and all of them
        and not $http_Post
}

// 32-bit files

rule deimosc2_agent_win32_https {
    meta:
        description = "Non-obfuscated PE32 Deimos C2 Agents using HTTPS via http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {E8??0000008B4C24248B5424208B5C241C8B6C2428899C248400000089942488000000898C248C00000089AC249000000083C470C3}
        $http_Post = {
            E8 ?? ?? ?? 00               //                 call    net_http_NewRequestWithContext
            8B 44 24 20                  //                 mov     eax, [esp+40h+var_20]
            8B 4C 24 24                  //                 mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                  //                 mov     edx, [esp+40h+var_18]
            85 C9                        //                 test    ecx, ecx
            0F 85 F4 00 00 00            //                 jnz     loc_6203AB
            89 44 24 30                  //                 mov     [esp+40h+var_10], eax
            8B 48 1C                     //                 mov     ecx, [eax+1Ch]
            89 4C 24 3C                  //                 mov     [esp+40h+var_4], ecx
            90                           //                 nop
            8D 15 ?? ?? ?? 00            //                 lea     edx, aContentType ; "Content-Type"
            89 14 24                     //                 mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00      //                 mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF               //                 call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        #deimos > 10
        and all of them
}

rule deimosc2_agent_win32_tcp {
    meta:
        description = "Non-obfuscated PE32 Deimos C2 Agents using TCP via net.Dial()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $deimos = "github.com/DeimosC2/DeimosC2/agents/resources"
        $net_Dial = {E8??0000008B4C24248B5424208B5C241C8B6C2428899C248400000089942488000000898C248C00000089AC249000000083C470C3}
        $http_Post = {E86AEBFFFF8B4424108B4C240C8B54240889542460894C24648944246883C440C3}

    condition:
        #deimos > 10
        and $net_Dial
        and not $http_Post
}

private rule deimosc2_agent_win32_colon_decrypt_obfuscated {
    meta:
        description = "Detects gobfuscate XOR decryption 32-bit routine for a single colon character"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $colon = {
            64 8B 0D 14 00 00 00        // mov     ecx, large fs:14h
            8B 89 00 00 00 00           // mov     ecx, [ecx+0]
            3B 61 08                    // cmp     esp, [ecx+8]
            76 73                       // jbe     short loc_6D5D15
            83 EC 1C                    // sub     esp, 1Ch
            C6 44 24 1A ??              // mov     [esp+1Ch+var_2], 62h ; 'b'
            C6 44 24 19 ??              // mov     [esp+1Ch+var_3], 58h ; 'X'
            C6 44 24 1B 00              // mov     [esp+1Ch+var_1], 0
            31 C0                       // xor     eax, eax
            EB 0C                       // jmp     short loc_6D5CC4
        }
    condition:
        pe.is_32bit()
        and for 1 i in (1..#colon) : (
                uint8(@colon[i] + 25) ^ uint8(@colon[i] + 30) == 0x3a // ':'
            )
}

rule deimosc2_agent_win32_https_obfuscated {
    meta:
        description = "Detects HTTPS samples by the presence of http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $http_Post = {
            E8 ?? ?? ?? 00                 // call    net_http_NewRequestWithContext
            8B 44 24 20                    // mov     eax, [esp+40h+var_20]
            8B 4C 24 24                    // mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                    // mov     edx, [esp+40h+var_18]
            85 C9                          // test    ecx, ecx
            0F 85 F4 00 00 00              // jnz     loc_6203AB
            89 44 24 30                    // mov     [esp+40h+var_10], eax
            8B 48 1C                       // mov     ecx, [eax+1Ch]
            89 4C 24 3C                    // mov     [esp+40h+var_4], ecx
            90                             // nop
            8D 15 ?? ?? ?? 00              // lea     edx, aContentType ; "Content-Type"
            89 14 24                       // mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00        // mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF                 // call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        deimosc2_agent_win32_colon_decrypt_obfuscated
        and all of them
}

rule deimosc2_agent_win32_tcp_obfuscated {
    meta:
        description = "Detects TCP samples by the presence of net.Dial() but no http.Post()"
        author = "Fernando Mercês @ Trend Micro FTR"
        date = "2022-08-05"

    strings:
        $http_Post = {
            E8 ?? ?? ?? 00               //                 call    net_http_NewRequestWithContext
            8B 44 24 20                  //                 mov     eax, [esp+40h+var_20]
            8B 4C 24 24                  //                 mov     ecx, [esp+40h+var_1C]
            8B 54 24 28                  //                 mov     edx, [esp+40h+var_18]
            85 C9                        //                 test    ecx, ecx
            0F 85 F4 00 00 00            //                 jnz     loc_6203AB
            89 44 24 30                  //                 mov     [esp+40h+var_10], eax
            8B 48 1C                     //                 mov     ecx, [eax+1Ch]
            89 4C 24 3C                  //                 mov     [esp+40h+var_4], ecx
            90                           //                 nop
            8D 15 ?? ?? ?? 00            //                 lea     edx, aContentType ; "Content-Type"
            89 14 24                     //                 mov     [esp+40h+var_40], edx ; int
            C7 44 24 04 0C 00 00 00      //                 mov     [esp+40h+var_3C], 0Ch ; int
            E8 ?? ?? ?? FF               //                 call    net_textproto_CanonicalMIMEHeaderKey
        }

    condition:
        deimosc2_agent_win32_colon_decrypt_obfuscated
        and not $http_Post
}
rule Windows_Trojan_PoshC2_e2d3881e {
    meta:
        author = "Elastic Security"
        id = "e2d3881e-d849-4ec8-a560-000a9b29814f"
        fingerprint = "30a9161077a90068acf756dcc2354bd04186f87717e32cccdcacc9521c41ddde"
        creation_date = "2023-03-29"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.PoshC2"
        reference_sample = "7a718a4f74656346bd9a2e29e008705fc2b1c4d167a52bd4f6ff10b3f2cd9395"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Sharp_v4_x64.dll"
        $a2 = "Sharp_v4_x86_dll"
        $a3 = "Posh_v2_x64_Shellcode" wide
        $a4 = "Posh_v2_x86_Shellcode" wide
        $b1 = "kill-implant" wide
        $b2 = "run-dll-background" wide
        $b3 = "run-exe-background" wide
        $b4 = "TVqQAAMAAAAEAAAA"
    condition:
        1 of ($a*) and 1 of ($b*)
}
import "pe"

rule brc4_core {
    meta:
        version = "first version"
        author = "@ninjaparanoid"
        reference = "https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/brc4.yara"
        date = "2022-11-19"
        description = "Hunts for known strings used in Badger till release v1.2.9 when not in an encrypted state"
    strings:
        $coreStrings1 = "CLOSED"
        $coreStrings2 = "LISTENING"
        $coreStrings3 = "SYN_SENT"
        $coreStrings4 = "SYN_RCVD"
        $coreStrings5 = "ESTABLISHED"
        $coreStrings6 = "FIN_WAIT1"
        $coreStrings7 = "FIN_WAIT2"
        $coreStrings8 = "CLOSE_WAIT"
        $coreStrings9 = "CLOSING"
        $coreStrings10 = "LAST_ACK"
        $coreStrings11 = "TIME_WAIT"
        $coreStrings12 = "DELETE_TCB"
        $coreStrings13 = "v4.0.30319"
        $coreStrings14 = "bYXJm/3#M?:XyMBF"
        $coreStrings15 = "ServicesActive"
        $coreStrings16 = "coffee"
        $coreStrings17 = "Until Admin Unlock"
        $coreStrings18 = "alertable"
        $coreStrings19 = "%02d%02d%d_%02d%02d%2d%02d_%s"
        $coreStrings20 = "<Left-Mouse>;"
        $coreStrings21 = "<Right-Mouse>;"
        $coreStrings22 = "<Cancel>;"
        $coreStrings23 = "<Middle-Mouse>;"
        $coreStrings24 = "<X1-Mouse>;"
        $coreStrings25 = "<X2-Mouse>;"
        $coreStrings26 = "<BackSpace>;"
        $coreStrings27 = "<Enter>;"
        $coreStrings28 = "<Shift>;"
        $coreStrings29 = "<CTRL>;"
        $coreStrings30 = "<ALT>;"
        $coreStrings31 = "<Pause>;"
        $coreStrings32 = "<Caps-Lock>;"
        $coreStrings33 = "<ESC>;"
        $coreStrings34 = "<Page-Up>;"
        $coreStrings35 = "<Page-Down>;"
        $coreStrings36 = "<End>;"
        $coreStrings37 = "<Home-Key>;"
        $coreStrings38 = "<Left-Arrow>;"
        $coreStrings39 = "<Up-Arrow>;"
        $coreStrings40 = "<Right-Arrow>;"
        $coreStrings41 = "<Down-Arrow>;"
        $coreStrings42 = "<Select>;"
        $coreStrings43 = "<Print-Key>;"
        $coreStrings44 = "<Print-Screen>;"
        $coreStrings45 = "<INS>;"
        $coreStrings46 = "<Delete>;"
        $coreStrings47 = "<Help>;"
        $coreStrings48 = "<Left-Windows-Key>;"
        $coreStrings49 = "<Right-Windows-Key>;"
        $coreStrings50 = "<Computer-Sleep>;"
        $coreStrings51 = "<F1>;"
        $coreStrings52 = "<F2>;"
        $coreStrings53 = "<F3>;"
        $coreStrings54 = "<F4>;"
        $coreStrings55 = "<F5>;"
        $coreStrings56 = "<F6>;"
        $coreStrings57 = "<F7>;"
        $coreStrings58 = "<F8>;"
        $coreStrings59 = "<F9>;"
        $coreStrings60 = "<F10>;"
        $coreStrings61 = "<F11>;"
        $coreStrings62 = "<F12>;"
        $coreStrings63 = "<F13>;"
        $coreStrings64 = "<F14>;"
        $coreStrings65 = "<F15>;"
        $coreStrings66 = "<F16>;"
        $coreStrings67 = "<F17>;"
        $coreStrings68 = "<F18>;"
        $coreStrings69 = "<F19>;"
        $coreStrings70 = "<F20>;"
        $coreStrings71 = "<F21>;"
        $coreStrings72 = "<F22>;"
        $coreStrings73 = "<F23>;"
        $coreStrings74 = "<F24>;"
        $coreStrings75 = "<Num-Lock>;"
        $coreStrings76 = "<Scroll-Lock>;"
        $coreStrings77 = "<Control>;"
        $coreStrings78 = "<Menu>;"
        $coreStrings79 = "<Volume Mute>;"
        $coreStrings80 = "<Volume Down>;"
        $coreStrings81 = "<Volume Up>;"
        $coreStrings82 = "<New Track>;"
        $coreStrings83 = "<Previous Track>;"
        $coreStrings84 = "<Play/Pause>;"
        $coreStrings85 = "<Play>;"
        $coreStrings86 = "<Zoom>;"
        $coreStrings87 = "%02X-%02X-%02X-%02X-%02X-%02X"
        $coreStrings88 = "%02d%02d%d_%02d%02d%2d%02d.png"
        $coreStrings89 = "%02d-%02d-%d %02d:%02d:%2d"
        $coreStrings90 = "%ls%s%ls%s%ls%s%ls%lu%ls%s%s"
        $coreStrings91 = "%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%ls%d%ls%lu%ls"
        $coreStrings92 = "bhttp_x64.dll"
        $coreStrings93 = "  - %-45ls : %d"
        $coreStrings94 = "  - %-45ls : %ls"
        $coreStrings95 = "  - %-45ls : %llu"
        $coreStrings96 = "  - %-45ls : %u"
        $coreStrings97 = "  - %-45ls : %f"
        $coreStrings98 = "  - %-45ls : %S"
        $coreStrings99 = "  - Path: %ls"
        $coreStrings100 = "  - Enabled: %ls"
        $coreStrings101 = "  - Last Run: %ls"
        $coreStrings102 = "  - Next Run: %ls"
        $coreStrings103 = "  - Current State: %ls"
        $coreStrings104 = "  - XML Output:"
        $coreStrings105 = "  - Error fetching xml"
        $coreStrings106 = "[+] Name: %ls"
        $coreStrings107 = "[+] Task: %ld"
        $coreStrings108 = "  - Name: %ls"
        $coreStrings109 = "BYTE data[] = {"
        $coreStrings110 = "[+] %s Password History:"
        $coreStrings111 = "[+] Object RDN: "
        $coreStrings112 = "[+] SAM Username: "
        $coreStrings113 = "[+] User Principal Name: "
        $coreStrings114 = "[+] UAC: %08x ["
        $coreStrings115 = "[+] Password last change: "
        $coreStrings116 = "[+] SID history:"
        $coreStrings117 = "[+] Object SID: "
        $coreStrings118 = "[+] Object RID: %u"
        $coreStrings119 = "[-] E: 0x%08x (%u) - %s"
        $coreStrings120 = "[-] E: no item!"
        $coreStrings121 = "[-] E: bad version (%u)"
        $coreStrings122 = "[-] E: 0x%08x (%u)"
        $coreStrings123 = "[-] E: (%08x)"
        $coreStrings124 = "[-] E: DRS Extension Size (%u)"
        $coreStrings125 = "[-] E: No DRS Extension"
        $coreStrings126 = "[-] E: DRSBind (%u)"
        $coreStrings127 = "[-] E: DC '%s' not found"
        $coreStrings128 = "[-] E: Version (%u)"
        $coreStrings129 = "[-] E: 0x%08x"
        $coreStrings130 = "[-] E: DC not found"
        $coreStrings131 = "[-] E: Binding DC!"
        $coreStrings132 = "[-] E: %u"
        $coreStrings133 = "[-] E: Domain not found"
        $coreStrings134 = "[+] Syncing DC: %ls"
        $coreStrings135 = "========================================|"
        $coreStrings136 = "[-] E: NCChangesReply"
        $coreStrings137 = "[-] E: GetNCChanges (%u)"
        $coreStrings138 = "[-] E: GetNCChanges: 0x%08x"
        $coreStrings139 = "[-] E: ASN1"
        $coreStrings140 = "[dsyn]"
        $coreStrings141 = "[+] size         : %lu"
        $coreStrings142 = "[+] malloc (RX)  : 0x%p"
        $coreStrings143 = "[+] malloc (RW)  : 0x%p"
        $coreStrings144 = "[+] size        : %lu"
        $coreStrings145 = "[+] mapview (RX): 0x%p"
        $coreStrings146 = "[+] mapview (RW): 0x%p"
        $coreStrings147 = "[-] Invalid thread"
        $coreStrings148 = "[+] Thread start : 0x%p"
        $coreStrings149 = "[+] Thread Id    : %lu"
        $coreStrings150 = "  - expires at: %02d-%02d-%02d %02d:%02d:%02d"
        $coreStrings151 = "%-30ls%-30ls%ls"
        $coreStrings152 = "%-30S*%-29ls%04d hours"
        $coreStrings153 = "%-30S%-30ls%04d hours"
        $coreStrings154 = "[+] User is privileged"
        $coreStrings155 = "[+] Members of [%ls] in %ls"
        $coreStrings156 = "[+] Members of [%ls]"
        $coreStrings157 = "p[+] Alertable thread: %lu"
        $coreStrings158 = "[-] E: No Alertable threads"
        $coreStrings159 = "[!] QAPC not supported on existing process"
        $coreStrings160 = "[+] PID (%S) => %lu"
        $coreStrings161 = "[+] PPID => %lu"
        $coreStrings162 = "[+] PID (%S) => %lu"
        $coreStrings163 = "[+] Args => (%S)"
        $coreStrings164 = "[+] PPID => %lu"
        $coreStrings165 = "[+] %S => PID: %lu"
        $coreStrings166 = "[+] %S => PID (Suspended): %lu:%lu"
        $coreStrings167 = "[+] SYS key: "
        $coreStrings168 = "[+] SAM key: "
        $coreStrings169 = "v2.0.50727"
        $coreStrings170 = "v4.0.30319"
        $coreStrings171 = "[+] Dotnet: v"
        $coreStrings172 = "[+] Socks started"
        $coreStrings173 = "[-] Socks stopped and Profile cleared"
        $coreStrings174 = "[+] Stasis: %d:%d"
        $coreStrings175 = "<DIR>?%ls?%02d-%02d-%d %02d:%02d"
        $coreStrings176 = "<DIR>?%ls"
        $coreStrings177 = "<FILE>?%ls?%02d-%02d-%d %02d:%02d?%lld bytes"
        $coreStrings178 = "<FILE>?%ls"
        $coreStrings179 = "[+] listing %ls"
        $coreStrings180 = "%02d-%02d-%d %02d:%02d <DIR>  %ls"
        $coreStrings181 = "%02d-%02d-%d %02d:%02d <FILE> %ls %lld bytes"
        $coreStrings182 = "[+] PID: %d"
        $coreStrings183 = "[+] Impersonated: '%S\\%S'"
        $coreStrings184 = "[+] Killed: %lu"
        $coreStrings185 = "%ls%-8ls | %-8ls | %-6ls | %-30ls 	| %ls"
        $coreStrings186 = "[pstree] %S"
        $coreStrings187 = "6%d?%d?%S?%ls?%ls"
        $coreStrings188 = "%-8d | %-8d | %-6S | %-30ls 	| %ls"
        $coreStrings189 = "%d?%d?N/A?N/A?%ls"
        $coreStrings190 = "%-8d | %-8d | %-6ls | %-30ls 	| %ls"
        $coreStrings191 = "[-] Child Process???"
        $coreStrings192 = "[+] PID: %lu"
        $coreStrings193 = "[+] Impersonated '%ls'"
        $coreStrings194 = "[-] Duplicate listener: %S"
        $coreStrings195 = "[+] TCP listener: %S"
        $coreStrings196 = "[TCP] [%S]-<>-[%S]"
        $coreStrings197 = "[+] Added to Token Vault: %ls"
        $coreStrings198 = "[-] E: Invalid Arch: 0x%X"
        $coreStrings199 = "[+] Searching [0x%02X] permission"
        $coreStrings200 = "[-] SPN not found: %ls"
        $coreStrings201 = "[-] Invalid SPN: %S"
        $coreStrings202 = "[+] SPN: %ls"
        $coreStrings203 = "[+] Start Address: (%p)"
        $coreStrings204 = "[!] Invalid Address"
        $coreStrings205 = "[!] Invalid PID: %S"
        $coreStrings206 = "[+] PID: %lu"
        $coreStrings207 = "[+] TID: %lu"
        $coreStrings208 = "[+] T-Handle: 0x%X"
        $coreStrings209 = "[+] Suspend count: %lu"
        $coreStrings210 = "[+] %-24ls%-24ls%-24ls"
        $coreStrings211 = "%-66ls%-46ls%ls"
        $coreStrings212 = "    ============================================================= ============================================= =================================================="
        $coreStrings213 = "[+] Elevated Privilege"
        $coreStrings214 = "[-] Restricted Privilege"
        $coreStrings215 = "[+] Task-%d => %S (%S %%)"
        $coreStrings216 = "[Tasks] %02d => 0x%02X 0x%02X"
        $coreStrings217 = "[*] No active tasks"
        $coreStrings218 = "[-] Child: NA"
        $coreStrings219 = "[+] Child: %S"
        $coreStrings220 = "[TCP] Task-%d => %S"
        $coreStrings221 = "[+] Malloc: %lu"
        $coreStrings222 = "[+] ThreadEx: %lu"
        $coreStrings223 = "[+] %-30ls: %S"
        $coreStrings224 = "[+] %-30ls: %S"
        $coreStrings225 = "[+] %-30ls: "
        $coreStrings226 = "[+] %-30ls: %ls"
        $coreStrings227 = "  - %-6S %-22S %-22S %S"
        $coreStrings228 = "  - %-6S %-22S %-22S"
        $coreStrings229 = "  - 0x%lu [%02X-%02X-%02X-%02X-%02X-%02X] %S"
        $coreStrings230 = "  %-21S%-17S%-17S%-11S%-10S"
        $coreStrings231 = "  - %-19S%-17S%-17S%-11ld%-9ld"
        $coreStrings232 = "  - %-30ls: %I64dMB/%I64dMB"
        $coreStrings233 = "  - %-30ls: %lu MB"
        $coreStrings234 = "[+] CM: Already Running"
        $coreStrings235 = "[+] CM: Running"
        $coreStrings236 = "[+] CM: Started"
        $coreStrings237 = "[*] Task-%02d [Thread: %lu]"
        $coreStrings238 = "+-------------------------------------------------------------------+"
        $coreStrings239 = "[+] Session ID %lu => %ls: %ls\\%ls"
        $coreStrings240 = "[+] Enumerating PID: %lu [%ls]"
        $coreStrings241 = "[+] Captured Handle (PID: %lu)"
        $coreStrings242 = "[+] Initiated NTFS transaction"
        $coreStrings243 = "\\??\\C:\\Users\\Public\\cache.txt"
        $coreStrings244 = "[+] Dump Size: %d Mb"
        $coreStrings245 = "bhttp_x64.dll"
        $coreStrings246 = "bYXJm/3#M?:XyMBF"
        $coreStrings247 = "SeDebugPrivilege"
    condition:
        20 of them
}

rule brc4_shellcode {
    meta:
        version = "last version"
        author = "@ninjaparanoid"
        description = "Hunts for shellcode opcode used in Badger x86/x64 till release v1.2.9"
        arch_context = "x64"
        reference = "https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/brc4.yara"
        date = "2022-11-19"
    strings:
        $shellcode_x64_Start = { 55 50 53 51 52 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 }
        $shellcode_x64_End = { 5B 5E 5F 41 5C 41 5D 41 5E 41 5F 5D C3 }
        $shellcode_x64_StageEnd = { 5C 41 5F 41 5E 41 5D 41 5C 41 5B 41 5A 41 59 41 58 5F 5E 5A 59 5B 58 5D C3 }
        $funcHash1 = { 5B BC 4A 6A }
        $funcHash2 = { 5D 68 FA 3C }
        $funcHash3 = { AA FC 0D 7C }
        $funcHash4 = { 8E 4E 0E EC }
        $funcHash5 = { B8 12 DA 00 }
        $funcHash6 = { 07 C4 4C E5 }
        $funcHash7 = { BD CA 3B D3 }
        $funcHash8 = { 89 4D 39 8C }
        $hashFuncx64 = { EB 20 0F 1F 44 00 00 44 0F B6 C8 4C 89 DA 41 83 E9 20 4D 63 C1 4B 8D 04 10 49 39 CB 74 21 49 83 C3 01 41 89 C2 }
        $hashFuncx86 = { EB 07 8D 74 26 00 83 C2 01 0F B6 31 C1 C8 0D 89 F1 8D 5C 30 E0 01 F0 80 F9 61 89 D1 0F 43 C3 39 D7 75 E3 }
    condition:
        (pe.machine == pe.MACHINE_AMD64 and (2 of ($shellcode*) or all of ($funcHash*) and $hashFuncx64))
        or
        (pe.machine == pe.MACHINE_I386 and (all of ($funcHash*) and $hashFuncx86))
}
rule apfell_mythic {
   meta:
      description = "May detect a Mythic/Apfell C2 Agent"
      author = "cbecks2"
      date = "2021-10-21"
   strings:
      $x1 = "exports.shell_elevated = function(task, command, params){" fullword ascii
      $x2 = "exports.spawn_drop_and_execute = function(task, command, params){" fullword ascii
      $s3 = "b64_exported_public = b64_exported_public.base64EncodedStringWithOptions(0).js; // get a base64 encoded string version" fullword ascii
      $s4 = "exports.persist_loginitem_allusers = function(task, command, params){" fullword ascii
      $s5 = "exports.spawn_download_cradle = function(task, command, params){" fullword ascii
      $s6 = "exports.test_password = function(task, command, params){" fullword ascii
      $s7 = "exports.list_users = function(task, command, params){" fullword ascii
      $s8 = "exports.system_info = function(task, command, params){" fullword ascii
      $s9 = "            var full_command = \"echo \\\"\" + base64_command + \"\\\" | base64 -D | /usr/bin/osascript -l JavaScript &amp;\";" fullword ascii
      $s10 = "//console.log(\"posting: \" + sendData + \" to \" + urlEnding);" fullword ascii
      $s11 = "        return {\"user_output\": \"Created temp file: \" + temp_file + \", started process and removed file\", \"completed\": tr" ascii
      $s12 = "        return {\"user_output\": \"Created temp file: \" + temp_file + \", started process and removed file\", \"completed\": tr" ascii
      $s13 = "//console.log(\"about to load commands\");" fullword ascii
      $s14 = "                    return {\"user_output\":\"Error trying to read /Library/LaunchAgents: \" + error.toString(), \"completed\": " ascii
      $s15 = "                    \"app.doShellScript(\\\" osascript -l JavaScript -e \\\\\\\"eval(ObjC.unwrap($.NSString.alloc.initWithDataEn" ascii
      $s16 = "exports.download = function(task, command, params){" fullword ascii
      $s17 = "exports.run = function(task, command, params){" fullword ascii
      $s18 = "                    return {\"user_output\":\"Error trying to read /Library/LaunchAgents: \" + error.toString(), \"completed\": " ascii
      $s19 = "this.pid = this.procInfo.processIdentifier;" fullword ascii
      $s20 = "exports.jscript = function(task, command, params){" fullword ascii
   condition:
      uint16(0) == 0x2f2f and filesize < 300KB and
      1 of ($x*) and 4 of them
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule Sliver_Implant_32bit
{
  meta:
    description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    hash =  "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      81 ?? 74 63 70 70     cmp     dword ptr [ecx], 70706374h
      .
      .
      .
      81 ?? 04 69 76 6F 74  cmp     dword ptr [ecx+4], 746F7669h
    */
    $s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }

    // case "wg":
    /*
      66 81 ?? 77 67 cmp     word ptr [eax], 6777h      // "gw"
    */
    $s_wg = { 66 81 ?? 77 67 }

    // case "dns":
    /*
      66 81 ?? 64 6E cmp     word ptr [eax], 6E64h    // "nd"
      .
      .
      .
      80 ?? 02 73    cmp     byte ptr [eax+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "http":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [eax], 70747468h     // "ptth"
     */
    $s_http = { 81 ?? 68 74 74 70 }

    // case "https":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [ecx], 70747468h     // "ptth"
      .
      .
      .
      80 ?? 04 73        cmp     byte ptr [ecx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }

    // case "mtls":       NOTE: this one can be missing due to compilate time config
    /*
      81 ?? 6D 74 6C 73  cmp     dword ptr [eax], 736C746Dh     // "sltm"
    */
    $s_mtls = { 81 ?? 6D 74 6C 73 }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    4 of ($s*) and not 1 of ($fp*)
}
/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule Sliver_Implant_64bit
{
  meta:
    description = "Sliver 64-bit implant (with and without --debug flag at compile)"
    hash =  "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      48 ?? 74 63 70 70 69 76 6F 74 mov     rcx, 746F766970706374h
    */
    $s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }


    // case "namedpipe":
    /*
      48 ?? 6E 61 6D 65 64 70 69 70 mov     rsi, 70697064656D616Eh      // "pipdeman"
      .
      .
      .
      80 ?? 08 65 cmp     byte ptr [rdx+8], 65h ; 'e'

    */
    $s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }

    // case "https":
    /*
      81 3A 68 74 74 70 cmp     dword ptr [rdx], 70747468h          // "ptth"
      .
      .
      .
      80 7A 04 73       cmp     byte ptr [rdx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }

    // case "wg":
    /*
      66 81 3A 77 67 cmp     word ptr [rdx], 6777h      // "gw"
    */
    $s_wg = {66 81 ?? 77 67}


    // case "dns":
    /*
      66 81 3A 64 6E cmp     word ptr [rdx], 6E64h     // "nd"
      .
      .
      .
      80 7A 02 73    cmp     byte ptr [rdx+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "mtls":         // This one may or may not be in the file, depending on the config flags.
    /*
       81 ?? 6D 74 6C 73 cmp   dword ptr [rdx], 736C746Dh          // "mtls"
    */
    $s_mtls = {  81 ?? 6D 74 6C 73  }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    5 of ($s*) and not 1 of ($fp*)
}
rule Windows_Trojan_IcedID_1cd868a6 {
    meta:
        author = "Elastic Security"
        id = "1cd868a6-d2ec-4c48-a69a-aaa6c7af876c"
        fingerprint = "3e76b3ac03c5268923cfd5d0938745d66cda273d436b83bee860250fdcca6327"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_237e9fb6 {
    meta:
        author = "Elastic Security"
        id = "237e9fb6-b5fa-4747-af1f-533c76a5a639"
        fingerprint = "e2ea6d1477ce4132f123b6c00101a063f7bba7acf38be97ee8dca22cc90ed511"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_f1ce2f0a {
    meta:
        author = "Elastic Security"
        id = "f1ce2f0a-0d34-46a4-8e42-0906adf4dc1b"
        fingerprint = "1940c4bf5d8011dc7edb8dde718286554ed65f9e96fe61bfa90f6182a4b8ca9e"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_08530e24 {
    meta:
        author = "Elastic Security"
        id = "08530e24-5b84-40a4-bc5c-ead74762faf8"
        fingerprint = "f2b5768b87eec7c1c9730cc99364cc90e87fd9201bf374418ad008fd70d321af"
        creation_date = "2021-03-21"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "c:\\ProgramData\\" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
        $a3 = "aws.amazon.com" wide fullword
        $a4 = "Cookie: __gads=" wide fullword
        $b1 = "LookupAccountNameW" ascii fullword
        $b2 = "GetUserNameA" ascii fullword
        $b3 = "; _gat=" wide fullword
        $b4 = "; _ga=" wide fullword
        $b5 = "; _u=" wide fullword
        $b6 = "; __io=" wide fullword
        $b7 = "; _gid=" wide fullword
        $b8 = "%s%u" wide fullword
        $b9 = "i\\|9*" ascii fullword
        $b10 = "WinHttpSetStatusCallback" ascii fullword
    condition:
        all of ($a*) and 5 of ($b*)
}

rule Windows_Trojan_IcedID_11d24d35 {
    meta:
        author = "Elastic Security"
        id = "11d24d35-6bff-4fac-83d8-4d152aa0be57"
        fingerprint = "155e5df0f3f598cdc21e5c85bcf21c1574ae6788d5f7e0058be823c71d06c21e"
        creation_date = "2022-02-16"
        last_modified = "2022-04-06"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b8d794f6449669ff2d11bc635490d9efdd1f4e92fcb3be5cdb4b40e4470c0982"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\user\\source\\repos\\anubis\\bin\\RELEASE\\loader_dll_64.pdb" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_IcedID_0b62e783 {
    meta:
        author = "Elastic Security"
        id = "0b62e783-5c1a-4377-8338-1c53194b8d01"
        fingerprint = "2f473fbe6338d9663808f1a3615cf8f0f6f9780fbce8f4a3c24f0ddc5f43dd4a"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 44 95 E0 83 E0 07 8A C8 42 8B 44 85 E0 D3 C8 FF C0 42 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_91562d18 {
    meta:
        author = "Elastic Security"
        id = "91562d18-28a1-4349-9e4b-92ad165510c9"
        fingerprint = "024bbd15da6bc759e321779881b466b500f6364a1d67bbfdc950aedccbfbc022"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 44 8B 4C 19 2C 4C 03 D6 74 1C 4D 85 C0 74 17 4D 85 C9 74 12 41 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_2086aecb {
    meta:
        author = "Elastic Security"
        id = "2086aecb-161b-4102-89c7-580fb9ac3759"
        fingerprint = "a8b6cbb3140ff3e1105bb32a2da67831917caccc4985c485bbfdb0aa50016d86"
        creation_date = "2022-04-06"
        last_modified = "2022-03-02"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 4C 8D 05 [4] 42 8A 44 01 ?? 42 32 04 01 88 44 0D ?? 48 FF C1 48 83 F9 20 72 ?? }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_48029e37 {
    meta:
        author = "Elastic Security"
        id = "48029e37-b392-4d53-b0de-2079f6a8a9d9"
        fingerprint = "375266b526fe14354550d000d3a10dde3f6a85e11f4ba5cab14d9e1f878de51e"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 C1 E3 10 0F 31 48 C1 E2 ?? 48 0B C2 0F B7 C8 48 0B D9 8B CB 83 E1 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_56459277 {
    meta:
        author = "Elastic Security"
        id = "56459277-432c-437c-9350-f5efaa60ffca"
        fingerprint = "503bfa6800e0f4ff1a0b56eb8a145e67fa0f387c84aee7bd2eca3cf7074be709"
        creation_date = "2022-08-21"
        last_modified = "2023-03-02"
        description = "IcedID Gzip Variant Core"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "21b1a635db2723266af4b46539f67253171399830102167c607c6dbf83d6d41c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "cookie.tar" ascii fullword
        $str2 = "passff.tar" ascii fullword
        $str3 = "\\sqlite64.dll" ascii fullword
        $str4 = "Cookie: session=" ascii fullword
        $str5 = "{0ccac395-7d1d-4641-913a-7558812ddea2}" ascii fullword
        $str6 = "mail_vault" wide fullword
        $seq_decrypt_payload = { 42 0F B6 04 32 48 FF C2 03 C8 C1 C1 ?? 48 3B D7 72 ?? 44 33 F9 45 33 C9 44 89 3C 3B 48 85 FF 74 ?? 41 0F B6 D1 44 8D 42 01 83 E2 03 41 83 E0 03 }
        $seq_compute_hash = { 0F B6 4C 14 ?? 48 FF C2 8B C1 83 E1 ?? 48 C1 E8 ?? 41 0F B7 04 41 66 89 03 48 8D 5B ?? 41 0F B7 0C 49 66 89 4B ?? 48 83 FA ?? 72 ?? 66 44 89 03 B8 }
        $seq_format_string = { C1 E8 ?? 44 0B D8 41 0F B6 D0 8B C1 C1 E2 ?? C1 E1 ?? 25 [4] 0B C1 41 C1 E8 ?? 41 0F B6 CA 41 0B D0 44 8B 44 24 ?? C1 E0 ?? C1 E1 ?? 41 C1 EB ?? 44 0B D8 41 C1 EA ?? 0F B7 44 24 ?? 41 0B CA }
        $seq_custom_ror = { 41 8A C0 41 8A D0 02 C0 0F B6 C8 8A C1 44 8B C1 34 ?? 84 D2 0F B6 C8 44 0F 48 C1 49 83 EB }
        $seq_string_decrypt = { 0F B7 44 24 ?? 0F B7 4C 24 ?? 3B C1 7D ?? 8B 4C 24 ?? E8 [4] 89 44 24 ?? 0F B7 44 24 ?? 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 33 C1 0F B7 4C 24 ?? 48 8B 54 24 ?? 88 04 0A EB }
    condition:
        5 of ($str*) or 2 of ($seq_*)
}

rule Windows_Trojan_IcedID_7c1619e3 {
    meta:
        author = "Elastic Security"
        id = "7c1619e3-f94a-4a46-8a81-d5dd7a58c754"
        fingerprint = "ae21deaad74efaff5bec8c9010dc340118ac4c79e3bec190a7d3c3672a5a8583"
        creation_date = "2022-12-20"
        last_modified = "2023-02-01"
        description = "IcedID Injector Variant Loader "
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "4f6de748628b8b06eeef3a5fabfe486bfd7aaa92f50dc5a8a8c70ec038cd33b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 84 C0 75 ?? 8B 74 24 ?? 81 F1 [4] 39 16 76 }
        $a2 = { D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 }
        $a3 = { 8B 4E ?? FF 74 0B ?? 8B 44 0B ?? 03 C1 50 8B 44 0B ?? 03 46 ?? 50 E8 [4] 8B 46 ?? 8D 5B ?? 83 C4 0C 47 3B 78 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_d8b23cd6 {
    meta:
        author = "Elastic Security"
        id = "d8b23cd6-c20c-40c9-a8e9-80d68e709764"
        fingerprint = "d47af2b50d0fb07858538fdb9f53fee008b49c9b1d015e4593199407673e0e21"
        creation_date = "2023-01-03"
        last_modified = "2023-01-03"
        description = "IcedID VNC server"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "bd4da2f84c29437bc7efe9599a3a41f574105d449ac0d9b270faaca8795153ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User idle %u sec / Locked: %s / ScreenSaver: %s" wide
        $a2 = "No VNC HOOK" wide
        $a3 = "Webcam %u" wide
        $a4 = "rundll32.exe shell32.dll,#61"
        $a5 = "LAP WND"
        $a6 = "FG WND"
        $a7 = "CAP WND"
        $a8 = "HDESK Tmp" wide
        $a9 = "HDESK Bot" wide
        $a10 = "HDESK bot" wide
        $a11 = "CURSOR: %u, %u"
        $b1 = { 83 7C 24 ?? 00 75 ?? 83 7C 24 ?? 00 75 ?? [1] 8B 0D [4] 8B 44 24 }
    condition:
        6 of them
}

rule Windows_Trojan_IcedID_a2ca5f80 {
    meta:
        author = "Elastic Security"
        id = "a2ca5f80-85b1-4502-8794-b8b4ea1be482"
        fingerprint = "dfbacf63b91315e5acf168b57bf18283ba30f681f5b3d3835418d0d32d238854"
        creation_date = "2023-01-16"
        last_modified = "2023-04-23"
        description = "IcedID Injector Variant Core"
        threat_name = "Windows.Trojan.Icedid"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "EMPTY"
        $a2 = "CLEAR"
        $a3 = { 66 C7 06 6D 3D 83 C6 02 0F B6 05 [4] 50 68 34 73 00 10 56 FF D7 03 F0 66 C7 06 26 6A C6 46 ?? 3D 83 C6 03 }
        $a4 = { 8B 46 ?? 6A 00 FF 76 ?? F7 D8 FF 76 ?? 1B C0 FF 76 ?? 50 FF 76 ?? 53 FF 15 }
        $a5 = { 8D 44 24 ?? 89 7C 24 ?? 89 44 24 ?? 33 F6 B8 BB 01 00 00 46 55 66 89 44 24 ?? 89 74 24 ?? E8 [4] 89 44 24 ?? 85 C0 74 ?? 8B AC 24 }
        $a6 = { 8A 01 88 45 ?? 45 41 83 EE 01 75 ?? 8B B4 24 [4] 8B 7E }
        $a7 = { 53 E8 [4] 8B D8 30 1C 2F 45 59 3B EE 72 }
        $a8 = { 8B 1D [4] 33 D9 6A 00 53 52 E8 [4] 83 C4 0C 89 44 24 ?? 85 C0 0F 84 }
        $a9 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 }
    condition:
        4 of them
}
// Copyright (C) 2013 Claudio "nex" Guarnieri

rule embedded_macho
{
    meta:
        author = "nex"
        description = "Contains an embedded Mach-O file"

    strings:
        $magic1 = { ca fe ba be }
        $magic2 = { ce fa ed fe }
        $magic3 = { fe ed fa ce }
    condition:
        any of ($magic*) and not ($magic1 at 0) and not ($magic2 at 0) and not ($magic3 at 0)
}

rule embedded_pe
{
    meta:
        author = "nex"
        description = "Contains an embedded PE32 file"

    strings:
        $a = "PE32"
        $b = "This program"
        $mz = { 4d 5a }
    condition:
        ($a and $b) and not ($mz at 0)
}

rule embedded_win_api
{
    meta:
        author = "nex"
        description = "A non-Windows executable contains win32 API functions names"

    strings:
        $mz = { 4d 5a }
        $api1 = "CreateFileA"
        $api2 = "GetProcAddress"
        $api3 = "LoadLibraryA"
        $api4 = "WinExec"
        $api5 = "GetSystemDirectoryA"
        $api6 = "WriteFile"
        $api7 = "ShellExecute"
        $api8 = "GetWindowsDirectory"
        $api9 = "URLDownloadToFile"
        $api10 = "IsBadReadPtr"
        $api11 = "IsBadWritePtr"
        $api12 = "SetFilePointer"
        $api13 = "GetTempPath"
        $api14 = "GetWindowsDirectory"
    condition:
        not ($mz at 0) and any of ($api*)
}

rule Arcom
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Arcom"
        family = "arcom"
        tags = "rat, arcom"

    strings:
        $a1 = "CVu3388fnek3W(3ij3fkp0930di"
        $a2 = "ZINGAWI2"
        $a3 = "clWebLightGoldenrodYellow"
        $a4 = "Ancestor for '%s' not found" wide
        $a5 = "Control-C hit" wide
        $a6 = {A3 24 25 21}

    condition:
        all of them
}

rule adWind
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/adWind"
        family = "adwind"
        tags = "rat, adwind"

    strings:
        $meta = "META-INF"
        $conf = "config.xml"
        $a = "Adwind.class"
        $b = "Principal.adwind"

    condition:
        all of them
}

rule Adzok
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        Description = "Adzok Rat"
        Versions = "Free 1.0.0.3,"
        date = "2015/05"
        ref = "http://malwareconfig.com/stats/Adzok"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "adzok"
        tags = "rat, adzok"

    strings:
        $a1 = "config.xmlPK"
        $a2 = "key.classPK"
        $a3 = "svd$1.classPK"
        $a4 = "svd$2.classPK"
    $a5 = "Mensaje.classPK"
        $a6 = "inic$ShutdownHook.class"
        $a7 = "Uninstall.jarPK"
        $a8 = "resources/icono.pngPK"
        
    condition:
    7 of ($a*)
}

rule Ap0calypse
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Ap0calypse"
        family = "ap0calypse"
        tags = "rat, apocalypse"

    strings:
        $a = "Ap0calypse"
        $b = "Sifre"
        $c = "MsgGoster"
        $d = "Baslik"
        $e = "Dosyalars"
        $f = "Injecsiyon"

    condition:
        all of them
}

rule Albertino
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/AAR"
        family = "albertino"
        tags = "rat, albertino"

    strings:
        $a = "Hashtable"
        $b = "get_IsDisposed"
        $c = "TripleDES"
        $d = "testmemory.FRMMain.resources"
        $e = "$this.Icon" wide
        $f = "{11111-22222-20001-00001}" wide
        $g = "@@@@@@@@@@@"

    condition:
        all of them
}

rule AlienSpy
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/03"
        ref = "http://malwareconfig.com/stats/AlienSpy"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "alienspy"
        tags = "rat, alienspy"

    strings:
        $a1 = "Main.classPK"
        $a2 = "MANIFEST.MFPK"
        $a3 = "plugins/Server.classPK"
        $a4 = "META-INF/MANIFEST.MF"
        $a5 = "ID"
        
        $b1 = "config.xml"
        $b2 = "options/PK"
        $b3 = "plugins/PK"
        $b4 = "util/PK"
        $b5 = "util/OSHelper/PK"
        $b6 = "Start.class"
        $b7 = "AlienSpy"
    condition:
        all of ($a*) or all of ($b*)
}

rule Bandook
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Bandook"
        maltype = "Remote Access Trojan"
        family = "bandook"
        tags = "rat, bandook"

    strings:
            $a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
            $e = "aaaaaa5|"
            $f = "%s%d.exe"
            $g = "astalavista"
            $h = "givemecache"
            $i = "%s\\system32\\drivers\\blogs\\*"
            $j = "bndk13me"

    condition:
            all of them
}

rule BlackNix
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/BlackNix"
        family = "blacknix"
        tags = "rat, blacknix"

    strings:
        $a1 = "SETTINGS" wide
        $a2 = "Mark Adler"
        $a3 = "Random-Number-Here"
        $a4 = "RemoteShell"
        $a5 = "SystemInfo"


    condition:
        all of them
}

rule Bozok
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Bozok"
        family = "bozok"
        tags = "rat, bozok"

    strings:
        $a = "getVer" nocase
        $b = "StartVNC" nocase
        $c = "SendCamList" nocase
        $d = "untPlugin" nocase
        $e = "gethostbyname" nocase

    condition:
        all of them
}

rule BlueBanana
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/BlueBanana"
        maltype = "Remote Access Trojan"
        filetype = "Java"
        family = "bluebanana"
        tags = "rat, bluebanane"

    strings:
        $meta = "META-INF"
        $conf = "config.txt"
        $a = "a/a/a/a/f.class"
        $b = "a/a/a/a/l.class"
        $c = "a/a/a/b/q.class"
        $d = "a/a/a/b/v.class"


    condition:
        all of them
}

rule BlackShades
{
    meta:
        author = "Brian Wallace (@botnet_hunter)"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
        family = "blackshades"
        tags = "rat blackshades"

    strings:
        $string1 = "bss_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    condition:
        all of them
}

rule ClientMesh
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/06"
        ref = "http://malwareconfig.com/stats/ClientMesh"
        family = "clientmesh"
        tags = "rat, clientmesh"

    strings:
        $string1 = "machinedetails"
        $string2 = "MySettings"
        $string3 = "sendftppasswords"
        $string4 = "sendbrowserpasswords"
        $string5 = "arma2keyMass"
        $string6 = "keylogger"
        $conf = {00 00 00 00 00 00 00 00 00 7E}

    condition:
        all of them
}

rule Crimson
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        Description = "Crimson Rat"
        date = "2015/05"
        ref = "http://malwareconfig.com/stats/Crimson"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "crimson"
        tags = "rat, crimson"

    strings:
        $a1 = "com/crimson/PK"
        $a2 = "com/crimson/bootstrapJar/PK"
        $a3 = "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
        $a4 = "com/crimson/universal/containers/KeyloggerLog.classPK"
        $a5 = "com/crimson/universal/UploadTransfer.classPK"
        
    condition:
        all of ($a*)
}

rule CyberGate
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/CyberGate"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "cybergate"
        tags = "rat, cybergate"

    strings:
        $string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
        $string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
        $string3 = "EditSvr"
        $string4 = "TLoader"
        $string5 = "Stroks"
        $string6 = "####@####"
        $res1 = "XX-XX-XX-XX"
        $res2 = "CG-CG-CG-CG"

    condition:
        all of ($string*) and any of ($res*)
}

rule DarkComet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/DarkComet"
        family = "darkcomet"
        tags = "rat, darkcomet"

    strings:
        // Versions 2x
        $a1 = "#BOT#URLUpdate"
        $a2 = "Command successfully executed!"
        $a3 = "MUTEXNAME" wide
        $a4 = "NETDATA" wide
        // Versions 3x & 4x & 5x
        $b1 = "FastMM Borland Edition"
        $b2 = "%s, ClassID: %s"
        $b3 = "I wasn't able to open the hosts file"
        $b4 = "#BOT#VisitUrl"
        $b5 = "#KCMDDC"

    condition:
        all of ($a*) or all of ($b*)
}

rule DarkRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/DarkRAT"
        maltype = "Remote Access Trojan"
        family = "darkrat"
        tags = "rat, darkrat"

    strings:
        $a = "@1906dark1996coder@"
        $b = "SHEmptyRecycleBinA"
        $c = "mciSendStringA"
        $d = "add_Shutdown"
        $e = "get_SaveMySettingsOnExit"
        $f = "get_SpecialDirectories"
        $g = "Client.My"

    condition:
        all of them
}

rule Greame
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Greame"
        maltype = "Remote Access Trojan"
        family = "greame"
        tags = "rat, greame"

    strings:
            $a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
            $b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
            $c = "EditSvr"
            $d = "TLoader"
            $e = "Stroks"
            $f = "Avenger by NhT"
            $g = "####@####"
            $h = "GREAME"

    condition:
            all of them
}

rule HawkEye
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/06"
        ref = "http://malwareconfig.com/stats/HawkEye"
        maltype = "KeyLogger"
        filetype = "exe"
        family = "hawkeye"
        tags = "rat, hawkeye"

    strings:
        $key = "HawkEyeKeylogger" wide
        $salt = "099u787978786" wide
        $string1 = "HawkEye_Keylogger" wide
        $string2 = "holdermail.txt" wide
        $string3 = "wallet.dat" wide
        $string4 = "Keylog Records" wide
    $string5 = "<!-- do not script -->" wide
    $string6 = "\\pidloc.txt" wide
    $string7 = "BSPLIT" wide

    condition:
        $key and $salt and all of ($string*)
}

rule Imminent
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Imminent"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "imminent"
        tags = "rat, imminent"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule Infinity
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Infinity"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "infinity"
        tags = "rat, infinity"

    strings:
        $a = "CRYPTPROTECT_PROMPTSTRUCT"
        $b = "discomouse"
        $c = "GetDeepInfo"
        $d = "AES_Encrypt"
        $e = "StartUDPFlood"
        $f = "BATScripting" wide
        $g = "FBqINhRdpgnqATxJ.html" wide
        $i = "magic_key" wide

    condition:
        all of them
}

rule jRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/jRat"
        maltype = "Remote Access Trojan"
        filetype = "Java"
        family = "jrat"
        tags = "rat, jrat"

    strings:
        $meta = "META-INF"
        $key = "key.dat"
        $conf = "config.dat"
         $jra1 = "enc.dat"
        $jra2 = "a.class"
        $jra3 = "b.class"
        $jra4 = "c.class"
        $reClass1 = /[a-z]\.class/
        $reClass2 = /[a-z][a-f]\.class/

    condition:
       ($meta and $key and $conf and #reClass1 > 10 and #reClass2 > 10) or ($meta and $key and all of ($jra*))
}

rule LostDoor
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/LostDoor"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "lostdoor"
        tags = "rat, lostdoor"

    strings:
        $a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
        $a1 = "*mlt* = %"
        $a2 = "*ip* = %"
        $a3 = "*victimo* = %"
        $a4 = "*name* = %"
        $b5 = "[START]"
        $b6 = "[DATA]"
        $b7 = "We Control Your Digital World" wide ascii
        $b8 = "RC4Initialize" wide ascii
        $b9 = "RC4Decrypt" wide ascii

    condition:
        all of ($a*) or all of ($b*)
}

rule LuminosityLink
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/06"
        ref = "http://malwareconfig.com/stats/LuminosityLink"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "luminositylink"
        tags = "rat, luminositylink"

    strings:
        $a = "SMARTLOGS" wide
        $b = "RUNPE" wide
        $c = "b.Resources" wide
        $d = "CLIENTINFO*" wide
        $e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
        $f = "Proactive Anti-Malware has been manually activated!" wide
        $g = "REMOVEGUARD" wide
        $h = "C0n1f8" wide
        $i = "Luminosity" wide
        $j = "LuminosityCryptoMiner" wide
        $k = "MANAGER*CLIENTDETAILS*" wide

    condition:
        all of them
}

rule LuxNet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/LuxNet"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "luxnet"
        tags = "rat, luxnet"

    strings:
        $a = "GetHashCode"
        $b = "Activator"
        $c = "WebClient"
        $d = "op_Equality"
        $e = "dickcursor.cur" wide
        $f = "{0}|{1}|{2}" wide

    condition:
        all of them
}

rule NanoCore
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "nanocore"
        tags = "rat, nanocore"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}

rule NetWire
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NetWire"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "netwire"
        tags = "rat, netwire"
        
    strings:
        $string1 = "[Scroll Lock]"
        $string2 = "[Shift Lock]"
        $string3 = "200 OK"
        $string4 = "%s.Identifier"
        $string5 = "sqlite3_column_text"
        $string6 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
    condition:
        all of them
}

rule njRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/njRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "njrat"
        tags = "rat, njrat"

    strings:

        $s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
        $s2 = "netsh firewall add allowedprogram" wide
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s4 = "yyyy-MM-dd" wide

        $v1 = "cmd.exe /k ping 0 & del" wide
        $v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $v3 = "cmd.exe /c ping 0 -n 2 & del" wide


    condition:
        all of ($s*) and any of ($v*)
}

rule Pandora
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Pandora"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "pandora"
        tags = "rat, pandora"

    strings:
        $a = "Can't get the Windows version"
        $b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
        $c = "JPEG error #%d" wide
        $d = "Cannot assign a %s to a %s" wide
        $g = "%s, ProgID:"
        $h = "clave"
        $i = "Shell_TrayWnd"
        $j = "melt.bat"
        $k = "\\StubPath"
        $l = "\\logs.dat"
        $m = "1027|Operation has been canceled!"
        $n = "466|You need to plug-in! Double click to install... |"
        $0 = "33|[Keylogger Not Activated!]"

    condition:
        all of them
}

rule Paradox
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Paradox"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "paradox"
        tags = "rat, paradox"

    strings:
        $a = "ParadoxRAT"
        $b = "Form1"
        $c = "StartRMCam"
        $d = "Flooders"
        $e = "SlowLaris"
        $f = "SHITEMID"
        $g = "set_Remote_Chat"

    condition:
        all of them
}

rule PoisonIvy
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        family = "poisonivy"
        tags = "rat, poisonivy"

    strings:
        $stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
        $string1 = "CONNECT %s:%i HTTP/1.0"
        $string2 = "ws2_32"
        $string3 = "cks=u"
        $string4 = "thj@h"
        $string5 = "advpack"
    condition:
        $stub at 0x1620 and all of ($string*) or (all of them)
}

rule PredatorPain
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PredatorPain"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "predatorpain"
        tags = "rat, predatorpain"

    strings:
        $string1 = "holderwb.txt" wide
        $string3 = "There is a file attached to this email" wide
        $string4 = "screens\\screenshot" wide
        $string5 = "Disablelogger" wide
        $string6 = "\\pidloc.txt" wide
        $string7 = "clearie" wide
        $string8 = "clearff" wide
        $string9 = "emails should be sent to you shortly" wide
        $string10 = "jagex_cache\\regPin" wide
        $string11 = "open=Sys.exe" wide
        $ver1 = "PredatorLogger" wide
        $ver2 = "EncryptedCredentials" wide
        $ver3 = "Predator Pain" wide

    condition:
        7 of ($string*) and any of ($ver*)
}

rule Punisher
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Punisher"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "punisher"
        tags = "rat, punisher"

    strings:
        $a = "abccba"
        $b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
        $c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
        $d = "SpyTheSpy" wide ascii
        $e = "wireshark" wide
        $f = "apateDNS" wide
        $g = "abccbaDanabccb"

    condition:
        all of them
}

rule PythoRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PythoRAT"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "pythorat"
        tags = "rat, pythorat"

    strings:
        $a = "TKeylogger"
        $b = "uFileTransfer"
        $c = "TTDownload"
        $d = "SETTINGS"
        $e = "Unknown" wide
        $f = "#@#@#"
        $g = "PluginData"
        $i = "OnPluginMessage"

    condition:
        all of them
}

rule SmallNet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/SmallNet"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "smallnet"
        tags = "rat, smallnet"

    strings:
        $split1 = "!!<3SAFIA<3!!"
        $split2 = "!!ElMattadorDz!!"
        $a1 = "stub_2.Properties"
        $a2 = "stub.exe" wide
        $a3 = "get_CurrentDomain"

    condition:
        ($split1 or $split2) and (all of ($a*))
}

rule SpyGate
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/SpyGate"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "spygate"
        tags = "rat, spygate"

    strings:
        $split = "abccba"
        $a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
        $a2 = "StubX.pdb"
        $a3 = "abccbaDanabccb"
        $b1 = "monikerString" nocase //$b = Version 2.0
        $b2 = "virustotal1"
        $b3 = "get_CurrentDomain"
        $c1 = "shutdowncomputer" wide //$c = Version 2.9
        $c2 = "shutdown -r -t 00" wide
        $c3 = "set cdaudio door closed" wide
        $c4 = "FileManagerSplit" wide
        $c5 = "Chating With >> [~Hacker~]" wide

    condition:
        (all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule Sub7Nation
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Sub7Nation"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "sub7nation"
        tags = "rat, sub7nation"

    strings:
        $a = "EnableLUA /t REG_DWORD /d 0 /f"
        $b = "*A01*"
        $c = "*A02*"
        $d = "*A03*"
        $e = "*A04*"
        $f = "*A05*"
        $g = "*A06*"
        $h = "#@#@#"
        $i = "HostSettings"
        $verSpecific1 = "sevane.tmp"
        $verSpecific2 = "cmd_.bat"
        $verSpecific3 = "a2b7c3d7e4"
        $verSpecific4 = "cmd.dll"

    condition:
        all of them
}

rule unrecom
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/AAR"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "unrecom"
        tags = "rat, unrecom"

    strings:
        $meta = "META-INF"
        $conf = "load/ID"
        $a = "load/JarMain.class"
        $b = "load/MANIFEST.MF"
        $c = "plugins/UnrecomServer.class"

    condition:
        all of them
}

rule Vertex
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Vertex"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "vertex"
        tags = "rat, vertex"

    strings:
        $string1 = "DEFPATH"
        $string2 = "HKNAME"
        $string3 = "HPORT"
        $string4 = "INSTALL"
        $string5 = "IPATH"
        $string6 = "MUTEX"
        $res1 = "PANELPATH"
        $res2 = "ROOTURL"

    condition:
        all of them
}

rule VirusRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/VirusRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "virusrat"
        tags = "rat, virusrat"

    strings:
        $string0 = "virustotal"
        $string1 = "virusscan"
        $string2 = "abccba"
        $string3 = "pronoip"
        $string4 = "streamWebcam"
        $string5 = "DOMAIN_PASSWORD"
        $string6 = "Stub.Form1.resources"
        $string7 = "ftp://{0}@{1}" wide
        $string8 = "SELECT * FROM moz_logins" wide
        $string9 = "SELECT * FROM moz_disabledHosts" wide
        $string10 = "DynDNS\\Updater\\config.dyndns" wide
        $string11 = "|BawaneH|" wide

    condition:
        all of them
}

rule xRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/xRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "xrat"
        tags = "rat, xrat"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule XtremeRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Xtreme"
        family = "xtreme"
        tags = "rat, xtreme"

    strings:
        $a = "XTREME" wide
        $b = "ServerStarted" wide
        $c = "XtremeKeylogger" wide
        $d = "x.html" wide
        $e = "Xtreme RAT" wide

    condition:
        all of them
}

rule winnti
{
    meta:
        author = "S2R2"
        family = "winnti"

    strings:
        $tcp = { 60 62 63 64 }
        $http = { 62 62 63 64 }
        $https = { 63 62 63 64 }

    condition:
        $tcp at (filesize + 196 - uint32(filesize - 4)) or $http at (filesize + 196 - uint32(filesize - 4)) or $https at (filesize + 196 - uint32(filesize - 4))
}
// Copyright (C) 2013 Claudio "nex" Guarnieri

rule vmdetect
{
    meta:
        author = "nex"
        description = "Possibly employs anti-virtualization techniques"

    strings:
        // Binary tricks
        $vmware = {56 4D 58 68}
        $virtualpc = {0F 3F 07 0B}
        $ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        $vmcheckdll = {45 C7 00 01}
        $redpill = {0F 01 0D 00 00 00 00 C3}

        // Random strings
        $vmware1 = "VMXh"
        $vmware2 = "Ven_VMware_" nocase
        $vmware3 = "Prod_VMware_Virtual_" nocase
        $vmware4 = "hgfs.sys" nocase
        $vmware5 = "mhgfs.sys" nocase
        $vmware6 = "prleth.sys" nocase
        $vmware7 = "prlfs.sys" nocase
        $vmware8 = "prlmouse.sys" nocase
        $vmware9 = "prlvideo.sys" nocase
        $vmware10 = "prl_pv32.sys" nocase
        $vmware11 = "vpc-s3.sys" nocase
        $vmware12 = "vmsrvc.sys" nocase
        $vmware13 = "vmx86.sys" nocase
        $vmware14 = "vmnet.sys" nocase
        $vmware15 = "vmicheartbeat" nocase
        $vmware16 = "vmicvss" nocase
        $vmware17 = "vmicshutdown" nocase
        $vmware18 = "vmicexchange" nocase
        $vmware19 = "vmdebug" nocase
        $vmware20 = "vmmouse" nocase
        $vmware21 = "vmtools" nocase
        $vmware22 = "VMMEMCTL" nocase
        $vmware23 = "vmx86" nocase
        $vmware24 = "vmware" nocase
        $virtualpc1 = "vpcbus" nocase
        $virtualpc2 = "vpc-s3" nocase
        $virtualpc3 = "vpcuhub" nocase
        $virtualpc4 = "msvmmouf" nocase
        $xen1 = "xenevtchn" nocase
        $xen2 = "xennet" nocase
        $xen3 = "xennet6" nocase
        $xen4 = "xensvc" nocase
        $xen5 = "xenvdb" nocase
        $xen6 = "XenVMM" nocase
        $virtualbox1 = "VBoxHook.dll" nocase
        $virtualbox2 = "VBoxService" nocase
        $virtualbox3 = "VBoxTray" nocase
        $virtualbox4 = "VBoxMouse" nocase
        $virtualbox5 = "VBoxGuest" nocase
        $virtualbox6 = "VBoxSF" nocase
        $virtualbox7 = "VBoxGuestAdditions" nocase
        $virtualbox8 = "VBOX HARDDISK"  nocase

        // MAC addresses
        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_1c = "000569"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_2c = "005056"
        $vmware_mac_3a = "00-0C-29" nocase
        $vmware_mac_3b = "00:0C:29" nocase
        $vmware_mac_3c = "000C29" nocase
        $vmware_mac_4a = "00-1C-14" nocase
        $vmware_mac_4b = "00:1C:14" nocase
        $vmware_mac_4c = "001C14" nocase
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

    condition:
        any of them
}
rule Windows_Hacktool_Nighthawk_9f3a5abb {
    meta:
        author = "Elastic Security"
        id = "9f3a5abb-b329-44db-af71-d72eae2737ac"
        fingerprint = "ba21edf160113951444dacf7549f288a41ec0bae64064431e8defd8e34f173db"
        creation_date = "2022-11-24"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.Nighthawk"
        reference_sample = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $loader_build_iat0 = { B9 BF BF D1 D5 E8 ?? ?? ?? ?? BA 7C 75 84 91 [3-12] E8 ?? ?? ?? ?? BA 47 FB EB 2B [3-12] E8 ?? ?? ?? ?? BA 42 24 3D 39 [3-12] E8 ?? ?? ?? ?? BA E7 E9 EF EE [3-12] E8 ?? ?? ?? ?? BA 47 FD 36 2E [3-12] E8 ?? ?? ?? ?? BA 39 DE 19 3D [3-12] E8 ?? ?? ?? ?? BA 20 DF DB F7 [3-12] E8 ?? ?? ?? ?? BA 45 34 2A 41 [3-12] E8 ?? ?? ?? ?? BA 7D 1C 44 2E [3-12] E8 ?? ?? ?? ?? BA 7D 28 44 2E [3-12] E8 ?? ?? ?? ?? BA 94 36 65 8D [3-12] E8 ?? ?? ?? ?? }
        $loader_syscall_func = { 65 48 8B 04 25 30 00 00 00 48 8B 80 10 01 00 00 48 89 44 24 F0 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA FF 64 24 F0 }
    condition:
        $loader_build_iat0 and $loader_syscall_func
}

rule Windows_Hacktool_Nighthawk_2a2e3b9d {
    meta:
        author = "Elastic Security"
        id = "2a2e3b9d-e85f-43b6-9754-1aa7c9f6f978"
        fingerprint = "40912e8d6bd09754046598b1311080e0ec6e040cb1b9ca93003c6314725d4d45"
        creation_date = "2022-11-24"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.Nighthawk"
        reference_sample = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $payload_bytes1 = { 66 C1 E0 05 66 33 D0 66 C1 E2 0A 66 0B D1 0F B7 D2 8B CA 0F B7 C2 C1 E9 02 33 CA 66 D1 E8 D1 E9 33 CA C1 E9 02 33 CA C1 E2 0F 83 E1 01 }
        $payload_bytes2 = { 48 8B D9 44 8B C2 41 C1 E0 0F 8B C2 F7 D0 48 8B F2 44 03 C0 41 8B C0 C1 E8 0C 41 33 C0 8D 04 80 8B C8 C1 E9 04 33 C8 44 69 C1 09 08 00 00 41 8B C0 C1 E8 10 44 33 C0 B8 85 1C A7 AA }
    condition:
        any of them
}

rule HKTL_NimPlant_Jan23_1 {
   meta:
      description = "Detects Nimplant C2 implants (simple rule)"
      author = "Florian Roth"
      reference = "https://github.com/chvancooten/NimPlant"
      date = "2023-01-30"
      score = 85
      hash1 = "3410755c6e83913c2cbf36f4e8e2475e8a9ba60dd6b8a3d25f2f1aaf7c06f0d4"
      hash2 = "b810a41c9bfb435fe237f969bfa83b245bb4a1956509761aacc4bd7ef88acea9"
      hash3 = "c9e48ba9b034e0f2043e13f950dd5b12903a4006155d6b5a456877822f9432f2"
      hash4 = "f70a3d43ae3e079ca062010e803a11d0dcc7dd2afb8466497b3e8582a70be02d"
   strings:
      $x1 = "NimPlant.dll" ascii fullword
      $x2 = "NimPlant v" ascii

      $a1 = "base64.nim" ascii fullword
      $a2 = "zippy.nim" ascii fullword
      $a3 = "whoami.nim" ascii fullword

      $sa1 = "getLocalAdm" ascii fullword 
      $sa2 = "getAv" ascii fullword
      $sa3 = "getPositionImpl" ascii fullword
   condition:
      ( 
         1 of ($x*) and 2 of ($a*)
      ) 
      or ( 
         all of ($a*) and all of ($s*) 
      )
      or 5 of them
}
rule win_shadowpad_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.shadowpad."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowpad"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 84c9 7409 43 8a0c18 80f92e 75f3 }
            // n = 6, score = 200
            //   84c9                 | test                cl, cl
            //   7409                 | je                  0xb
            //   43                   | inc                 ebx
            //   8a0c18               | mov                 cl, byte ptr [eax + ebx]
            //   80f92e               | cmp                 cl, 0x2e
            //   75f3                 | jne                 0xfffffff5

        $sequence_1 = { 750c 891e 395e08 7e03 895e08 33c0 }
            // n = 6, score = 200
            //   750c                 | jne                 0xe
            //   891e                 | mov                 dword ptr [esi], ebx
            //   395e08               | cmp                 dword ptr [esi + 8], ebx
            //   7e03                 | jle                 5
            //   895e08               | mov                 dword ptr [esi + 8], ebx
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 895df4 895df0 885df8 e8???????? 8d45f8 }
            // n = 5, score = 200
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   885df8               | mov                 byte ptr [ebp - 8], bl
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_3 = { 6a00 8bf0 e8???????? 53 50 ff15???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 8975dc 8975e4 8975e0 e8???????? ff75e4 8b7dd8 8b4508 }
            // n = 7, score = 200
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   e8????????           |                     
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   8b7dd8               | mov                 edi, dword ptr [ebp - 0x28]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_5 = { 53 8d85dcfbffff 50 889ddffbffff }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   8d85dcfbffff         | lea                 eax, [ebp - 0x424]
            //   50                   | push                eax
            //   889ddffbffff         | mov                 byte ptr [ebp - 0x421], bl

        $sequence_6 = { c3 55 8bec 83ec10 56 33c9 33f6 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   56                   | push                esi
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi

        $sequence_7 = { e8???????? 57 8d4c2410 51 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   57                   | push                edi
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   51                   | push                ecx

        $sequence_8 = { 8bfe 8d45e8 895de8 895dec 895df4 895df0 885df8 }
            // n = 7, score = 200
            //   8bfe                 | mov                 edi, esi
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   885df8               | mov                 byte ptr [ebp - 8], bl

        $sequence_9 = { 51 8d45e0 e8???????? 8b06 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]

    condition:
        7 of them and filesize < 188416
}
rule asyncrat {
  meta:
    author = "Paul Melson @pmelson"
    descriptuon = "AsyncRAT (aka NYAN) .NET RAT"
    hashes = "b40486b43cf193b26509e85cfebd0891,c3c5114e9ba59f5031bec7251c530b26,003560f0ee0324f8892eb1fd4ba61d23"
  strings:
    $plain_async = "AysncRAT" wide
    $plain_extfmt = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
    $plain_sc2 = "\\root\\SecurityCenter2" wide
    $plain_av = "Select * from AntivirusProduct" wide
    $b64regex_00 = /[A-Za-z0-9\/\-\=]{88}/ wide
    $b64regex_01 = /[A-Za-z0-9\/\-\=]{108}/ wide
  condition:
    uint16(0) == 0x5a4d and 
    any of ($plain*) and 
    any of ($b64*)
}
rule win_meterpreter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.meterpreter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 55 8bec dcec 088b55895356 108b3a85ff89 7dfc 750e }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   dcec                 | fsub                st(4), st(0)
            //   088b55895356         | or                  byte ptr [ebx + 0x56538955], cl
            //   108b3a85ff89         | adc                 byte ptr [ebx - 0x76007ac6], cl
            //   7dfc                 | jge                 0xfffffffe
            //   750e                 | jne                 0x10

        $sequence_1 = { 66833800 7508 6683780200 7406 }
            // n = 4, score = 200
            //   66833800             | cmp                 word ptr [eax], 0
            //   7508                 | jne                 0xa
            //   6683780200           | cmp                 word ptr [eax + 2], 0
            //   7406                 | je                  8

        $sequence_2 = { 56 e8???????? 85d9 f5 }
            // n = 4, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   85d9                 | test                ecx, ebx
            //   f5                   | cmc                 

        $sequence_3 = { e70c 8b4339 b273 1466 83780f00 }
            // n = 5, score = 200
            //   e70c                 | out                 0xc, eax
            //   8b4339               | mov                 eax, dword ptr [ebx + 0x39]
            //   b273                 | mov                 dl, 0x73
            //   1466                 | adc                 al, 0x66
            //   83780f00             | cmp                 dword ptr [eax + 0xf], 0

        $sequence_4 = { 0884c9751c8b4e 50 89487c 8b4672 8b5754 822000 0000 }
            // n = 7, score = 200
            //   0884c9751c8b4e       | or                  byte ptr [ecx + ecx*8 + 0x4e8b1c75], al
            //   50                   | push                eax
            //   89487c               | mov                 dword ptr [eax + 0x7c], ecx
            //   8b4672               | mov                 eax, dword ptr [esi + 0x72]
            //   8b5754               | mov                 edx, dword ptr [edi + 0x54]
            //   822000               | and                 byte ptr [eax], 0
            //   0000                 | add                 byte ptr [eax], al

        $sequence_5 = { 83c4c4 2bf0 8931 5e be9be55dc3 }
            // n = 5, score = 200
            //   83c4c4               | add                 esp, -0x3c
            //   2bf0                 | sub                 esi, eax
            //   8931                 | mov                 dword ptr [ecx], esi
            //   5e                   | pop                 esi
            //   be9be55dc3           | mov                 esi, 0xc35de59b

        $sequence_6 = { 37 f9 40 45 }
            // n = 4, score = 200
            //   37                   | aaa                 
            //   f9                   | stc                 
            //   40                   | inc                 eax
            //   45                   | inc                 ebp

        $sequence_7 = { 624dc9 75c7 85c0 7406 }
            // n = 4, score = 200
            //   624dc9               | bound               ecx, qword ptr [ebp - 0x37]
            //   75c7                 | jne                 0xffffffc9
            //   85c0                 | test                eax, eax
            //   7406                 | je                  8

        $sequence_8 = { 5d c20800 44 e70c 8b4339 b273 }
            // n = 6, score = 200
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   44                   | inc                 esp
            //   e70c                 | out                 0xc, eax
            //   8b4339               | mov                 eax, dword ptr [ebx + 0x39]
            //   b273                 | mov                 dl, 0x73

        $sequence_9 = { 8bd0 8bfe 83c9ff 338183c408f2 ae f7d1 }
            // n = 6, score = 200
            //   8bd0                 | mov                 edx, eax
            //   8bfe                 | mov                 edi, esi
            //   83c9ff               | or                  ecx, 0xffffffff
            //   338183c408f2         | xor                 eax, dword ptr [ecx - 0xdf73b7d]
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

    condition:
        7 of them and filesize < 188416
}
rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14

{

	meta:

		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"

		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

  // Decoder function for the embedded payload

	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }



	condition:
		any of them
}



rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2

{

	meta:

		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"

		hash =  "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		89 ??           mov     eax, ecx

		B? 04 00 00 00  mov     edi, 4

		99              cdq

		F7 FF           idiv    edi

		8B [2]          mov     edi, [ebp+arg_8]

		8A [2]          mov     al, [edi+edx]

		30 ??           xor     [ebx], al

		8A ??           mov     al, [ebx]

		4?              inc     ebx

		88 [2]          mov     [esi+ecx], al

	*/



	$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }

	condition:

		all of them

}



rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"

		hash =  "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		C7 [3] 5C 00 00 00  mov     dword ptr [esp+28h], 5Ch ; '\'

		C7 [3] 65 00 00 00  mov     dword ptr [esp+24h], 65h ; 'e'

		C7 [3] 70 00 00 00  mov     dword ptr [esp+20h], 70h ; 'p'

		C7 [3] 69 00 00 00  mov     dword ptr [esp+1Ch], 69h ; 'i'

		C7 [3] 70 00 00 00  mov     dword ptr [esp+18h], 70h ; 'p'

		F7 F1               div     ecx

		C7 [3] 5C 00 00 00  mov     dword ptr [esp+14h], 5Ch ; '\'

		C7 [3] 2E 00 00 00  mov     dword ptr [esp+10h], 2Eh ; '.'

		C7 [3] 5C 00 00 00  mov     dword ptr [esp+0Ch], 5Ch ; '\'

	*/



	$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }

  $fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

		

	condition:

		all of them

}





rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14

{

	meta:

		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"

		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		8B [2]   mov     eax, [ebp+var_C]

		89 ??    mov     ecx, eax

		03 [2]   add     ecx, [ebp+lpBuffer]

		8B [2]   mov     eax, [ebp+var_C]

		03 [2]   add     eax, [ebp+lpBuffer]

		0F B6 18 movzx   ebx, byte ptr [eax]

		8B [2]   mov     eax, [ebp+var_C]

		89 ??    mov     edx, eax

		C1 [2]   sar     edx, 1Fh

		C1 [2]   shr     edx, 1Eh

		01 ??    add     eax, edx

		83 [2]   and     eax, 3

		29 ??    sub     eax, edx

		03 [2]   add     eax, [ebp+arg_8]

		0F B6 00 movzx   eax, byte ptr [eax]

		31 ??    xor     eax, ebx

		88 ??    mov     [ecx], al

	*/



	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }

	

	condition:

		any of them

}



rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x

{

	meta:

		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"

		hash =  "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		89 ??           mov     eax, ecx

		B? 04 00 00 00  mov     edi, 4

		99              cdq

		F7 FF           idiv    edi

		8B [2]          mov     edi, [ebp+var_20]

		8A [2]          mov     al, [edi+edx]

		30 [2]          xor     [ebx+ecx], al

	*/



	$decoderFunc  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }



	condition:

		$decoderFunc

}





rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14

{

	meta:

		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"

		hash =  "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		8B [2]      mov     eax, [rbp+var_4]

		48 98       cdqe

		48 89 C1    mov     rcx, rax

		48 03 4D 10 add     rcx, [rbp+arg_0]

		8B 45 FC    mov     eax, [rbp+var_4]

		48 98       cdqe

		48 03 45 10 add     rax, [rbp+arg_0]

		44 0F B6 00 movzx   r8d, byte ptr [rax]

		8B 45 FC    mov     eax, [rbp+var_4]

		89 C2       mov     edx, eax

		C1 FA 1F    sar     edx, 1Fh

		C1 EA 1E    shr     edx, 1Eh

		01 D0       add     eax, edx

		83 E0 03    and     eax, 3

		29 D0       sub     eax, edx

		48 98       cdqe

		48 03 45 20 add     rax, [rbp+arg_10]

		0F B6 00    movzx   eax, byte ptr [rax]

		44 31 C0    xor     eax, r8d

		88 01       mov     [rcx], al

	*/



	$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }

		

	condition:

		$a

}



rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0

{

	meta:

		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"

		hash =  "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 C0                xor     eax, eax

		EB 0F                jmp     short loc_6BAC16B5

		41 83 E1 03          and     r9d, 3

		47 8A 0C 08          mov     r9b, [r8+r9]

		44 30 0C 01          xor     [rcx+rax], r9b

		48 FF C0             inc     rax

		39 D0                cmp     eax, edx

		41 89 C1             mov     r9d, eax

		7C EA                jl      short loc_6BAC16A6

		4C 8D 05 53 29 00 00 lea     r8, aRundll32Exe; "rundll32.exe"

		E9 D1 FE FF FF       jmp     sub_6BAC1599

	*/



	$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }



	condition:

		$decoderFunction

}



rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"

		hash =  "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		41 B8 5C 00 00 00       mov     r8d, 5Ch ; '\'

		C7 44 24 50 5C 00 00 00 mov     [rsp+68h+var_18], 5Ch ; '\'

		C7 44 24 48 65 00 00 00 mov     [rsp+68h+var_20], 65h ; 'e'

		C7 44 24 40 70 00 00 00 mov     [rsp+68h+var_28], 70h ; 'p'

		C7 44 24 38 69 00 00 00 mov     [rsp+68h+var_30], 69h ; 'i'

		C7 44 24 30 70 00 00 00 mov     [rsp+68h+var_38], 70h ; 'p'

		C7 44 24 28 5C 00 00 00 mov     dword ptr [rsp+68h+lpThreadId], 5Ch ; '\'

		C7 44 24 20 2E 00 00 00 mov     [rsp+68h+dwCreationFlags], 2Eh ; '.'

		89 54 24 58             mov     [rsp+68h+var_10], edx

		48 8D 15 22 38 00 00    lea     rdx, Format; Format

		E8 0D 17 00 00          call    sprintf

	*/



	$fmtBuilder = {

			41 ?? 5C 00 00 00

			C7 [3] 5C 00 00 00

			C7 [3] 65 00 00 00

			C7 [3] 70 00 00 00

			C7 [3] 69 00 00 00

			C7 [3] 70 00 00 00

			C7 [3] 5C 00 00 00

			C7 [3] 2E 00 00 00

			89 [3]

			48 [6]

			E8

		}



  $fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

		

	condition:

		all of them

}





rule CobaltStrike_Resources_Beacon_Dll_v1_44

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.44"

    hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      0F B7 D2  movzx   edx, dx

      4A        dec     edx; switch 5 cases

      53        push    ebx

      8B D9     mov     ebx, ecx; a2

      83 FA 04  cmp     edx, 4

      77 36     ja      short def_1000106C; jumptable 1000106C default case

      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump

    */

    $version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }

    

    /*

      B1 69          mov     cl, 69h ; 'i'

      30 88 [4]      xor     byte ptr word_10018F20[eax], cl

      40             inc     eax

      3D 28 01 00 00 cmp     eax, 128h

      7C F2          jl      short loc_10001AD4

    */

    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }    

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v1_45

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.45"

    hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      51        push    ecx

      0F B7 D2  movzx   edx, dx

      4A        dec     edx; switch 9 cases

      53        push    ebx

      56        push    esi

      83 FA 08  cmp     edx, 8

      77 6B     ja      short def_1000106C; jumptable 1000106C default case

      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump

    */

    $version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }



    /*

      B1 69          mov     cl, 69h ; 'i'

      30 88 [4]      xor     byte ptr word_10019F20[eax], cl

      40             inc     eax

      3D 28 01 00 00 cmp     eax, 128h

      7C F2          jl      short loc_10002664

    */

    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v1_46

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.46"

    hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      8B F2             mov     esi, edx

      83 F9 0C          cmp     ecx, 0Ch

      0F 87 8E 00 00 00 ja      def_1000107F; jumptable 1000107F default case, case 8

      FF 24 ??          jmp     ds:jpt_1000107F[ecx*4]; switch jump

    */   

    $version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }



    /*

      B1 69          mov     cl, 69h ; 'i'

      30 88 [4]      xor     byte ptr word_1001D040[eax], cl

      40             inc     eax

      3D A8 01 00 00 cmp     eax, 1A8h

      7C F2          jl      short loc_10002A04

    */

    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v1_47

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.47"

    hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      83 F8 12  cmp     eax, 12h

      77 10     ja      short def_100010BB; jumptable 100010BB default case, case 8

      FF 24 ??  jmp     ds:jpt_100010BB[eax*4]; switch jump

    */

    $version_sig = { 83 F8 12 77 10 FF 24 }



    /*

      B1 69          mov     cl, 69h ; 'i'

      30 88 [4]      xor     byte ptr word_1001E040[eax], cl

      40             inc     eax

      3D A8 01 00 00 cmp     eax, 1A8h

    */

    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v1_48

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.48"

    hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48        dec     eax; switch 24 cases

      57        push    edi

      8B F1     mov     esi, ecx

      8B DA     mov     ebx, edx

      83 F8 17  cmp     eax, 17h

      77 12     ja      short def_1000115D; jumptable 1000115D default case, case 8

      FF 24 ??  jmp     ds:jpt_1000115D[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }

    

    /*

      B1 69          mov     cl, 69h ; 'i'

      30 88 [4]      xor     byte ptr word_1001F048[eax], cl

      40             inc     eax

      3D A8 01 00 00 cmp     eax, 1A8h

      7C F2          jl      short loc_100047B4

    */

    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v1_49

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 1.49"

    hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                   dec     eax; switch 31 cases

      56                   push    esi

      83 F8 1E             cmp     eax, 1Eh

      0F 87 23 01 00 00    ja      def_1000115B; jumptable 1000115B default case, cases 8,30

      FF 24 85 80 12 00 10 jmp     ds:jpt_1000115B[eax*4]; switch jump

    */

    $version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }

    

    /*

      B1 69            mov     cl, 69h ; 'i'

      90               nop

      30 88 [4]        xor     byte ptr word_10022038[eax], cl

      40               inc     eax

      3D A8 01 00 00   cmp     eax, 1A8h

      7C F2            jl      short loc_10005940

    */    

    $decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }

      

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v2_0_49

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"

    hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      83 F8 22          cmp     eax, 22h

      0F 87 96 01 00 00 ja      def_1000115D; jumptable 1000115D default case, cases 8,30

      FF 24 ??          jmp     ds:jpt_1000115D[eax*4]; switch jump

    */

    $version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }



    /*

      B1 69            mov     cl, 69h ; 'i'

      EB 03            jmp     short loc_10006930

      8D 49 00         lea     ecx, [ecx+0]

      30 88 [4]        xor     byte ptr word_10023038[eax], cl

      40               inc     eax

      3D 30 05 00 00   cmp     eax, 530h

      72 F2            jb      short loc_10006930

    */

    $decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2

{

  // v2.1 and v2.2 use the exact same beacon binary (matching hashes)

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"

    hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      49                dec     ecx; switch 37 cases

      56                push    esi

      57                push    edi

      83 F9 24          cmp     ecx, 24h

      0F 87 8A 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30

      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump

    */

    $version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v2_3

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 2.3"

    hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      49                dec     ecx; switch 39 cases

      56                push    esi

      57                push    edi

      83 F9 26          cmp     ecx, 26h

      0F 87 A9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30

      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump

    */

    $version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v2_4

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 2.4"

    hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      4A                dec     edx; switch 48 cases

      56                push    esi

      57                push    edi

      83 FA 2F          cmp     edx, 2Fh

      0F 87 F9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 6-8,30

      FF 24 ??          jmp     ds:jpt_1000112E[edx*4]; switch jump

    */

    $version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v2_5

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 2.5"

    hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 59 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 3A          cmp     eax, 3Ah

      0F 87 6E 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30

      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_0

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.0"

    hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 61 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 3C          cmp     eax, 3Ch

      0F 87 89 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30

      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_1

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.1"

    hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  // v3.1 and v3.2 share the same C2 handler code. We are using a function that

  // is not included in v3.2 to mark the v3.1 version along with the decoder

  // which allows us to narrow in on only v3.1 samples

  strings:

    /*

      55             push    ebp

      8B EC          mov     ebp, esp

      83 EC 58       sub     esp, 58h

      A1 [4]         mov     eax, ___security_cookie

      33 C5          xor     eax, ebp

      89 45 FC       mov     [ebp+var_4], eax

      E8 DF F5 FF FF call    sub_10002109

      6A 50          push    50h ; 'P'; namelen

      8D 45 A8       lea     eax, [ebp+name]

      50             push    eax; name

      FF 15 [4]      call    ds:gethostname

      8D 45 ??       lea     eax, [ebp+name]

      50             push    eax; name

      FF 15 [4]      call    ds:__imp_gethostbyname

      85 C0          test    eax, eax

      74 14          jz      short loc_10002B58

      8B 40 0C       mov     eax, [eax+0Ch]

      83 38 00       cmp     dword ptr [eax], 0

      74 0C          jz      short loc_10002B58

      8B 00          mov     eax, [eax]

      FF 30          push    dword ptr [eax]; in

      FF 15 [4]      call    ds:inet_ntoa

      EB 05          jmp     short loc_10002B5D

      B8 [4]         mov     eax, offset aUnknown; "unknown"

      8B 4D FC       mov     ecx, [ebp+var_4]

      33 CD          xor     ecx, ebp; StackCookie

      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)

      C9             leave

    */

    $version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_2

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"

    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"

    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 62 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 3D          cmp     eax, 3Dh

      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30

      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig

    // as a negating condition to diff between 3.1 and 3.2

    /*

      55             push    ebp

      8B EC          mov     ebp, esp

      83 EC 58       sub     esp, 58h

      A1 [4]         mov     eax, ___security_cookie

      33 C5          xor     eax, ebp

      89 45 FC       mov     [ebp+var_4], eax

      E8 DF F5 FF FF call    sub_10002109

      6A 50          push    50h ; 'P'; namelen

      8D 45 A8       lea     eax, [ebp+name]

      50             push    eax; name

      FF 15 [4]      call    ds:gethostname

      8D 45 ??       lea     eax, [ebp+name]

      50             push    eax; name

      FF 15 [4]      call    ds:__imp_gethostbyname

      85 C0          test    eax, eax

      74 14          jz      short loc_10002B58

      8B 40 0C       mov     eax, [eax+0Ch]

      83 38 00       cmp     dword ptr [eax], 0

      74 0C          jz      short loc_10002B58

      8B 00          mov     eax, [eax]

      FF 30          push    dword ptr [eax]; in

      FF 15 [4]      call    ds:inet_ntoa

      EB 05          jmp     short loc_10002B5D

      B8 [4]         mov     eax, offset aUnknown; "unknown"

      8B 4D FC       mov     ecx, [ebp+var_4]

      33 CD          xor     ecx, ebp; StackCookie

      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)

      C9             leave

    */

    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }



  condition:

    $version_sig and $decoder and not $version3_1_sig

}



rule CobaltStrike_Resources_Beacon_Dll_v3_3

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.3"

    hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 66 cases

      57                push    edi

      8B F1             mov     esi, ecx

      83 F8 41          cmp     eax, 41h

      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,30

      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h

      40             inc     eax

      3D 10 06 00 00 cmp     eax, 610h

      72 F1          jb      short loc_1000674A

    */

    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_4

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.4"

    hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 67 cases

      57                push    edi

      8B F1             mov     esi, ecx

      83 F8 42          cmp     eax, 42h

      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30

      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1

{

  // Version 3.5-hf1 and 3.5.1 use the exact same beacon binary (same hash)

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"

    hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 68 cases

      57                push    edi

      8B F1             mov     esi, ecx

      83 F8 43          cmp     eax, 43h

      0F 87 07 03 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30

      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_6

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.6"

    hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 72 cases

      57                push    edi

      8B F9             mov     edi, ecx

      83 F8 47          cmp     eax, 47h

      0F 87 2F 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30

      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_7

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.7"

    hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 74 cases

      57                push    edi

      8B F9             mov     edi, ecx

      83 F8 49          cmp     eax, 49h

      0F 87 47 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30

      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump

    */   

    $version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_8

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.8"

    hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 76 cases

      57                push    edi

      8B F9             mov     edi, ecx

      83 F8 4B          cmp     eax, 4Bh

      0F 87 5D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30

      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



    // XMRig uses a v3.8 sample to trick sandboxes into running their code. 

    // These samples are the same and useless. This string removes many

    // of them from our detection

    $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"

    // To remove others, we look for known xmrig C2 domains in the config:

    $c2_1 = "ns7.softline.top" xor

    $c2_2 = "ns8.softline.top" xor

    $c2_3 = "ns9.softline.top" xor

    //$a = /[A-Za-z]{1020}.{4}$/

    

  condition:

    $version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)

}



/*



  missing specific signatures for 3.9 and 3.10 since we don't have samples



*/



rule CobaltStrike_Resources_Beacon_Dll_v3_11

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.11"

    hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  // Original version from April 9, 2018

  strings:

    /*

      48                dec     eax; switch 81 cases

      57                push    edi

      8B FA             mov     edi, edx

      83 F8 50          cmp     eax, 50h

      0F 87 11 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36

      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"

    hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"

    rs2 ="4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  // Covers both 3.11 (bug fix form May 25, 2018) and v3.12

  strings:

    /*

      48                dec     eax; switch 81 cases

      57                push    edi

      8B FA             mov     edi, edx

      83 F8 50          cmp     eax, 50h

      0F 87 0D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36

      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_13

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.13"

    hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      4A                dec     edx; switch 91 cases

      56                push    esi

      57                push    edi

      83 FA 5A          cmp     edx, 5Ah

      0F 87 2D 03 00 00 ja      def_10008D01; jumptable 10008D01 default case, cases 2,6-8,20,21,26,30,36,63-66

      FF 24 ??          jmp     ds:jpt_10008D01[edx*4]; switch jump

    */

    $version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_Dll_v3_14

{

  meta:

    description = "Cobalt Strike's resources/beacon.dll Versions 3.14"

    hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"

    rs2 ="87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      83 FA 5B  cmp     edx, 5Bh

      77 15     ja      short def_1000939E; jumptable 1000939E default case, cases 2,6-8,20,21,26,30,36,63-66

      FF 24 ??  jmp     ds:jpt_1000939E[edx*4]; switch jump

    */

    $version_sig = { 83 FA 5B 77 15 FF 24 }



    /*

      80 B0 [4] 69   xor     byte_1002E020[eax], 69h

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10008741

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"

    hash =  "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      51                   push    ecx

      4A                   dec     edx; switch 99 cases

      56                   push    esi

      57                   push    edi

      83 FA 62             cmp     edx, 62h

      0F 87 8F 03 00 00    ja      def_100077C3; jumptable 100077C3 default case, cases 2,6-8,20,21,25,26,30,34-36,63-66

      FF 24 95 56 7B 00 10 jmp     ds:jpt_100077C3[edx*4]; switch jump

    */



    $version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }



    /*

      80 B0 20 00 03 10 ??  xor     byte_10030020[eax], 2Eh

      40                    inc     eax

      3D 00 10 00 00        cmp     eax, 1000h

      7C F1                 jl      short loc_1000912B

    */



    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"

    hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"

    rs2 ="9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 100 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 63          cmp     eax, 63h

      0F 87 3C 03 00 00 ja      def_10007F28; jumptable 10007F28 default case, cases 2,6-8,20,21,25,26,29,30,34-36,58,63-66,80,81,95-97

      FF 24 ??          jmp     ds:jpt_10007F28[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }



    /*

      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10009791

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"

    hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"

    rs2 ="78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      48                dec     eax; switch 102 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 65          cmp     eax, 65h

      0F 87 47 03 00 00 ja      def_10007EAD; jumptable 10007EAD default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97

      FF 24 ??          jmp     ds:jpt_10007EAD[eax*4]; switch jump

    */

    $version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }



    /*

      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_10009791

    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"

    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:



    /*

      53                push    ebx

      56                push    esi

      48                dec     eax; switch 104 cases

      57                push    edi

      8B F2             mov     esi, edx

      83 F8 67          cmp     eax, 67h

      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97

    */

    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }



    /*

      80 B0 [5]      xor     byte_10033020[eax], 2Eh

      40             inc     eax

      3D 00 10 00 00 cmp     eax, 1000h

      7C F1          jl      short loc_1000ADA1

    */



    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



/*



 64-bit Beacons.

 

 These signatures are a bit different. The decoders are all identical in the 4.x

 series and the command processor doesn't use a switch/case idiom, but rather

 an expanded set of if/then/else branches. This invalidates our method for

 detecting the versions of the beacons by looking at the case count check

 used by the 32-bit versions. As such, we are locking in on "random",

 non-overlapping between version, sections of code in the command processor. 

 While a reasonable method is to look for blocks of Jcc which will have specific

 address offsets per version, this generally is insufficient due to the lack of 

 code changes. As such, the best method appears to be to look for specific

 function call offsets



 NOTE: There are only VERY subtle differences between the following versions:

  * 3.2 and 3.3

  * 3.4 and 3.5-hf1/3.5.1

  * 3.12, 3.13 and 3.14

  * 4.3 and 4.4-4.6 . 

  

 Be very careful if you modify the $version_sig field for either of those rules. 

*/





rule CobaltStrike_Resources_Beacon_x64_v3_2

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"

    hash =  "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      4C 8D 05 9F F8 FF FF lea     r8, sub_18000C4B0

      8B D3                mov     edx, ebx

      48 8B CF             mov     rcx, rdi

      E8 05 1A 00 00       call    sub_18000E620

      EB 0A                jmp     short loc_18000CC27

      8B D3                mov     edx, ebx

      48 8B CF             mov     rcx, rdi

      E8 41 21 00 00       call    sub_18000ED68

      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]

      48 83 C4 20          add     rsp, 20h

    */



    $version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00

                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30

                     48 83 C4 20 }

    

    /*

      80 31 ??          xor     byte ptr [rcx], 69h

      FF C2             inc     edx

      48 FF C1          inc     rcx

      48 63 C2          movsxd  rax, edx

      48 3D 10 06 00 00 cmp     rax, 610h

    */



    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_3

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"

    hash =  "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      8B D3                mov     edx, ebx

      48 8B CF             mov     rcx, rdi

      E8 89 66 00 00       call    sub_1800155E8

      E9 23 FB FF FF       jmp     loc_18000EA87

      41 B8 01 00 00 00    mov     r8d, 1

      E9 F3 FD FF FF       jmp     loc_18000ED62

      48 8D 0D 2A F8 FF FF lea     rcx, sub_18000E7A0

      E8 8D 2B 00 00       call    sub_180011B08

      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]

      48 83 C4 20          add     rsp, 20h

    */



    $version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 

                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF

                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }



    /*

      80 31 ??          xor     byte ptr [rcx], 69h

      FF C2             inc     edx

      48 FF C1          inc     rcx

      48 63 C2          movsxd  rax, edx

      48 3D 10 06 00 00 cmp     rax, 610h

    */



    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_4

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"

    hash =  "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      8B D3             mov     edx, ebx

      48 8B CF          mov     rcx, rdi

      E8 56 6F 00 00    call    sub_180014458

      E9 17 FB FF FF    jmp     loc_18000D01E

      41 B8 01 00 00 00 mov     r8d, 1

      8B D3             mov     edx, ebx

      48 8B CF          mov     rcx, rdi

      E8 41 4D 00 00    call    sub_180012258

      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]

      48 83 C4 20       add     rsp, 20h

    */

    $version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF

                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00

                     48 8B 5C 24 30 48 83 C4 20 }



    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_18001600E

    */

    

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"

    hash =  "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      8B D3             mov     edx, ebx

      48 8B CF          mov     rcx, rdi

      E8 38 70 00 00    call    sub_180014548

      E9 FD FA FF FF    jmp     loc_18000D012

      41 B8 01 00 00 00 mov     r8d, 1

      8B D3             mov     edx, ebx

      48 8B CF          mov     rcx, rdi

      E8 3F 4D 00 00    call    sub_180012264

      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]

      48 83 C4 20       add     rsp, 20h

      5F                pop     rdi

    */



    $version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 

                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 

                     48 8B 5C 24 30 48 83 C4 20 5F }



    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180016B3E

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_6

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"

    hash =  "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      48 89 5C 24 08    mov     [rsp+arg_0], rbx

      57                push    rdi

      48 83 EC 20       sub     rsp, 20h

      41 8B D8          mov     ebx, r8d

      48 8B FA          mov     rdi, rdx

      83 F9 27          cmp     ecx, 27h ; '''

      0F 87 47 03 00 00 ja      loc_18000D110

      0F 84 30 03 00 00 jz      loc_18000D0FF

      83 F9 14          cmp     ecx, 14h

      0F 87 A4 01 00 00 ja      loc_18000CF7C

      0F 84 7A 01 00 00 jz      loc_18000CF58

      83 F9 0C          cmp     ecx, 0Ch

      0F 87 C8 00 00 00 ja      loc_18000CEAF

      0F 84 B3 00 00 00 jz      loc_18000CEA0

    */

    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27

                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14

                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C

                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }



    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180016B3E

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_7

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"

    hash =  "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      48 89 5C 24 08    mov     [rsp+arg_0], rbx

      57                push    rdi

      48 83 EC 20       sub     rsp, 20h

      41 8B D8          mov     ebx, r8d

      48 8B FA          mov     rdi, rdx

      83 F9 28          cmp     ecx, 28h ; '('

      0F 87 7F 03 00 00 ja      loc_18000D148

      0F 84 67 03 00 00 jz      loc_18000D136

      83 F9 15          cmp     ecx, 15h

      0F 87 DB 01 00 00 ja      loc_18000CFB3

      0F 84 BF 01 00 00 jz      loc_18000CF9D

    */



    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28

                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15

                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }



    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180016ECA

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_8

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"

    hash =  "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      8B D3          mov     edx, ebx

      48 8B CF       mov     rcx, rdi

      E8 7A 52 00 00 call    sub_18001269C

      EB 0D          jmp     short loc_18000D431

      45 33 C0       xor     r8d, r8d

      8B D3          mov     edx, ebx

      48 8B CF       mov     rcx, rdi; Src

      E8 8F 55 00 00 call    sub_1800129C0

    */



    $version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF

                     E8 8F 55 00 00 }

    

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_18001772E

    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_11

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"

    hash =  "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"

    rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

	

    /*

      48 83 EC 20       sub     rsp, 20h

      41 8B D8          mov     ebx, r8d

      48 8B FA          mov     rdi, rdx

      83 F9 2D          cmp     ecx, 2Dh ; '-'

      0F 87 B2 03 00 00 ja      loc_18000D1EF

      0F 84 90 03 00 00 jz      loc_18000D1D3

      83 F9 17          cmp     ecx, 17h

      0F 87 F8 01 00 00 ja      loc_18000D044

      0F 84 DC 01 00 00 jz      loc_18000D02E

      83 F9 0E          cmp     ecx, 0Eh

      0F 87 F9 00 00 00 ja      loc_18000CF54

      0F 84 DD 00 00 00 jz      loc_18000CF3E

      FF C9             dec     ecx

      0F 84 C0 00 00 00 jz      loc_18000CF29

      83 E9 02          sub     ecx, 2

      0F 84 A6 00 00 00 jz      loc_18000CF18

      FF C9             dec     ecx

    */



    $version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00

                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00

                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00

                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02

                     0F 84 A6 00 00 00 FF C9 }

    

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180017DCA

    */



    $decoder = {

      80 34 28 ?? 

      48 FF C0

      48 3D 00 10 00 00

      7C F1

    }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_12

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"

    hash =  "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      8B D3          mov     edx, ebx

      48 8B CF       mov     rcx, rdi

      E8 F8 2E 00 00 call    sub_180010384

      EB 16          jmp     short loc_18000D4A4

      8B D3          mov     edx, ebx

      48 8B CF       mov     rcx, rdi

      E8 00 5C 00 00 call    f_OTH__Command_75

      EB 0A          jmp     short loc_18000D4A4

      8B D3          mov     edx, ebx

      48 8B CF       mov     rcx, rdi

      E8 64 4F 00 00 call    f_OTH__Command_74

    */

    $version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF

                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }

    

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180018205

    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}





rule CobaltStrike_Resources_Beacon_x64_v3_13

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"

    hash =  "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      48 8D 0D 01 5B FF FF lea     rcx, f_NET__ExfiltrateData

      48 83 C4 28          add     rsp, 28h

      E9 A8 54 FF FF       jmp     f_OTH__Command_85

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10; lpSrc

      E8 22 55 FF FF       call    f_OTH__Command_84

    */



    $version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0

                     49 8B CA E8 22 55 FF FF }

      

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180018C01

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Beacon_x64_v3_14

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"

    hash =  "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"

    rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:



    /*

      8B D0          mov     edx, eax

      49 8B CA       mov     rcx, r10; Src

      48 83 C4 28    add     rsp, 28h

      E9 B1 1F 00 00 jmp     f_OTH__Command_69

      8B D0          mov     edx, eax

      49 8B CA       mov     rcx, r10; Source

      48 83 C4 28    add     rsp, 28h

    */



    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA

                     48 83 C4 28 }

    

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 69h

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_1800196BD

    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}





rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"

    hash =  "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      41 B8 01 00 00 00    mov     r8d, 1

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10

      48 83 C4 28          add     rsp, 28h

      E9 D1 B3 FF FF       jmp     sub_180010C5C

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10

      48 83 C4 28          add     rsp, 28h

      E9 AF F5 FF FF       jmp     f_UNK__Command_92__ChangeFlag

      45 33 C0             xor     r8d, r8d

      4C 8D 0D 8D 70 FF FF lea     r9, sub_18000C930

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10

      E8 9B B0 FF FF       call    f_OTH__Command_91__WrapInjection

    */



    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF

                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0

                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"

    hash =  "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      83 F9 34          cmp     ecx, 34h ; '4'

      0F 87 8E 03 00 00 ja      loc_180016259

      0F 84 7A 03 00 00 jz      loc_18001624B

      83 F9 1C          cmp     ecx, 1Ch

      0F 87 E6 01 00 00 ja      loc_1800160C0

      0F 84 D7 01 00 00 jz      loc_1800160B7

      83 F9 0E          cmp     ecx, 0Eh

      0F 87 E9 00 00 00 ja      loc_180015FD2

      0F 84 CE 00 00 00 jz      loc_180015FBD

      FF C9             dec     ecx

      0F 84 B8 00 00 00 jz      loc_180015FAF

      83 E9 02          sub     ecx, 2

      0F 84 9F 00 00 00 jz      loc_180015F9F

      FF C9             dec     ecx

    */



    $version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00

                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9

                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }





    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_x64_v4_3

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"

    hash =  "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

  

    /*

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10; Source

      48 83 C4 28          add     rsp, 28h

      E9 D3 88 FF FF       jmp     f_OTH__CommandAbove_10

      4C 8D 05 84 6E FF FF lea     r8, f_NET__ExfiltrateData

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10

      48 83 C4 28          add     rsp, 28h

    */



    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF

                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }

  

    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_1800186E1

    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}





rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"

    hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:

    /*

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10; Source

      48 83 C4 28          add     rsp, 28h

      E9 83 88 FF FF       jmp     f_OTH__CommandAbove_10

      4C 8D 05 A4 6D FF FF lea     r8, f_NET__ExfiltrateData

      8B D0                mov     edx, eax

      49 8B CA             mov     rcx, r10

      48 83 C4 28          add     rsp, 28h

    */



    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF

                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }



    /*

      80 34 28 2E       xor     byte ptr [rax+rbp], 2Eh

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_1800184D9

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }



  condition:

    all of them

}



rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant

{

  meta:

    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"

    hash =  "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      41 B8 01 00 00 00 mov     r8d, 1

      8B D0             mov     edx, eax

      49 8B CA          mov     rcx, r10

      48 83 C4 28       add     rsp, 28h

      E9 E8 AB FF FF    jmp     sub_1800115A4

      8B D0             mov     edx, eax

      49 8B CA          mov     rcx, r10

      E8 1A EB FF FF    call    f_UNK__Command_92__ChangeFlag

      48 83 C4 28       add     rsp, 28h

    */

    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF

                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }



    /*

      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh

      48 FF C0          inc     rax

      48 3D 00 10 00 00 cmp     rax, 1000h

      7C F1             jl      short loc_180018E1F

    */



    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

    

  condition:

    all of them

}





rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"

		hash =  "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		48 31 C0       xor     rax, rax

		AC             lodsb

		41 C1 C9 0D    ror     r9d, 0Dh

		41 01 C1       add     r9d, eax

		38 E0          cmp     al, ah

		75 F1          jnz     short loc_100000000000007D

		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]

		45 39 D1       cmp     r9d, r10d

		75 D8          jnz     short loc_100000000000006E

		58             pop     rax

		44 8B 40 24    mov     r8d, [rax+24h]

		49 01 D0       add     r8, rdx

		66 41 8B 0C 48 mov     cx, [r8+rcx*2]

		44 8B 40 1C    mov     r8d, [rax+1Ch]

		49 01 D0       add     r8, rdx

		41 8B 04 88    mov     eax, [r8+rcx*4]

		48 01 D0       add     rax, rdx

	*/



	$apiLocator = {

			48 [2]

			AC

			41 [2] 0D

			41 [2]

			38 ??

			75 ??

			4C [4]

			45 [2]

			75 ??

			5?

			44 [2] 24

			49 [2]

			66 [4]

			44 [2] 1C

			49 [2]

			41 [3]

			48 

		}





  // the signature for reverse64 and bind really differ slightly, here we are using the inclusion of additional calls

  // found in bind64 to differentate between this and reverse64

  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,

  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be

  // unchanged. This means we can use these values as anchors in our signature.

	/*

		41 BA C2 DB 37 67 mov     r10d, bind

		FF D5             call    rbp

		48 31 D2          xor     rdx, rdx

		48 89 F9          mov     rcx, rdi

		41 BA B7 E9 38 FF mov     r10d, listen

		FF D5             call    rbp

		4D 31 C0          xor     r8, r8

		48 31 D2          xor     rdx, rdx

		48 89 F9          mov     rcx, rdi

		41 BA 74 EC 3B E1 mov     r10d, accept

		FF D5             call    rbp

		48 89 F9          mov     rcx, rdi

		48 89 C7          mov     rdi, rax

		41 BA 75 6E 4D 61 mov     r10d, closesocket

	*/



	$calls = {

			41 BA C2 DB 37 67

			FF D5

			48 [2]

			48 [2]

			41 BA B7 E9 38 FF

			FF D5

			4D [2]

			48 [2]

			48 [2]

			41 BA 74 EC 3B E1

			FF D5

			48 [2]

			48 [2]

			41 BA 75 6E 4D 61

		}

		

	condition:

		$apiLocator and $calls

}





rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"

		hash =  "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



    // the signature for the stagers overlap significantly. Looking for bind.bin specific bytes helps delineate sample types

	/*

		5D             pop     ebp

		68 33 32 00 00 push    '23'

		68 77 73 32 5F push    '_2sw'

	*/



	$ws2_32 = {

			5D

			68 33 32 00 00

			68 77 73 32 5F

		}



  // bind.bin, unlike reverse.bin, listens for incoming connections. Using the API hashes for listen and accept is a solid

  // approach to finding bind.bin specific samples

	/*

		5?             push    ebx

		5?             push    edi

		68 B7 E9 38 FF push    listen

		FF ??          call    ebp

		5?             push    ebx

		5?             push    ebx

		5?             push    edi

		68 74 EC 3B E1 push    accept

	*/

	$listenaccept = {

			5? 

			5? 

			68 B7 E9 38 FF

			FF ?? 

			5? 

			5? 

			5? 

			68 74 EC 3B E1

		}

	

	condition:

		$apiLocator and $ws2_32 and $listenaccept

}





rule  CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"

		hash =  "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		FF [1-5]        call    ds:recv               // earlier versions (v1.x to 2.x) this is CALL EBP

		83 ?? FF        cmp     eax, 0FFFFFFFFh

		74 ??           jz      short loc_100020D5

		85 C0           test    eax, eax

		(74  | 76) ??   jz      short loc_100020D5    // earlier versions (v1.x to 2.x) used jbe (76) here

		03 ??           add     esi, eax

		83 ?? 02        cmp     esi, 2

		72 ??           jb      short loc_100020D1

		80 ?? 3E FF 0A  cmp     byte ptr [esi+edi-1], 0Ah

		75 ??           jnz     short loc_100020D1

		80 ?? 3E FE 0D  cmp     byte ptr [esi+edi-2], 0Dh

	*/



	$socket_recv = {

			FF [1-5]

			83 ?? FF 

			74 ?? 

			85 C0

			(74 | 76) ?? 

			03 ?? 

			83 ?? 02 

			72 ?? 

			80 ?? 3E FF 0A 

			75 ?? 

			80 ?? 3E FE 0D 

		}

		

  // distinctive regex (sscanf) format string

  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"



	condition:

		all of them

}



rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"

		hash =  "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		FF 15 [4]         call    cs:recv

		83 ?? FF          cmp     eax, 0FFFFFFFFh

		74 ??             jz      short loc_1800018FB

		85 ??             test    eax, eax

		74 ??             jz      short loc_1800018FB

		03 ??             add     ebx, eax

		83 ?? 02          cmp     ebx, 2

		72 ??             jb      short loc_1800018F7

		8D ?? FF          lea     eax, [rbx-1]

		80 [2] 0A         cmp     byte ptr [rax+rdi], 0Ah

		75 ??             jnz     short loc_1800018F7

		8D ?? FE          lea     eax, [rbx-2]

		80 [2] 0D         cmp     byte ptr [rax+rdi], 0Dh

	*/



	$socket_recv = {

			FF 15 [4]

			83 ?? FF

			74 ??

			85 ??

			74 ??

			03 ??

			83 ?? 02

			72 ??

			8D ?? FF

			80 [2] 0A

			75 ??

			8D ?? FE

			80 [2] 0D

		}



  // distinctive regex (sscanf) format string

  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

		

	condition:

		all of them

}





rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"

		hash =  "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		A1 [4]    mov     eax, fileop

		6A 00     push    0

		8B ??     mov     ecx, [eax]

		5?        push    edx

		5?        push    eax

		FF ?? 48  call    dword ptr [ecx+48h]

		85 ??     test    eax, eax

		75 ??     jnz     short loc_10001177

		A1 [4]    mov     eax, fileop

		5?        push    eax

		8B ??     mov     ecx, [eax]

		FF ?? 54  call    dword ptr [ecx+54h]

	*/



	$deleteFileCOM = {

			A1 [4]

			6A 00

			8B ?? 

			5? 

			5? 

			FF ?? 48 

			85 ?? 

			75 ?? 

			A1 [4]

			5? 

			8B ?? 

			FF ?? 54 

		}



	/*

		A1 [4]    mov     eax, fileop

		6A 00     push    0

		FF ?? 08  push    [ebp+copyName]

		8B ??     mov     ecx, [eax]

		FF [5]    push    dstFile

		FF [5]    push    srcFile

		5?        push    eax

		FF ?? 40  call    dword ptr [ecx+40h]

		85 ??     test    eax, eax

		75 ??     jnz     short loc_10001026  // this line can also be 0F 85 <32-bit offset>

		A1 [4]    mov     eax, fileop

		5?        push    eax

		8B ??     mov     ecx, [eax]

		FF ?? 54  call    dword ptr [ecx+54h]

	*/



	$copyFileCOM = {

			A1 [4]

			6A 00

			FF [2]

			8B ?? 

			FF [5]

			FF [5]

			5? 

			FF ?? 40 

			85 ?? 

			[2 - 6]

			A1 [4]

			5? 

			8B ?? 

			FF ?? 54 

		}

		

				

	condition:

		all of them

}





rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x

{

	meta:

		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"

		hash =  "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		48 8B 0D 07 A4 01 00 mov     rcx, cs:fileop

		45 33 C0             xor     r8d, r8d

		48 8B 01             mov     rax, [rcx]

		FF 90 90 00 00 00    call    qword ptr [rax+90h]

		85 C0                test    eax, eax

		75 D9                jnz     short loc_180001022

		48 8B 0D F0 A3 01 00 mov     rcx, cs:fileop

		48 8B 11             mov     rdx, [rcx]

		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]

		85 C0                test    eax, eax

	*/



	$deleteFileCOM = {

			48 8B [5]

			45 33 ??

			48 8B ??

			FF 90 90 00 00 00

			85 C0

			75 ??

			48 8B [5]

			48 8B ??

			FF 92 A8 00 00 00

			85 C0

		}	

	

	

	/*

		48 8B 0D 32 A3 01 00 mov     rcx, cs:fileop

		4C 8B 05 3B A3 01 00 mov     r8, cs:dstFile

		48 8B 15 2C A3 01 00 mov     rdx, cs:srcFile

		48 8B 01             mov     rax, [rcx]

		4C 8B CD             mov     r9, rbp

		48 89 5C 24 20       mov     [rsp+38h+var_18], rbx

		FF 90 80 00 00 00    call    qword ptr [rax+80h]

		85 C0                test    eax, eax

		0F 85 7B FF FF FF    jnz     loc_1800010B0

		48 8B 0D 04 A3 01 00 mov     rcx, cs:fileop

		48 8B 11             mov     rdx, [rcx]

		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]

	*/



	$copyFileCOM = {

			48 8B [5]

			4C 8B [5]

			48 8B [5]

			48 8B ??

			4C 8B ??

			48 89 [3]

			FF 90 80 00 00 00

			85 C0

			0F 85 [4]

			48 8B [5]

			48 8B 11

			FF 92 A8 00 00 00

		}



	condition:

		all of them

}





rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14

{

	meta:

		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"

		hash =  "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		5?                 push    eax; ReturnLength

		5?                 push    edi; TokenInformationLength

		5?                 push    edi; TokenInformation

		8B ??              mov     ebx, ecx

		6A 19              push    19h; TokenInformationClass

		5?                 push    ebx; TokenHandle

		FF 15 [4]          call    ds:GetTokenInformation

		85 C0              test    eax, eax

		75 ??              jnz     short loc_10001100

		FF 15 [4]          call    ds:GetLastError

		83 ?? 7A           cmp     eax, 7Ah ; 'z'

		75 ??              jnz     short loc_10001100

		FF [2]             push    [ebp+ReturnLength]; uBytes

		5?                 push    edi; uFlags

		FF 15 [4]          call    ds:LocalAlloc

		8B ??              mov     esi, eax

		8D [2]             lea     eax, [ebp+ReturnLength]

		5?                 push    eax; ReturnLength

		FF [2]             push    [ebp+ReturnLength]; TokenInformationLength

		5?                 push    esi; TokenInformation

		6A 19              push    19h; TokenInformationClass

		5?                 push    ebx; TokenHandle

		FF 15 [4]          call    ds:GetTokenInformation

		85 C0              test    eax, eax

		74 ??              jz      short loc_10001103

		FF ??              push    dword ptr [esi]; pSid

		FF 15 [4]          call    ds:GetSidSubAuthorityCount

		8A ??              mov     al, [eax]

		FE C8              dec     al

		0F B6 C0           movzx   eax, al

		5?                 push    eax; nSubAuthority

		FF ??              push    dword ptr [esi]; pSid

		FF 15 [4]          call    ds:GetSidSubAuthority

		B? 01 00 00 00     mov     ecx, 1

		5?                 push    esi; hMem

		81 ?? 00 30 00 00  cmp     dword ptr [eax], 3000h

	*/



	$isHighIntegrityProcess = {

			5? 

			5? 

			5? 

			8B ?? 

			6A 19

			5? 

			FF 15 [4]

			85 C0

			75 ?? 

			FF 15 [4]

			83 ?? 7A 

			75 ?? 

			FF [2]

			5? 

			FF 15 [4]

			8B ?? 

			8D [2]

			5? 

			FF [2]

			5? 

			6A 19

			5? 

			FF 15 [4]

			85 C0

			74 ?? 

			FF ?? 

			FF 15 [4]

			8A ?? 

			FE C8

			0F B6 C0

			5? 

			FF ?? 

			FF 15 [4]

			B? 01 00 00 00 

			5? 

			81 ?? 00 30 00 00 

		}



	/*

		6A 3C               push    3Ch ; '<'; Size

		8D ?? C4            lea     eax, [ebp+pExecInfo]

		8B ??               mov     edi, edx

		6A 00               push    0; Val

		5?                  push    eax; void *

		8B ??               mov     esi, ecx

		E8 [4]              call    _memset

		83 C4 0C            add     esp, 0Ch

		C7 [2] 3C 00 00 00  mov     [ebp+pExecInfo.cbSize], 3Ch ; '<'

		8D [2]              lea     eax, [ebp+pExecInfo]

		C7 [2] 40 00 00 00  mov     [ebp+pExecInfo.fMask], 40h ; '@'

		C7 [6]              mov     [ebp+pExecInfo.lpFile], offset aTaskmgrExe; "taskmgr.exe"

		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpParameters], 0

		5?                  push    eax; pExecInfo

		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpDirectory], 0

		C7 [6]              mov     [ebp+pExecInfo.lpVerb], offset aRunas; "runas"

		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.nShow], 0

		FF 15 [4]           call    ds:ShellExecuteExW

		FF 75 FC            push    [ebp+pExecInfo.hProcess]; Process

	*/



	$executeTaskmgr = {

			6A 3C

			8D ?? C4 

			8B ?? 

			6A 00

			5? 

			8B ?? 

			E8 [4]

			83 C4 0C

			C7 [2] 3C 00 00 00 

			8D [2]

			C7 [2] 40 00 00 00 

			C7 [6]

			C7 [2] 00 00 00 00 

			5? 

			C7 [2] 00 00 00 00 

			C7 [6]

			C7 [2] 00 00 00 00 

			FF 15 [4]

			FF 75 FC

		}

		

	condition:

		all of them

}



rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14

{

	meta:

		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"

		hash =  "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		83 F8 7A          cmp     eax, 7Ah ; 'z'

		75 59             jnz     short loc_1800014BC

		8B 54 24 48       mov     edx, dword ptr [rsp+38h+uBytes]; uBytes

		33 C9             xor     ecx, ecx; uFlags

		FF 15 49 9C 00 00 call    cs:LocalAlloc

		44 8B 4C 24 48    mov     r9d, dword ptr [rsp+38h+uBytes]; TokenInformationLength

		8D 53 19          lea     edx, [rbx+19h]; TokenInformationClass

		48 8B F8          mov     rdi, rax

		48 8D 44 24 48    lea     rax, [rsp+38h+uBytes]

		48 8B CE          mov     rcx, rsi; TokenHandle

		4C 8B C7          mov     r8, rdi; TokenInformation

		48 89 44 24 20    mov     [rsp+38h+ReturnLength], rax; ReturnLength

		FF 15 B0 9B 00 00 call    cs:GetTokenInformation

		85 C0             test    eax, eax

		74 2D             jz      short loc_1800014C1

		48 8B 0F          mov     rcx, [rdi]; pSid

		FF 15 AB 9B 00 00 call    cs:GetSidSubAuthorityCount

		8D 73 01          lea     esi, [rbx+1]

		8A 08             mov     cl, [rax]

		40 2A CE          sub     cl, sil

		0F B6 D1          movzx   edx, cl; nSubAuthority

		48 8B 0F          mov     rcx, [rdi]; pSid

		FF 15 9F 9B 00 00 call    cs:GetSidSubAuthority

		81 38 00 30 00 00 cmp     dword ptr [rax], 3000h

	*/



	$isHighIntegrityProcess = {

			83 ?? 7A

			75 ??

			8B [3]

			33 ??

			FF 15 [4]

			44 [4]

			8D [2]

			48 8B ??

			48 8D [3]

			48 8B ??

			4C 8B ??

			48 89 [3]

			FF 15 [4]

			85 C0

			74 ??

			48 8B ??

			FF 15 [4]

			8D [2]

			8A ??

			40 [2]

			0F B6 D1

			48 8B 0F

			FF 15 [4]

			81 ?? 00 30 00 00

		}



	/*

		44 8D 42 70             lea     r8d, [rdx+70h]; Size

		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; void *

		E8 2E 07 00 00          call    memset

		83 64 24 50 00          and     [rsp+98h+pExecInfo.nShow], 0

		48 8D 05 E2 9B 00 00    lea     rax, aTaskmgrExe; "taskmgr.exe"

		0F 57 C0                xorps   xmm0, xmm0

		66 0F 7F 44 24 40       movdqa  xmmword ptr [rsp+98h+pExecInfo.lpParameters], xmm0

		48 89 44 24 38          mov     [rsp+98h+pExecInfo.lpFile], rax

		48 8D 05 E5 9B 00 00    lea     rax, aRunas; "runas"

		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; pExecInfo

		C7 44 24 20 70 00 00 00 mov     [rsp+98h+pExecInfo.cbSize], 70h ; 'p'

		C7 44 24 24 40 00 00 00 mov     [rsp+98h+pExecInfo.fMask], 40h ; '@'

		48 89 44 24 30          mov     [rsp+98h+pExecInfo.lpVerb], rax

		FF 15 05 9B 00 00       call    cs:ShellExecuteExW

	*/



	$executeTaskmgr = {

			44 8D ?? 70

			48 8D [3]

			E8 [4]

			83 [3] 00

			48 8D [5]

			0F 57 ??

			66 0F 7F [3]

			48 89 [3]

			48 8D [5]

			48 8D [3]

			C7 [3] 70 00 00 00

			C7 [3] 40 00 00 00

			48 89 [3]

			FF 15 

		}





	condition:

		all of them

}





rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"

		hash =  "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



  strings:		

    // the command.ps1 and compress.ps1 are the same file. Between v3.7 and v3.8 the file was renamed from command to compress.

    $ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase

    $ps2 ="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase

  

  condition:

    all of them

}



rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"

		hash =  "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		5?                  push    esi

		68 [4]              push    offset ProcName; "IsWow64Process"

		68 [4]              push    offset ModuleName; "kernel32"

		C7 [3-5] 00 00 00 00  mov     [ebp+var_9C], 0                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x

		FF 15 [4]           call    ds:GetModuleHandleA

		50                  push    eax; hModule

		FF 15 [4]           call    ds:GetProcAddress

		8B ??               mov     esi, eax

		85 ??               test    esi, esi

		74 ??               jz      short loc_1000298B

		8D [3-5]            lea     eax, [ebp+var_9C]                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x

		5?                  push    eax

		FF 15 [4]           call    ds:GetCurrentProcess

		50                  push    eax

	*/



	$dropComponentsAndActivateDriver_prologue = {

			5? 

			68 [4]

			68 [4]

			C7 [3-5] 00 00 00 00 

			FF 15 [4]

			50

			FF 15 [4]

			8B ?? 

			85 ?? 

			74 ??

			8D [3-5]

			5? 

			FF 15 [4]

			50

		}



	/*

		6A 00          push    0; AccessMode

		5?             push    esi; FileName

		E8 [4]         call    __access

		83 C4 08       add     esp, 8

		83 F8 FF       cmp     eax, 0FFFFFFFFh

		74 ??          jz      short loc_100028A7

		5?             push    esi

		68 [4]         push    offset aWarningSExists; "Warning: %s exists\n"   // this may not exist in v2.x samples

		E8 [4]         call    nullsub_1

		83 C4 08       add     esp, 8             // if the push doesnt exist, then this is 04, not 08

		// v2.x has a PUSH ESI here... so we need to skip that

		6A 00          push    0; hTemplateFile

		68 80 01 00 00 push    180h; dwFlagsAndAttributes

		6A 02          push    2; dwCreationDisposition

		6A 00          push    0; lpSecurityAttributes

		6A 05          push    5; dwShareMode

		68 00 00 00 40 push    40000000h; dwDesiredAccess

		5?             push    esi; lpFileName

		FF 15 [4]      call    ds:CreateFileA

		8B ??          mov     edi, eax

		83 ?? FF       cmp     edi, 0FFFFFFFFh

		75 ??          jnz     short loc_100028E2

		FF 15 [4]      call    ds:GetLastError

		5?             push    eax

	*/



	$dropFile = {

			6A 00

			5? 

			E8 [4]

			83 C4 08

			83 F8 FF

			74 ?? 

			5? 

			[0-5]

			E8 [4]

			83 C4 ??

			[0-2]

			6A 00

			68 80 01 00 00

			6A 02

			6A 00

			6A 05

			68 00 00 00 40

			5? 

			FF 15 [4]

			8B ?? 

			83 ?? FF 

			75 ?? 

			FF 15 [4]

			5? 

		}

	

	$nfp = "npf.sys" nocase

	$wpcap = "wpcap.dll" nocase



	condition:

		all of them

}



rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49

{

	meta:

		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"

		hash =  "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		C7 04 24 [4]    mov     dword ptr [esp], offset aKernel32; "kernel32"

		E8 [4]          call    GetModuleHandleA

		83 EC 04        sub     esp, 4

		C7 44 24 04 [4] mov     dword ptr [esp+4], offset aIswow64process; "IsWow64Process"

		89 04 24        mov     [esp], eax; hModule

		E8 59 14 00 00  call    GetProcAddress

		83 EC 08        sub     esp, 8

		89 45 ??        mov     [ebp+var_C], eax

		83 7D ?? 00     cmp     [ebp+var_C], 0

		74 ??           jz      short loc_4019BA

		E8 [4]          call    GetCurrentProcess

		8D [2]          lea     edx, [ebp+fIs64bit]

		89 [3]          mov     [esp+4], edx

		89 04 24        mov     [esp], eax

	*/



	$dropComponentsAndActivateDriver_prologue = {

			C7 04 24 [4]

			E8 [4]

			83 EC 04

			C7 44 24 04 [4]

			89 04 24

			E8 59 14 00 00

			83 EC 08

			89 45 ?? 

			83 7D ?? 00 

			74 ?? 

			E8 [4]

			8D [2]

			89 [3]

			89 04 24

		}



	/*

		C7 44 24 04 00 00 00 00 mov     dword ptr [esp+4], 0; AccessMode

		8B [2]                  mov     eax, [ebp+FileName]

		89 ?? 24                mov     [esp], eax; FileName

		E8 [4]                  call    _access

		83 F8 FF                cmp     eax, 0FFFFFFFFh

		74 ??                   jz      short loc_40176D

		8B [2]                  mov     eax, [ebp+FileName]

		89 ?? 24 04             mov     [esp+4], eax

		C7 04 24 [4]            mov     dword ptr [esp], offset aWarningSExists; "Warning: %s exists\n"

		E8 [4]                  call    log

		E9 [4]                  jmp     locret_401871

		C7 44 24 18 00 00 00 00 mov     dword ptr [esp+18h], 0; hTemplateFile

		C7 44 24 14 80 01 00 00 mov     dword ptr [esp+14h], 180h; dwFlagsAndAttributes

		C7 44 24 10 02 00 00 00 mov     dword ptr [esp+10h], 2; dwCreationDisposition

		C7 44 24 0C 00 00 00 00 mov     dword ptr [esp+0Ch], 0; lpSecurityAttributes

		C7 44 24 08 05 00 00 00 mov     dword ptr [esp+8], 5; dwShareMode

		C7 44 24 04 00 00 00 40 mov     dword ptr [esp+4], 40000000h; dwDesiredAccess

		8B [2]                  mov     eax, [ebp+FileName]

		89 04 24                mov     [esp], eax; lpFileName

		E8 [4]                  call    CreateFileA

		83 EC 1C                sub     esp, 1Ch

		89 45 ??                mov     [ebp+hFile], eax

	*/



	$dropFile = {

			C7 44 24 04 00 00 00 00

			8B [2]

			89 ?? 24 

			E8 [4]

			83 F8 FF

			74 ?? 

			8B [2]

			89 ?? 24 04 

			C7 04 24 [4]

			E8 [4]

			E9 [4]

			C7 44 24 18 00 00 00 00

			C7 44 24 14 80 01 00 00

			C7 44 24 10 02 00 00 00

			C7 44 24 0C 00 00 00 00

			C7 44 24 08 05 00 00 00

			C7 44 24 04 00 00 00 40

			8B [2]

			89 04 24

			E8 [4]

			83 EC 1C

			89 45 ?? 

		}



	$nfp = "npf.sys" nocase

	$wpcap = "wpcap.dll" nocase

			

	condition:

		all of them

}





rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"

		hash =  "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



    // the signature for the stagers overlap significantly. Looking for dnsstager.bin specific bytes helps delineate sample types

	  $dnsapi = { 68 64 6E 73 61 }	

	

	condition:

		$apiLocator and $dnsapi

}





rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x

{

	meta:

		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"

		hash =  "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		6A 00               push    0; lParam

		6A 28               push    28h ; '('; wParam

		68 00 01 00 00      push    100h; Msg

		5?                  push    edi; hWnd

		C7 [5] 01 00 00 00  mov     dword_10017E70, 1

		FF ??               call    esi ; PostMessageA

		6A 00               push    0; lParam

		6A 27               push    27h ; '''; wParam

		68 00 01 00 00      push    100h; Msg

		5?                  push    edi; hWnd

		FF ??               call    esi ; PostMessageA

		6A 00               push    0; lParam

		6A 00               push    0; wParam

		68 01 02 00 00      push    201h; Msg

		5?                  push    edi; hWnd

		FF ??               call    esi ; PostMessageA

	*/



	$wnd_proc = {

			6A 00

			6A 28

			68 00 01 00 00

			5? 

			C7 [5] 01 00 00 00 

			FF ?? 

			6A 00

			6A 27

			68 00 01 00 00

			5? 

			FF ?? 

			6A 00

			6A 00

			68 01 02 00 00

			5? 

			FF ?? 

		}



		

	condition:

		$wnd_proc

}





rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x

{

	meta:

		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"

		hash =  "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		81 FA 21 01 00 00             cmp     edx, 121h

		75 4A                         jnz     short loc_1800017A9

		83 3D 5A 7E 01 00 00          cmp     cs:dword_1800195C0, 0

		75 41                         jnz     short loc_1800017A9

		45 33 C9                      xor     r9d, r9d; lParam

		8D 57 DF                      lea     edx, [rdi-21h]; Msg

		C7 05 48 7E 01 00 01 00 00 00 mov     cs:dword_1800195C0, 1

		45 8D 41 28                   lea     r8d, [r9+28h]; wParam

		FF 15 36 DB 00 00             call    cs:PostMessageA

		45 33 C9                      xor     r9d, r9d; lParam

		8D 57 DF                      lea     edx, [rdi-21h]; Msg

		45 8D 41 27                   lea     r8d, [r9+27h]; wParam

		48 8B CB                      mov     rcx, rbx; hWnd

		FF 15 23 DB 00 00             call    cs:PostMessageA

		45 33 C9                      xor     r9d, r9d; lParam

		45 33 C0                      xor     r8d, r8d; wParam

		BA 01 02 00 00                mov     edx, 201h; Msg

		48 8B CB                      mov     rcx, rbx; hWnd

	*/



	$wnd_proc = {

			81 ?? 21 01 00 00

			75 ??

			83 [5] 00

			75 ??

			45 33 ??

			8D [2]

			C7 [5] 01 00 00 00

			45 [2] 28

			FF 15 [4]

			45 33 ??

			8D [2]

			45 [2] 27

			48 [2]

			FF 15 [4]

			45 33 ??

			45 33 ??

			BA 01 02 00 00

			48 

		}



	condition:

		$wnd_proc

}





rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"

		hash =  "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		48 31 C0       xor     rax, rax

		AC             lodsb

		41 C1 C9 0D    ror     r9d, 0Dh

		41 01 C1       add     r9d, eax

		38 E0          cmp     al, ah

		75 F1          jnz     short loc_100000000000007D

		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]

		45 39 D1       cmp     r9d, r10d

		75 D8          jnz     short loc_100000000000006E

		58             pop     rax

		44 8B 40 24    mov     r8d, [rax+24h]

		49 01 D0       add     r8, rdx

		66 41 8B 0C 48 mov     cx, [r8+rcx*2]

		44 8B 40 1C    mov     r8d, [rax+1Ch]

		49 01 D0       add     r8, rdx

		41 8B 04 88    mov     eax, [r8+rcx*4]

		48 01 D0       add     rax, rdx

	*/



	$apiLocator = {

			48 [2]

			AC

			41 [2] 0D

			41 [2]

			38 ??

			75 ??

			4C [4]

			45 [2]

			75 ??

			5?

			44 [2] 24

			49 [2]

			66 [4]

			44 [2] 1C

			49 [2]

			41 [3]

			48 

		}





  // the signature for httpstager64 and httpsstager64 really only differ by the flags passed to WinInet API

  // and the inclusion of the InternetSetOptionA call. We will trigger off that API

	/*

		BA 1F 00 00 00    mov     edx, 1Fh

		6A 00             push    0

		68 80 33 00 00    push    3380h

		49 89 E0          mov     r8, rsp

		41 B9 04 00 00 00 mov     r9d, 4

		41 BA 75 46 9E 86 mov     r10d, InternetSetOptionA

	*/



	$InternetSetOptionA = {

			BA 1F 00 00 00

			6A 00

			68 80 33 00 00

			49 [2]

			41 ?? 04 00 00 00

			41 ?? 75 46 9E 86

		}	

	

	condition:

		$apiLocator and $InternetSetOptionA

}





rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"

		hash =  "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API

  // and the inclusion of the InternetSetOptionA call. We will trigger off that API

	/*

		6A 04          push    4

		5?             push    eax

		6A 1F          push    1Fh

		5?             push    esi

		68 75 46 9E 86 push    InternetSetOptionA

		FF ??          call    ebp

	*/



	$InternetSetOptionA = {

			6A 04

			5? 

			6A 1F

			5? 

			68 75 46 9E 86

			FF  

		}

	

	condition:

		$apiLocator and $InternetSetOptionA

}





rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"

		hash =  "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		48 31 C0       xor     rax, rax

		AC             lodsb

		41 C1 C9 0D    ror     r9d, 0Dh

		41 01 C1       add     r9d, eax

		38 E0          cmp     al, ah

		75 F1          jnz     short loc_100000000000007D

		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]

		45 39 D1       cmp     r9d, r10d

		75 D8          jnz     short loc_100000000000006E

		58             pop     rax

		44 8B 40 24    mov     r8d, [rax+24h]

		49 01 D0       add     r8, rdx

		66 41 8B 0C 48 mov     cx, [r8+rcx*2]

		44 8B 40 1C    mov     r8d, [rax+1Ch]

		49 01 D0       add     r8, rdx

		41 8B 04 88    mov     eax, [r8+rcx*4]

		48 01 D0       add     rax, rdx

	*/



	$apiLocator = {

			48 [2]

			AC

			41 [2] 0D

			41 [2]

			38 ??

			75 ??

			4C [4]

			45 [2]

			75 ??

			5?

			44 [2] 24

			49 [2]

			66 [4]

			44 [2] 1C

			49 [2]

			41 [3]

			48 

		}





  // the signature for httpstager64 and httpsstager64 really the inclusion or exclusion of InternetSetOptionA. However,

  // there is a subtle difference in the jmp after the InternetOpenA call (short jmp for x86 and long jmp for x64)

	/*

		41 BA 3A 56 79 A7 mov     r10d, InternetOpenA

		FF D5             call    rbp

		EB 61             jmp     short j_get_c2_ip

	*/



	$postInternetOpenJmp = {

			41 ?? 3A 56 79 A7

			FF ??

			EB 

		}



	

	condition:

		$apiLocator and $postInternetOpenJmp

}





rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"

		hash =  "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



  // the signature for httpstager and httpsstager really only differ by the flags passed to WinInet API

  // and the httpstager controls the download loop slightly different than the httpsstager

	/*

		B? 00 2F 00 00  mov     edi, 2F00h

		39 ??           cmp     edi, eax

		74 ??           jz      short loc_100000E9

		31 ??           xor     edi, edi

		E9 [4]          jmp     loc_100002CA      // opcode could also be EB for a short jump (v2.5-v3.10)

	*/



	$downloaderLoop = {

			B? 00 2F 00 00 

			39 ?? 

			74 ?? 

			31 ?? 

			( E9 | EB )

		}



	condition:

		$apiLocator and $downloaderLoop

}





rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"

		hash =  "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		48 31 C0       xor     rax, rax

		AC             lodsb

		41 C1 C9 0D    ror     r9d, 0Dh

		41 01 C1       add     r9d, eax

		38 E0          cmp     al, ah

		75 F1          jnz     short loc_100000000000007D

		4C 03 4C 24 08 add     r9, [rsp+40h+var_38]

		45 39 D1       cmp     r9d, r10d

		75 D8          jnz     short loc_100000000000006E

		58             pop     rax

		44 8B 40 24    mov     r8d, [rax+24h]

		49 01 D0       add     r8, rdx

		66 41 8B 0C 48 mov     cx, [r8+rcx*2]

		44 8B 40 1C    mov     r8d, [rax+1Ch]

		49 01 D0       add     r8, rdx

		41 8B 04 88    mov     eax, [r8+rcx*4]

		48 01 D0       add     rax, rdx

	*/



	$apiLocator = {

			48 [2]

			AC

			41 [2] 0D

			41 [2]

			38 ??

			75 ??

			4C [4]

			45 [2]

			75 ??

			5?

			44 [2] 24

			49 [2]

			66 [4]

			44 [2] 1C

			49 [2]

			41 [3]

			48 

		}





  // the signature for reverse64 and bind really differ slightly, here we are using the lack of additional calls

  // found in reverse64 to differentate between this and bind64

  // Note that we can reasonably assume that the constants being passed to the call rbp will be just that, constant,

  // since we are triggering on the API hasher. If that hasher is unchanged, then the hashes we look for should be

  // unchanged. This means we can use these values as anchors in our signature.

	/*

		41 BA EA 0F DF E0 mov     r10d, WSASocketA

		FF D5             call    rbp

		48 89 C7          mov     rdi, rax

		6A 10             push    10h

		41 58             pop     r8

		4C 89 E2          mov     rdx, r12

		48 89 F9          mov     rcx, rdi

		41 BA 99 A5 74 61 mov     r10d, connect

		FF D5             call    rbp

	*/



	$calls = {

			48 89 C1

			41 BA EA 0F DF E0

			FF D5

			48 [2]

			6A ??

			41 ??

			4C [2]

			48 [2]

			41 BA 99 A5 74 61

			FF D5

		}

	condition:

		$apiLocator and $calls

}





rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"

		hash =  "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



    // the signature for the stagers overlap significantly. Looking for reverse.bin specific bytes helps delineate sample types

	/*

		5D             pop     ebp

		68 33 32 00 00 push    '23'

		68 77 73 32 5F push    '_2sw'

	*/



	$ws2_32 = {

			5D

			68 33 32 00 00

			68 77 73 32 5F

		}





  // reverse.bin makes outbound connection (using connect) while bind.bin listens for incoming connections (using listen)

  // so the presence of the connect API hash is a solid method for distinguishing between the two.

	/*

		6A 10          push    10h

		[0]5?          push    esi

		5?             push    edi

		68 99 A5 74 61 push    connect

	*/

	$connect = {

			6A 10

			5? 

			5? 

			68 99 A5 74 61

		}

	

	condition:

		$apiLocator and $ws2_32 and $connect

}





rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x

{

	meta:

		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"

		hash =  "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	/*

		31 ??     xor     eax, eax

		AC        lodsb

		C1 ?? 0D  ror     edi, 0Dh

		01 ??     add     edi, eax

		38 ??     cmp     al, ah

		75 ??     jnz     short loc_10000054

		03 [2]    add     edi, [ebp-8]

		3B [2]    cmp     edi, [ebp+24h]

		75 ??     jnz     short loc_1000004A

		5?        pop     eax

		8B ?? 24  mov     ebx, [eax+24h]

		01 ??     add     ebx, edx

		66 8B [2] mov     cx, [ebx+ecx*2]

		8B ?? 1C  mov     ebx, [eax+1Ch]

		01 ??     add     ebx, edx

		8B ?? 8B  mov     eax, [ebx+ecx*4]

		01 ??     add     eax, edx

		89 [3]    mov     [esp+28h+var_4], eax

		5?        pop     ebx

		5?        pop     ebx

	*/



	$apiLocator = {

			31 ?? 

			AC

			C1 ?? 0D 

			01 ?? 

			38 ?? 

			75 ?? 

			03 [2]

			3B [2]

			75 ?? 

			5? 

			8B ?? 24 

			01 ?? 

			66 8B [2]

			8B ?? 1C 

			01 ?? 

			8B ?? 8B 

			01 ?? 

			89 [3]

			5? 

			5? 

		}



    // the signature for the stagers overlap significantly. Looking for smbstager.bin specific bytes helps delineate sample types

	  $smb = { 68 C6 96 87 52 }	

	  

	  // This code block helps differentiate between smbstager.bin and metasploit's engine which has reasonable level of overlap

	  	/*

		6A 40          push    40h ; '@'

		68 00 10 00 00 push    1000h

		68 FF FF 07 00 push    7FFFFh

		6A 00          push    0

		68 58 A4 53 E5 push    VirtualAlloc

	*/



	$smbstart = {

			6A 40

			68 00 10 00 00

			68 FF FF 07 00

			6A 00

			68 58 A4 53 E5

		}

	

	condition:

		$apiLocator and $smb and $smbstart

}




rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash =  "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:   
    $arch = "platform.architecture()"
    $nope = "WindowsPE"
    $alloc = "ctypes.windll.kernel32.VirtualAlloc"
    $movemem = "ctypes.windll.kernel32.RtlMoveMemory"
    $thread = "ctypes.windll.kernel32.CreateThread"
    $wait = "ctypes.windll.kernel32.WaitForSingleObject"

  condition:
    all of them
}



rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"

		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"



	strings:

    $scriptletstart = "<scriptlet>" nocase

    $registration = "<registration progid=" nocase

    $classid = "classid=" nocase

		$scriptlang = "<script language=\"vbscript\">" nocase

		$cdata = "<![CDATA["

    $scriptend = "</script>" nocase

	  $antiregistration = "</registration>" nocase

    $scriptletend = "</scriptlet>"



  condition:

    all of them and @scriptletstart[1] < @registration[1] and @registration[1] < @classid[1] and @classid[1] < @scriptlang[1] and @scriptlang[1] < @cdata[1]

}



rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x

{

	meta:

		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"

		hash =  "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	  $ea = "Excel.Application" nocase

    $vis = "Visible = False" nocase

    $wsc = "Wscript.Shell" nocase

    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase

    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase

    $regwrite = ".RegWrite" nocase

    $dw = "REG_DWORD"

    $code = ".CodeModule.AddFromString"

	 /* Hex encoded Auto_*/ /*Open */

    $ao = { 41 75 74 6f 5f 4f 70 65 6e }

    $da = ".DisplayAlerts"



  condition:

    all of them

}


rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
    $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
    $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
    $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
    $paramsGIM = ".GenerateInMemory = $True" nocase
    $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
    //$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    //$64bitSpecific = "[IntPtr]::size -eq 8"
    
    
  condition:
    all of them
}

/*

 *

 * Unless required by applicable law or agreed to in writing, software

 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

 * See the License for the specific language governing permissions and

 * limitations under the License.

 */



rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13

{

	meta:

		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"

		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

    $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase

    $imm = "InMemoryModule" nocase

    $mdt = "MyDelegateType" nocase

    $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase

    $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    $64bitSpecific = "[IntPtr]::size -eq 8"

    $mandatory = "Mandatory = $True"

    

  condition:

    all of them

}



rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash =  "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

	strings:
    $createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
    $allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
    $writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
    $runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
    $vars = "Dim rwxpage As Long" nocase
    $res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
    $rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

  condition:
    all of them and @vars[1] < @res[1] and @allocstuff[1] < @rwxpage[1]
}

/*

 *

 * Unless required by applicable law or agreed to in writing, software

 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

 * See the License for the specific language governing permissions and

 * limitations under the License.

 */



rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x

{

	meta:

		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"

		hash =  "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	  /* The method for making this signatures consists of extracting each stub from the various resources/xor.bin files

	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 

	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been

	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */

    $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}

    $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}



  condition:

    any of them

}







/*

 *

 * Unless required by applicable law or agreed to in writing, software

 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

 * See the License for the specific language governing permissions and

 * limitations under the License.

 */



rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x

{

	meta:

		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"

		hash =  "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

		

	strings:

	  /* The method for making this signatures consists of extracting each stub from the various resources/xor64.bin files

	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 

	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been

	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */



    $stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}

    $stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}

    $stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}

  

  condition:

    any of them

}

 

/*

 *

 * Unless required by applicable law or agreed to in writing, software

 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

 * See the License for the specific language governing permissions and

 * limitations under the License.

 */



rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"

    hash =  "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"

    author = "gssincla@google.com"

    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

    date = "2022-11-18"

   

  strings:

    /*

      C6 45 F0 48 mov     [ebp+var_10], 48h ; 'H'

      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'

      C6 45 F2 61 mov     [ebp+var_E], 61h ; 'a'

      C6 45 F3 70 mov     [ebp+var_D], 70h ; 'p'

      C6 45 F4 41 mov     [ebp+var_C], 41h ; 'A'

      C6 45 F5 6C mov     [ebp+var_B], 6Ch ; 'l'

      C6 45 F6 6C mov     [ebp+var_A], 6Ch ; 'l'

      C6 45 F7 6F mov     [ebp+var_9], 6Fh ; 'o'

      C6 45 F8 63 mov     [ebp+var_8], 63h ; 'c'

      C6 45 F9 00 mov     [ebp+var_7], 0

    */



    $core_sig = {

      C6 45 F0 48

      C6 45 F1 65

      C6 45 F2 61

      C6 45 F3 70

      C6 45 F4 41

      C6 45 F5 6C

      C6 45 F6 6C

      C6 45 F7 6F

      C6 45 F8 63

      C6 45 F9 00

    }



    // These strings can narrow down the specific version

    //$ver_43 = { 9B 2C 3E 60 }         // Version 4.3

    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6

    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"

    hash =  "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"


  strings:

    /*

      C6 45 EC 4D mov     [ebp+var_14], 4Dh ; 'M'

      C6 45 ED 61 mov     [ebp+var_13], 61h ; 'a'

      C6 45 EE 70 mov     [ebp+var_12], 70h ; 'p'

      C6 45 EF 56 mov     [ebp+var_11], 56h ; 'V'

      C6 45 F0 69 mov     [ebp+var_10], 69h ; 'i'

      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'

      C6 45 F2 77 mov     [ebp+var_E], 77h ; 'w'

      C6 45 F3 4F mov     [ebp+var_D], 4Fh ; 'O'

      C6 45 F4 66 mov     [ebp+var_C], 66h ; 'f'

      C6 45 F5 46 mov     [ebp+var_B], 46h ; 'F'

      C6 45 F6 69 mov     [ebp+var_A], 69h ; 'i'

      C6 45 F7 6C mov     [ebp+var_9], 6Ch ; 'l'

      C6 45 F8 65 mov     [ebp+var_8], 65h ; 'e'

      C6 45 F9 00 mov     [ebp+var_7], 0

    */



    $core_sig = {

      C6 45 EC 4D

      C6 45 ED 61

      C6 45 EE 70

      C6 45 EF 56

      C6 45 F0 69

      C6 45 F1 65

      C6 45 F2 77

      C6 45 F3 4F

      C6 45 F4 66

      C6 45 F5 46

      C6 45 F6 69

      C6 45 F7 6C

      C6 45 F8 65

      C6 45 F9 00

    }
    // These strings can narrow down the specific version

    //$ver_43 = { 9C 2C 3E 60 }         // Version 4.3

    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6

  condition:
    all of them
}
rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"

    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'

      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'

      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'

      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'

      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'

      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'

      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'

      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'

      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'

      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'

      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'

      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'

      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0

    */



    $core_sig = {

      C6 45 B0 56

      C6 45 B1 69

      C6 45 B2 72

      C6 45 B3 74

      C6 45 B4 75

      C6 45 B5 61

      C6 45 B6 6C

      C6 45 B7 41

      C6 45 B8 6C

      C6 45 B9 6C

      C6 45 BA 6F

      C6 45 BB 63

      C6 45 BC 00

    }



    /*

      8B 4D FC    mov     ecx, [ebp+var_4]

      83 C1 01    add     ecx, 1

      89 4D FC    mov     [ebp+var_4], ecx

      8B 55 FC    mov     edx, [ebp+var_4]

      3B 55 0C    cmp     edx, [ebp+arg_4]

      73 19       jnb     short loc_231

      0F B6 45 10 movzx   eax, [ebp+arg_8]

      8B 4D 08    mov     ecx, [ebp+arg_0]

      03 4D FC    add     ecx, [ebp+var_4]

      0F BE 11    movsx   edx, byte ptr [ecx]

      33 D0       xor     edx, eax

      8B 45 08    mov     eax, [ebp+arg_0]

      03 45 FC    add     eax, [ebp+var_4]

      88 10       mov     [eax], dl

      EB D6       jmp     short loc_207

    */



    $deobfuscator = {

      8B 4D FC

      83 C1 01

      89 4D FC

      8B 55 FC

      3B 55 0C

      73 19

      0F B6 45 10

      8B 4D 08

      03 4D FC

      0F BE 11

      33 D0

      8B 45 08

      03 45 FC

      88 10

      EB D6

    }

    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"

    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'

      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'

      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'

      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'

      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'

      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'

      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'

      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'

      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'

      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'

      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'

      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'

      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0

    */



    $core_sig = {

      C6 45 B0 56

      C6 45 B1 69

      C6 45 B2 72

      C6 45 B3 74

      C6 45 B4 75

      C6 45 B5 61

      C6 45 B6 6C

      C6 45 B7 41

      C6 45 B8 6C

      C6 45 B9 6C

      C6 45 BA 6F

      C6 45 BB 63

      C6 45 BC 00

    }



    /*

      8B 4D FC    mov     ecx, [ebp+var_4]

      83 C1 01    add     ecx, 1

      89 4D FC    mov     [ebp+var_4], ecx

      8B 55 FC    mov     edx, [ebp+var_4]

      3B 55 0C    cmp     edx, [ebp+arg_4]

      73 19       jnb     short loc_231

      0F B6 45 10 movzx   eax, [ebp+arg_8]

      8B 4D 08    mov     ecx, [ebp+arg_0]

      03 4D FC    add     ecx, [ebp+var_4]

      0F BE 11    movsx   edx, byte ptr [ecx]

      33 D0       xor     edx, eax

      8B 45 08    mov     eax, [ebp+arg_0]

      03 45 FC    add     eax, [ebp+var_4]

      88 10       mov     [eax], dl

      EB D6       jmp     short loc_207

    */



    $deobfuscator = {

      8B 4D FC

      83 C1 01

      89 4D FC

      8B 55 FC

      3B 55 0C

      73 19

      0F B6 45 10

      8B 4D 08

      03 4D FC

      0F BE 11

      33 D0

      8B 45 08

      03 45 FC

      88 10

      EB D6

    }

    

  condition:

    $core_sig and not $deobfuscator

}





// 64-bit BeaconLoaders



rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"

    hash =  "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      C6 44 24 38 48 mov     [rsp+78h+var_40], 48h ; 'H'

      C6 44 24 39 65 mov     [rsp+78h+var_3F], 65h ; 'e'

      C6 44 24 3A 61 mov     [rsp+78h+var_3E], 61h ; 'a'

      C6 44 24 3B 70 mov     [rsp+78h+var_3D], 70h ; 'p'

      C6 44 24 3C 41 mov     [rsp+78h+var_3C], 41h ; 'A'

      C6 44 24 3D 6C mov     [rsp+78h+var_3B], 6Ch ; 'l'

      C6 44 24 3E 6C mov     [rsp+78h+var_3A], 6Ch ; 'l'

      C6 44 24 3F 6F mov     [rsp+78h+var_39], 6Fh ; 'o'

      C6 44 24 40 63 mov     [rsp+78h+var_38], 63h ; 'c'

      C6 44 24 41 00 mov     [rsp+78h+var_37], 0

    */



    $core_sig = {

      C6 44 24 38 48

      C6 44 24 39 65

      C6 44 24 3A 61

      C6 44 24 3B 70

      C6 44 24 3C 41

      C6 44 24 3D 6C

      C6 44 24 3E 6C

      C6 44 24 3F 6F

      C6 44 24 40 63

      C6 44 24 41 00

    }



    // These strings can narrow down the specific version

    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3

    //$ver_44_45_46 = { D1 56 86 5F }   // Versions 4.4, 4.5, and 4.6

    

  condition:

    all of them

}





rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"

    hash =  "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      C6 44 24 58 4D mov     [rsp+98h+var_40], 4Dh ; 'M'

      C6 44 24 59 61 mov     [rsp+98h+var_3F], 61h ; 'a'

      C6 44 24 5A 70 mov     [rsp+98h+var_3E], 70h ; 'p'

      C6 44 24 5B 56 mov     [rsp+98h+var_3D], 56h ; 'V'

      C6 44 24 5C 69 mov     [rsp+98h+var_3C], 69h ; 'i'

      C6 44 24 5D 65 mov     [rsp+98h+var_3B], 65h ; 'e'

      C6 44 24 5E 77 mov     [rsp+98h+var_3A], 77h ; 'w'

      C6 44 24 5F 4F mov     [rsp+98h+var_39], 4Fh ; 'O'

      C6 44 24 60 66 mov     [rsp+98h+var_38], 66h ; 'f'

      C6 44 24 61 46 mov     [rsp+98h+var_37], 46h ; 'F'

      C6 44 24 62 69 mov     [rsp+98h+var_36], 69h ; 'i'

      C6 44 24 63 6C mov     [rsp+98h+var_35], 6Ch ; 'l'

      C6 44 24 64 65 mov     [rsp+98h+var_34], 65h ; 'e'

    */



    $core_sig = {

      C6 44 24 58 4D

      C6 44 24 59 61

      C6 44 24 5A 70

      C6 44 24 5B 56

      C6 44 24 5C 69

      C6 44 24 5D 65

      C6 44 24 5E 77

      C6 44 24 5F 4F

      C6 44 24 60 66

      C6 44 24 61 46

      C6 44 24 62 69

      C6 44 24 63 6C

      C6 44 24 64 65

    }



    // These strings can narrow down the specific version

    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3

    //$ver_44_45_46 = { D2 57 86 5F }   // Versions 4.4, 4.5, and 4.6

    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6

{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"

    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'

      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'

      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'

      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'

      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'

      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'

      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'

      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'

      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'

      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'

      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'

      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'

      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0

    */



    $core_sig = {

      C6 44 24 48 56

      C6 44 24 49 69

      C6 44 24 4A 72

      C6 44 24 4B 74

      C6 44 24 4C 75

      C6 44 24 4D 61

      C6 44 24 4E 6C

      C6 44 24 4F 41

      C6 44 24 50 6C

      C6 44 24 51 6C

      C6 44 24 52 6F

      C6 44 24 53 63

      C6 44 24 54 00

    }





    /*

      8B 04 24       mov     eax, [rsp+18h+var_18]

      FF C0          inc     eax

      89 04 24       mov     [rsp+18h+var_18], eax

      8B 44 24 28    mov     eax, [rsp+18h+arg_8]

      39 04 24       cmp     [rsp+18h+var_18], eax

      73 20          jnb     short loc_2E7

      8B 04 24       mov     eax, [rsp+18h+var_18]

      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]

      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]

      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]

      33 C1          xor     eax, ecx

      8B 0C 24       mov     ecx, [rsp+18h+var_18]

      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]

      88 04 0A       mov     [rdx+rcx], al

    */



    $deobfuscator = {

      8B 04 24

      FF C0

      89 04 24

      8B 44 24 28

      39 04 24

      73 20

      8B 04 24

      0F B6 4C 24 30

      48 8B 54 24 20

      0F BE 04 02

      33 C1

      8B 0C 24

      48 8B 54 24 20

      88 04 0A

    }



    

  condition:

    all of them

}



rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{

  meta:

    description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"

    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"

		author = "gssincla@google.com"

		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"

		date = "2022-11-18"

    

  strings:

    /*

      33 C0                      xor     eax, eax

      83 F8 01                   cmp     eax, 1

      74 63                      jz      short loc_378

      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]

      0F B7 00                   movzx   eax, word ptr [rax]

      3D 4D 5A 00 00             cmp     eax, 5A4Dh

      75 45                      jnz     short loc_369

      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]

      48 63 40 3C                movsxd  rax, dword ptr [rax+3Ch]

      48 89 44 24 28             mov     [rsp+38h+var_10], rax

      48 83 7C 24 28 40          cmp     [rsp+38h+var_10], 40h ; '@'

      72 2F                      jb      short loc_369

      48 81 7C 24 28 00 04 00 00 cmp     [rsp+38h+var_10], 400h

      73 24                      jnb     short loc_369

      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]

      48 8B 4C 24 28             mov     rcx, [rsp+38h+var_10]

      48 03 C8                   add     rcx, rax

      48 8B C1                   mov     rax, rcx

      48 89 44 24 28             mov     [rsp+38h+var_10], rax

      48 8B 44 24 28             mov     rax, [rsp+38h+var_10]

      81 38 50 45 00 00          cmp     dword ptr [rax], 4550h

      75 02                      jnz     short loc_369

    */



    $core_sig = {

      33 C0

      83 F8 01

      74 63

      48 8B 44 24 20

      0F B7 00

      3D 4D 5A 00 00

      75 45

      48 8B 44 24 20

      48 63 40 3C

      48 89 44 24 28

      48 83 7C 24 28 40

      72 2F

      48 81 7C 24 28 00 04 00 00

      73 24

      48 8B 44 24 20

      48 8B 4C 24 28

      48 03 C8

      48 8B C1

      48 89 44 24 28

      48 8B 44 24 28

      81 38 50 45 00 00

      75 02

    }



    /*

      8B 04 24       mov     eax, [rsp+18h+var_18]

      FF C0          inc     eax

      89 04 24       mov     [rsp+18h+var_18], eax

      8B 44 24 28    mov     eax, [rsp+18h+arg_8]

      39 04 24       cmp     [rsp+18h+var_18], eax

      73 20          jnb     short loc_2E7

      8B 04 24       mov     eax, [rsp+18h+var_18]

      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]

      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]

      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]

      33 C1          xor     eax, ecx

      8B 0C 24       mov     ecx, [rsp+18h+var_18]

      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]

      88 04 0A       mov     [rdx+rcx], al

    */



    $deobfuscator = {

      8B 04 24

      FF C0

      89 04 24

      8B 44 24 28

      39 04 24

      73 20

      8B 04 24

      0F B6 4C 24 30

      48 8B 54 24 20

      0F BE 04 02

      33 C1

      8B 0C 24

      48 8B 54 24 20

      88 04 0A

    }



    

  condition:

    $core_sig and not $deobfuscator

}