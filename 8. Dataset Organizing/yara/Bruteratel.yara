import "pe"

rule Adobe_XMP_Identifier
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature identifies Adobe Extensible Metadata Platform (XMP) identifiers embedded within files. Defined as a standard for mapping graphical asset relationships, XMP allows for tracking of both parent-child relationships and individual revisions. There are three categories of identifiers: original document, document, and instance. Generally, XMP data is stored in XML format, updated on save/copy, and embedded within the graphical asset. These identifiers can be used to track both malicious and benign graphics within common Microsoft and Adobe document lures."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://wwwimages.adobe.com/content/dam/acom/en/products/xmp/Pdfs/XMPAssetRelationships.pdf"
        labs_reference = "https://labs.inquest.net/dfi/sha256/1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"
        labs_pivot     = "https://labs.inquest.net/dfi/search/ioc/xmpid/xmp.did%3AEDC9411A6A5F11E2838BB9184F90E845##eyJyZXN1bHRzIjpbIn4iLCJmaXJzdFNlZW4iLDEsIiIsW11dfQ=="
        samples        = "1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"

	strings:
    $xmp_md5  = /xmp\.[dio]id[-: _][a-f0-9]{32}/  nocase ascii wide
    $xmp_guid = /xmp\.[dio]id[-: _][a-f0-9]{36}/ nocase ascii wide
	condition:
			any of them
}

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

rule HKTL_BruteRatel_Badger_Indicators_Oct22_4 {
   meta:
      description = "Detects Brute Ratel C4 badger indicators"
      author = "Matthew @embee_research, Florian Roth"
      reference = "https://twitter.com/embee_research/status/1580030310778953728"
      date = "2022-10-12"
      score = 75
   strings:
      $s1 = { b? 89 4d 39 8c }
      $s2 = { b? bd ca 3b d3 }
      $s3 = { b? b2 c1 06 ae } 
      $s4 = { b? 74 eb 1d 4d }
   condition:
      filesize < 8000KB 
      and all of ($s*)
      and not uint8(0) == 0x02 /* SHC files */
}

rule Windows_Trojan_BruteRatel_1916686d {
    meta:
        author = "Elastic Security"
        id = "1916686d-4821-4e5a-8290-58336d01997f"
        fingerprint = "86304082d3eda2f160465f0af0a3feae1aa9695727520e51f139d951e50d6efc"
        creation_date = "2022-06-23"
        last_modified = "2022-12-01"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[+] Spoofed PPID => %lu" wide fullword
        $a2 = "[-] Child process not set" wide fullword
        $a3 = "[+] Crisis Monitor: Already Running" wide fullword
        $a4 = "[+] Screenshot downloaded: %S" wide fullword
        $a5 = "s[-] Duplicate listener: %S" wide fullword
        $a6 = "%02d%02d%d_%02d%02d%2d%02d.png" wide fullword
        $a7 = "[+] Added Socks Profile" wide fullword
        $a8 = "[+] Dump Size: %d Mb" wide fullword
        $a9 = "[+] Enumerating PID: %lu [%ls]" wide fullword
        $a10 = "[+] Dump Size: %d Mb" wide fullword
        $a11 = "[+] SAM key: " wide fullword
        $a12 = "[+] Token removed: '%ls'" wide fullword
        $a13 = "[Tasks] %02d => 0x%02X 0x%02X" wide fullword
        $b1 = { 48 83 EC ?? 48 8D 35 ?? ?? ?? ?? 4C 63 E2 31 D2 48 8D 7C 24 ?? 48 89 CB 4D 89 E0 4C 89 E5 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 31 F6 BF ?? ?? ?? ?? 39 F5 7E ?? E8 ?? ?? ?? ?? 99 F7 FF 48 63 D2 8A 44 14 ?? 88 04 33 48 FF C6 EB ?? }
    condition:
        4 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_9b267f96 {
    meta:
        author = "Elastic Security"
        id = "9b267f96-11b3-48e6-9d38-ecfd72cb7e3e"
        fingerprint = "f20cbaf39dc68460a2612298a5df9efdf5bdb152159d38f4696aedf35862bbb6"
        creation_date = "2022-06-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "calAllocPH" ascii fullword
        $a2 = "lizeCritPH" ascii fullword
        $a3 = "BadgerPH" ascii fullword
        $a4 = "VirtualPPH" ascii fullword
        $a5 = "TerminatPH" ascii fullword
        $a6 = "ickCountPH" ascii fullword
        $a7 = "SeDebugPH" ascii fullword
        $b1 = { 50 48 B8 E2 6A 15 64 56 22 0D 7E 50 48 B8 18 2C 05 7F BB 78 D7 27 50 48 B8 C9 EC BC 3D 84 54 9A 62 50 48 B8 A1 E1 3C 4E AF 2B F6 B1 50 48 B8 2E E6 7B A0 94 CA 9D F0 50 48 B8 61 52 80 AA 1A B6 4B 0E 50 48 B8 B2 13 11 5A 28 81 ED 60 50 48 B8 20 DE A9 34 89 08 C8 32 50 48 B8 9B DC C1 FF 79 CE 5B F5 50 48 B8 FD 57 3F 4C C7 D3 7A 21 50 48 B8 70 B8 63 0F AB 19 BF 1C 50 48 B8 48 F2 1B 72 1E 2A C6 8A 50 48 B8 E3 FA 38 E9 1D 76 E0 6F 50 48 B8 97 AD 75 }
    condition:
        3 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_684a39f2 {
    meta:
        author = "Elastic Security"
        id = "684a39f2-a110-4553-8d29-9f742e0ca3dc"
        fingerprint = "fef288db141810b01f248a476368946c478a395b1709a982e2f740dd011c6328"
        creation_date = "2023-01-24"
        last_modified = "2023-02-01"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "5f4782a34368bb661f413f33e2d1fb9f237b7f9637f2c0c21dc752316b02350c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 39 DA 0F 82 61 02 00 00 45 8D 48 14 44 39 CA 0F 82 54 02 00 00 41 8D 40 07 46 0F B6 0C 09 44 0F B6 1C 01 42 0F B6 04 11 41 C1 E3 08 41 09 C3 }
        $seq2 = { 45 8A 44 13 F0 44 32 04 01 48 FF C0 45 88 04 13 48 FF C2 48 83 F8 04 75 E7 49 83 C2 04 48 83 C6 04 49 81 FA B0 00 00 00 75 AA 48 83 C4 38 5B 5E C3 }
        $seq3 = { 48 83 EC 18 8A 01 88 04 24 8A 41 05 88 44 24 01 8A 41 0A 88 44 24 02 8A 41 0F 88 44 24 03 8A 41 04 88 44 24 04 8A 41 09 88 44 24 05 8A 41 0E 88 44 24 06 8A 41 03 88 44 24 07 }
        $seq4 = { 42 8A 0C 22 8D 42 ?? 80 F9 ?? 75 ?? 48 98 4C 89 E9 48 29 C1 42 8A 14 20 80 FA ?? 74 ?? 88 14 01 48 FF C0 EB ?? }
        $cfg1 = { 22 00 2C 00 22 00 61 00 72 00 63 00 68 00 22 00 3A 00 22 00 78 00 36 00 34 00 22 00 2C 00 22 00 62 00 6C 00 64 00 22 00 3A 00 22 00 }
        $cfg2 = { 22 00 2C 00 22 00 77 00 76 00 65 00 72 00 22 00 3A 00 22 00 }
        $cfg3 = { 22 00 2C 00 22 00 70 00 69 00 64 00 22 00 3A 00 22 00 }
        $cfg4 = { 22 00 7D 00 2C 00 22 00 6D 00 74 00 64 00 74 00 22 00 3A 00 7B 00 22 00 68 00 5F 00 6E 00 61 00 6D 00 65 00 22 00 3A 00 22 00 }
    condition:
        any of ($seq*) and all of ($cfg*)
}

rule Windows_Trojan_BruteRatel_ade6c9d5 {
    meta:
        author = "Elastic Security"
        id = "ade6c9d5-e9b5-4ef8-bacd-2f050c25f7f6"
        fingerprint = "9a4c5660eeb9158652561cf120e91ea5887841ed71f69e7cf4bfe4cfb11fe74a"
        creation_date = "2023-01-24"
        last_modified = "2023-02-01"
        description = "Targets API hashes used by BruteRatel"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "dc9757c9aa3aff76d86f9f23a3d20a817e48ca3d7294307cc67477177af5c0d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1_NtReadVirtualMemory = { AA A5 EF 3A }
        $c2_NtQuerySystemInformation = { D6 CA E1 E4 }
        $c3_NtCreateFile = { 9D 8F 88 03 }
        $c4_RtlSetCurrentTranscation = { 90 85 A3 99 }
        $c5_LoadLibrary = { 8E 4E 0E EC }
    condition:
        all of them
}

rule Windows_Trojan_BruteRatel_4110d879 {
    meta:
        author = "Elastic Security"
        id = "4110d879-8d36-4004-858d-e62400948920"
        fingerprint = "64d7a121961108d17e03fa767bd5bc194c8654dfa18b3b2f38cf6c95a711f794"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "e0fbbc548fdb9da83a72ddc1040463e37ab6b8b544bf0d2b206bfff352175afe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 04 01 75 E2 48 83 C0 01 44 0F B6 04 02 45 84 C0 75 EC 48 89 }
        $a2 = { C8 48 83 E9 20 44 0F B6 40 E0 41 80 F8 E9 74 0B 44 0F B6 49 03 41 80 }
    condition:
        all of them
}

rule skip20_sqllang_hook
{
    meta:
    author      = "Mathieu Tartare <mathieu.tartare@eset.com>"
    date        = "21-10-2019"
    description = "YARA rule to detect if a sqllang.dll version is targeted by skip-2.0. Each byte pattern corresponds to a function hooked by skip-2.0. If $1_0 or $1_1 match, it is probably targeted as it corresponds to the hook responsible for bypassing the authentication."
    reference   = "https://www.welivesecurity.com/" 
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

    strings:
        $1_0  = {ff f3 55 56 57 41 56 48 81 ec c0 01 00 00 48 c7 44 24 38 fe ff ff ff}
        $1_1  = {48 8b c3 4c 8d 9c 24 a0 00 00 00 49 8b 5b 10 49 8b 6b 18 49 8b 73 20 49 8b 7b 28 49 8b e3 41 5e c3 90 90 90 90 90 90 90 ff 25}
        $2_0  = {ff f3 55 57 41 55 48 83 ec 58 65 48 8b 04 25 30 00 00 00}
        $2_1  = {48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 ff 25}
        $3_0  = {89 4c 24 08 4c 8b dc 49 89 53 10 4d 89 43 18 4d 89 4b 20 57 48 81 ec 90 00 00 00}
        $3_1  = {4c 8d 9c 24 20 01 00 00 49 8b 5b 40 49 8b 73 48 49 8b e3 41 5f 41 5e 41 5c 5f 5d c3}
        $4_0  = {ff f5 41 56 41 57 48 81 ec 90 00 00 00 48 8d 6c 24 50 48 c7 45 28 fe ff ff ff 48 89 5d 60 48 89 75 68 48 89 7d 70 4c 89 65 78}
        $4_1  = {8b c1 48 8b 8c 24 30 02 00 00 48 33 cc}
        $5_0  = {48 8b c4 57 41 54 41 55 41 56 41 57 48 81 ec 90 03 00 00 48 c7 80 68 fd ff ff fe ff ff ff 48 89 58 18 48 89 70 20}
        $5_1  = {48 c7 80 68 fd ff ff fe ff ff ff 48 89 58 18 48 89 70 20}
        $6_0  = {44 88 4c 24 20 44 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 53 56 57 41 54 41 55 41 56 41 57 48 81 ec 80 01 00 00}
        $6_1  = {48 89 4c 24 08 53 56 57 41 54 41 55 41 56 41 57 48 81 ec 80 01 00 00 48 c7 84 24 e8 00 00 00 fe ff ff ff}
        $7_0  = {08 48 89 74 24 10 57 48 83 ec 20 49 63 d8 48 8b f2 48 8b f9 45 85 c0}
        $7_1  = {20 49 63 d8 48 8b f2 48 8b f9 45 85}
        $8_0  = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [11300-] ff f5 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 70}
        $9_0  = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [40050-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $10_0 = {41 56 48 83 ec 50 48 c7 44 24 20 fe ff ff ff 48 89 5c 24 60 48 89 6c 24 68 48 89 74 24 70 48 89 7c 24 78 48 8b d9 33 ed 8b f5 89 6c}
        $10_1 = {48 8b 42 18 4c 89 90 f0 00 00 00 44 89 90 f8 00 00 00 c7 80 fc 00 00 00 1b 00 00 00 48 8b c2 c3 90 90 90}
        $11_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [40700-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $12_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [10650-] 48 8b c4 55 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 60}
        $13_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [41850-] ff f5 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 70}
        $14_0 = {48 89 01 48 8b c2 48 c7 41 08 04 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 89 91 40 [42600-] ff f7 48 83 ec 50 48 c7 44 24 20 fe ff ff ff}

    condition:
        any of them
}

rule SUSP_NVIDIA_LAPSUS_Leak_Compromised_Cert_Mar22_1 {
   meta:
      description = "Detects a binary signed with the leaked NVIDIA certifcate and compiled after March 1st 2022"
      author = "Florian Roth (Nextron Systems)"
      date = "2022-03-03"
      modified = "2022-03-04"
      score = 70
      reference = "https://twitter.com/cyb3rops/status/1499514240008437762"
   condition:
      uint16(0) == 0x5a4d and filesize < 100MB and
      pe.timestamp > 1646092800 and  // comment out to find all files signed with that certificate
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and (
            pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or
            pe.signatures[i].serial == "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
         )
   )
}

rule MAL_Malware_Imphash_Mar23_1 {
    meta:
        description = "Detects malware by known bad imphash or rich_pe_header_hash"
        reference = "https://yaraify.abuse.ch/statistics/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-03-20"
        modified = "2023-03-22"
        score = 75
        hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
        hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
        hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
        hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
        hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
        hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
        hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
        hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
        hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
        hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
        hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
        hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
        hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
        hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
        hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
        hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
        hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
        hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
        hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
        hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
        hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
        hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
        hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
        hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
        hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
        hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
        hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
        hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
        hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
        hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
        hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
        hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
        hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
        hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
        hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
        hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
        hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
        hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
        hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
        hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
        hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
        hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
        hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
    strings:
        $fp1 = "Win32 Cabinet Self-Extractor" wide
        $fp2 = "EXTRACTOPT" ascii fullword
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ (ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247) and the hash is calculated only on the header
            pe.imphash() == "9ee34731129f4801db97fd66adbfeaa0" or
            pe.imphash() == "f9e8597c55008e10a8cdc8a0764d5341" or
            pe.imphash() == "0a76016a514d8ed3124268734a31e2d2" or
            pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" or
            pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" or
            pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" or
            pe.imphash() == "890e522b31701e079a367b89393329e6" or
            pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or
            pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" or
            pe.imphash() == "9f4693fc0c511135129493f2161d1e86" or
            pe.imphash() == "b4c6fff030479aa3b12625be67bf4914" // or

            // these have lots of hits on abuse.ch but none on VT? (except for my one test upload) honeypot collected samples?
            //pe.imphash() == "2c2ad1dd2c57d1bd5795167a7236b045" or
            //pe.imphash() == "46f03ef2495b21d7ad3e8d36dc03315d" or
            //pe.imphash() == "6db997463de98ce64bf5b6b8b0f77a45" or
            //pe.imphash() == "c9246f292a6fdc22d70e6e581898a026" or
            //pe.imphash() == "c024c5b95884d2fe702af4f8984b369e" or
            //pe.imphash() == "4dcbc0931c6f88874a69f966c86889d9" or
            //pe.imphash() == "48521d8a9924bcb13fd7132e057b48e1" or

            // rich_pe_header_hash:b6321cd8142ea3954c1a27b162787f7d p:2+ has 238k hits on VT including many files without imphash (e.g. e193dadf0405a826b3455185bdd9293657f910e5976c59e960a0809b589ff9dc) due to being corrupted?
            // zero hits with p:0
            // disable bc it's killing performance
            //hash.md5(pe.rich_signature.clear_data) == "b6321cd8142ea3954c1a27b162787f7d"
        )
        and not 1 of ($fp*)
}

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

rule UPX
{
    meta:
        author = "kevoreilly"
        description = "UPX dump on OEP (original entry point)"
        cape_options = "bp0=$upx32+9,bp0=$upx64+11,action0=step2oep"
    strings:
        $upx32 = {6A 00 39 C4 75 FA 83 EC ?? E9}
        $upx64 = {6A 00 48 39 C4 75 F9 48 83 EC ?? E9}
    condition:
        uint16(0) == 0x5A4D and any of them
}