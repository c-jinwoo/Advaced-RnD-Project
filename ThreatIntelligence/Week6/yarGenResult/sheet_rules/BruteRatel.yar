import "pe"

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