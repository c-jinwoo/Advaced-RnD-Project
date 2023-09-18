import "pe"

rule Windows_Trojan_CobaltStrike_f0b627fc {
    meta:
        author = "Elastic Security"
        id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
        fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon reflective loader"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
    condition:
        any of them
}

rule INDICATOR_SUSPICIOUS_ReflectiveLoader {
    meta:
        description = "detects Reflective DLL injection artifacts"
        author = "ditekSHen"
    strings:
        $s1 = "_ReflectiveLoader@" ascii wide
        $s2 = "ReflectiveLoader@" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of them or (
            pe.exports("ReflectiveLoader@4") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("ReflectiveLoader")
            )
        )
}

rule Sfile
{
    meta:
        id = "64arpb3yJ0mZxamCG9jIVs"
        fingerprint = "7a2be690f14a9ea61917c2c31b4d44186295de7d8a1342f081ed9507a8ac46b0"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Sfile aka Escal ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"
    strings:
        $pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb" ascii wide
        $ = "%s SORTING time : %s" ascii wide
        $ = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
        $ = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeEnded" ascii wide
        $ = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeSorting" ascii wide
        $ = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
        $ = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
        $ = "%ws FINDFILES time : %s" ascii wide
        $ = "DRIVE_FIXED : %ws" ascii wide
        $ = "EncryptDisk(%ws) DONE" ascii wide
        $ = "ScheduleRoutine() : gogogo" ascii wide
        $ = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "WARN! FileLength more then memory has %ws" ascii wide
        $ = "WaitForHours() : gogogo" ascii wide
        $ = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "Your network has been penetrated." ascii wide
        $ = "--kill-susp" ascii wide
        $ = "--enable-shares" ascii wide
    condition:
        $pdb or 3 of them
}

rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 70
      date = "2017-07-17"
      modified = "2021-03-15"
      author = "Florian Roth (Nextron Systems)"
      nodeepdive = 1
   strings:
      $x1 = "ReflectiveLoader" fullword ascii
      $x2 = "ReflectivLoader.dll" fullword ascii
      $x3 = "?ReflectiveLoader@@" ascii
      $x4 = "reflective_dll.x64.dll" fullword ascii
      $x5 = "reflective_dll.dll" fullword ascii
      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Panda Security, S.L." wide ascii
   condition:
      uint16(0) == 0x5a4d and (
            1 of ($x*) or
            pe.exports("ReflectiveLoader") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("?ReflectiveLoader@@YGKPAX@Z")
         )
      and not 1 of ($fp*)
}