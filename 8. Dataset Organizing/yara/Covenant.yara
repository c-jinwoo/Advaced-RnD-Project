rule INDICATOR_SUSPICIOUS_EXE_B64_Encoded_UserAgent {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing base64 encoded User Agent"
    strings:
        $s1 = "TW96aWxsYS81LjAgK" ascii wide
        $s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule MALWARE_Win_CovenantGruntStager {
     meta:
        author = "ditekSHen"
        description = "Detects Covenant Grunt Stager"
    strings:
        $x1 = "VXNlci1BZ2VudA" ascii wide
        $x2 = "cGFnZT17R1VJRH0mdj0x" ascii wide
        $x3 = "0eXBlPXtHVUlEfSZ2PTE" ascii wide
        $x4 = "tZXNzYWdlPXtHVUlEfSZ2PTE" ascii wide
        $x5 = "L2VuLXVzL" ascii wide
        $x6 = "L2VuLXVzL2luZGV4Lmh0bWw" ascii wide
        $x7 = "L2VuLXVzL2RvY3MuaHRtbD" ascii wide
        $s1 = "ExecuteStager" ascii
        $s2 = "UseCertPinning" fullword ascii
        $s3 = "FromBase64String" fullword ascii
        $s4 = "ToBase64String" fullword ascii
        $s5 = "DownloadString" fullword ascii
        $s6 = "UploadString" fullword ascii
        $s7 = "GetWebRequest" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or all of ($s*) or (1 of ($x*) and 5 of ($s*)))
}

rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with PS2EXE"
        snort2_sid = "930004-930006"
        snort3_sid = "930001"
    strings:
        $s1 = "PS2EXE" fullword ascii
        $s2 = "PS2EXEApp" fullword ascii
        $s3 = "PS2EXEHost" fullword ascii
        $s4 = "PS2EXEHostUI" fullword ascii
        $s5 = "PS2EXEHostRawUI" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them
}