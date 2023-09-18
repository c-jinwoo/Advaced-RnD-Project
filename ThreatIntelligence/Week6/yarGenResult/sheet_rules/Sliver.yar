rule SUSP_Imphash_Mar23_3 {
    meta:
        description = "Detects imphash often found in malware samples (Maximum 0,25% hits with search for 'imphash:x p:0' on Virustotal) = 99,75% hits"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-23"
        reference = "Internal Research"
        score = 45
        hash = "b5296cf0eb22fba6e2f68d0c9de9ef7845f330f7c611a0d60007aa87e270c62a"
        hash = "5a5a5f71c2270cea036cd408cde99f4ebf5e04a751c558650f5cb23279babe6d"
        hash = "481b0d9759bfd209251eccb1848048ebbe7bd2c87c5914a894a5bffc0d1d67ff"
        hash = "716ba6ea691d6a391daedf09ae1262f1dc1591df85292bff52ad76611666092d"
        hash = "800d160736335aafab10503f7263f9af37a15db3e88e41082d50f68d0ad2dabd"
        hash = "416155124784b3c374137befec9330cd56908e0e32c70312afa16f8220627a52"
        hash = "21899e226502fe63b066c51d76869c4ec5dbd03570551cea657d1dd5c97e7070"
        hash = "0461830e811d3831818dac5a67d4df736b4dc2e8fb185da439f9338bdb9f69c3"
        hash = "773edc71d52361454156dfd802ebaba2bb97421ce9024a7798dcdee3da747112"
        hash = "fe53b9d820adf3bcddf42976b8af1411e87d9dfd9aa479f12b2db50a5600f348"
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ and the hash is calculated only on the header
            pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" or
            pe.imphash() == "09d0478591d4f788cb3e5ea416c25237" or
            pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or
            pe.imphash() == "6ed4f5f04d62b18d96b26d6db7c18840" or
            pe.imphash() == "fc6683d30d9f25244a50fd5357825e79" or
            pe.imphash() == "2c5f2513605e48f2d8ea5440a870cb9e" or
            pe.imphash() == "0b5552dccd9d0a834cea55c0c8fc05be"
        )
        and pe.number_of_signatures == 0
}

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

rule INDICATOR_TOOL_Sliver {
    meta:
        author = "ditekSHen"
        description = "Detects Sliver implant cross-platform adversary emulation/red team"
    strings:
        $x1 = "github.com/bishopfox/sliver/protobuf/sliverpbb." ascii
        $s1 = ".commonpb.ResponseR" ascii
        $s2 = ".PortfwdProtocol" ascii
        $s3 = ".WGTCPForwarder" ascii
        $s4 = ".WGSocksServerR" ascii
        $s5 = ".PivotEntryR" ascii
        $s6 = ".BackdoorReq" ascii
        $s7 = ".ProcessDumpReq" ascii
        $s8 = ".InvokeSpawnDllReq" ascii
        $s9 = ".SpawnDll" ascii
        $s10 = ".TCPPivotReq" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and (1 of ($x*) or 5 of ($s*))
}

