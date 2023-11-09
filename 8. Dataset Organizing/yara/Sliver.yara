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

import "pe"

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

rule INDICATOR_SUSPICIOUS_EXE_SandboxUserNames {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing possible sandbox analysis VM usernames"
    strings:
        $s1 = "15pb" fullword ascii wide nocase
        $s2 = "7man2" fullword ascii wide nocase
        $s3 = "stella" fullword ascii wide nocase
        $s4 = "f4kh9od" fullword ascii wide nocase
        $s5 = "willcarter" fullword ascii wide nocase
        $s6 = "biluta" fullword ascii wide nocase
        $s7 = "ehwalker" fullword ascii wide nocase
        $s8 = "hong lee" fullword ascii wide nocase
        $s9 = "joe cage" fullword ascii wide nocase
        $s10 = "jonathan" fullword ascii wide nocase
        $s11 = "kindsight" fullword ascii wide nocase
        $s12 = "malware" fullword ascii wide nocase
        $s13 = "peter miller" fullword ascii wide nocase
        $s14 = "petermiller" fullword ascii wide nocase
        $s15 = "phil" fullword ascii wide nocase
        $s16 = "rapit" fullword ascii wide nocase
        $s17 = "r0b0t" fullword ascii wide nocase
        $s18 = "cuckoo" fullword ascii wide nocase
        $s19 = "vm-pc" fullword ascii wide nocase
        $s20 = "analyze" fullword ascii wide nocase
        $s21 = "roslyn" fullword ascii wide nocase
        $s22 = "vince" fullword ascii wide nocase
        $s23 = "test" fullword ascii wide nocase
        $s24 = "sample" fullword ascii wide nocase
        $s25 = "mcafee" fullword ascii wide nocase
        $s26 = "vmscan" fullword ascii wide nocase
        $s27 = "mallab" fullword ascii wide nocase
        $s28 = "abby" fullword ascii wide nocase
        $s29 = "elvis" fullword ascii wide nocase
        $s30 = "wilbert" fullword ascii wide nocase
        $s31 = "joe smith" fullword ascii wide nocase
        $s32 = "hanspeter" fullword ascii wide nocase
        $s33 = "johnson" fullword ascii wide nocase
        $s34 = "placehole" fullword ascii wide nocase
        $s35 = "tequila" fullword ascii wide nocase
        $s36 = "paggy sue" fullword ascii wide nocase
        $s37 = "klone" fullword ascii wide nocase
        $s38 = "oliver" fullword ascii wide nocase
        $s39 = "stevens" fullword ascii wide nocase
        $s40 = "ieuser" fullword ascii wide nocase
        $s41 = "virlab" fullword ascii wide nocase
        $s42 = "beginer" fullword ascii wide nocase
        $s43 = "beginner" fullword ascii wide nocase
        $s44 = "markos" fullword ascii wide nocase
        $s45 = "semims" fullword ascii wide nocase
        $s46 = "gregory" fullword ascii wide nocase
        $s47 = "tom-pc" fullword ascii wide nocase
        $s48 = "will carter" fullword ascii wide nocase
        $s49 = "angelica" fullword ascii wide nocase
        $s50 = "eric johns" fullword ascii wide nocase
        $s51 = "john ca" fullword ascii wide nocase
        $s52 = "lebron james" fullword ascii wide nocase
        $s53 = "rats-pc" fullword ascii wide nocase
        $s54 = "robot" fullword ascii wide nocase
        $s55 = "serena" fullword ascii wide nocase
        $s56 = "sofynia" fullword ascii wide nocase
        $s57 = "straz" fullword ascii wide nocase
        $s58 = "bea-ch" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 10 of them
}

rule Multi_Trojan_Sliver_42298c4a {
    meta:
        author = "Elastic Security"
        id = "42298c4a-fcea-4c5a-b213-32db00e4eb5a"
        fingerprint = "0734b090ea10abedef4d9ed48d45c834dd5cf8e424886a5be98e484f69c5e12a"
        creation_date = "2021-10-20"
        last_modified = "2022-01-14"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "3b45aae401ac64c055982b5f3782a3c4c892bdb9f9a5531657d50c27497c8007"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = ").RequestResend"
        $a2 = ").GetPrivInfo"
        $a3 = ").GetReconnectIntervalSeconds"
        $a4 = ").GetPivotID"
        $a5 = "name=PrivInfo"
        $a6 = "name=ReconnectIntervalSeconds"
        $a7 = "name=PivotID"
    condition:
        2 of them
}

rule Multi_Trojan_Sliver_3bde542d {
    meta:
        author = "Elastic Security"
        id = "3bde542d-df52-4f05-84ff-de67e90592a9"
        fingerprint = "e52e39644274e3077769da4d04488963c85a0b691dc9973ad12d51eb34ba388b"
        creation_date = "2022-08-31"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
        $b1 = "InvokeSpawnDllReq" ascii fullword
        $b2 = "NetstatReq" ascii fullword
        $b3 = "HTTPSessionInit" ascii fullword
        $b4 = "ScreenshotReq" ascii fullword
        $b5 = "RegistryReadReq" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
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

rule Linux_Ransomware_Hive_bdc7de59 {
    meta:
        author = "Elastic Security"
        id = "bdc7de59-bf12-461f-99e0-ec2532ace4e9"
        fingerprint = "415ef589a1c2da6b16ab30fb68f938a9ee7917f5509f73aa90aeec51c10dc1ff"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Ransomware.Hive"
        reference_sample = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 40 03 4C 39 C1 73 3A 4C 89 84 24 F0 00 00 00 48 89 D3 48 89 CF 4C }
    condition:
        all of them
}