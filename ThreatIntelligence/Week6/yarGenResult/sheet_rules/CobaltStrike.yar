import "pe"

rule HKTL_CobaltStrike_Beacon_4_2_Decrypt {
   meta:
      author = "Elastic"
      description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
   strings:
      $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
      $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
   condition:
      any of them
}

rule HKTL_CobaltStrike_Beacon_Strings {
   meta:
      author = "Elastic"
      description = "Identifies strings used in Cobalt Strike Beacon DLL"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
   strings:
      $s1 = "%02d/%02d/%02d %02d:%02d:%02d"
      $s2 = "Started service %s on %s"
      $s3 = "%s as %s\\%s: %d"
   condition:
      2 of them
}

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

rule Malware_Floxif_mpsvc_dll : HIGHVOL {
   meta:
      description = "Malware - Floxif"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-04-07"
      hash1 = "1e654ee1c4736f4ccb8b5b7aa604782cfb584068df4d9e006de8009e60ab5a14"
   strings:
      $op1 = { 04 80 7a 03 01 75 04 8d 42 04 c3 8d 42 04 53 8b }
      $op2 = { 88 19 74 03 41 eb ea c6 42 03 01 5b c3 8b 4c 24 }
      $op3 = { ff 03 8d 00 f9 ff ff 88 01 eb a1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
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

rule INDICATOR_EXE_Packed_Themida {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Themida"
        snort2_sid = "930067-930069"
        snort3_sid = "930024"
    strings:
        $s1 = ".themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}

rule Office_Document_with_VBA_Project
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects an office document with an embedded VBA project. While this is fairly common it is sometimes used for malicious intent."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://msdn.microsoft.com/en-us/library/office/aa201751%28v=office.10%29.aspx"
        labs_reference = "https://labs.inquest.net/dfi/sha256/8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"
        labs_pivot     = "N/A"
        samples        = "8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"

	strings:
			
		$magic1 = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
		$magic2 = /^\x50\x4B\x03\x04\x14\x00\x06\x00/
		$vba_project1 = "VBA_PROJECT" wide nocase
		$vba_project2 = "word/vbaProject.binPK"
	
    condition:
			
		(($magic1 at 0) or ($magic2 at 0)) and any of ($vba_project*)

}

rule Cobaltbaltstrike_Payload_Encoded
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
    // x86 array
    $s01 = "0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b" ascii wide nocase
    $s02 = "0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b" ascii wide nocase
    // x64 array
    $s03 = "0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51" ascii wide nocase
    $s04 = "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51" ascii wide nocase
    // x86 hex
    $s05 = "fce8890000006089e531d2648b52308b" ascii wide nocase
    $s06 = "fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b" ascii wide nocase
    // x64 hex
    $s07 = "fc4883e4f0e8c8000000415141505251" ascii wide nocase
    $s08 = "fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51" ascii wide nocase
    // x86 base64
    $s09 = "/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJX" ascii wide
    // x64 base64
    $s10 = "/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHA" ascii wide
    // x86 base64 + xor 0x23
    $s11 = "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0" ascii wide
    // x64 base64 + xor 0x23
    $s12 = "32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLj" ascii wide
    // x86 base64 utf16
    $s13 = "/ADoAIkAAAAAAAAAYACJAOUAMQDSAGQAiwBSADAAiwBSAAwAiwBSABQAiwByACg" ascii wide
    // x64 base64 utf16
    $s14 = "/ABIAIMA5ADwAOgAyAAAAAAAAABBAFEAQQBQAFIAUQBWAEgAMQDSAGUASACLAFI" ascii wide
    // x86 base64 + xor 0x23 utf16
    $s15 = "3yPLI6ojIyMjIyMjQyOqI8YjEiPxI0cjqCNxIxMjqCNxIy8jqCNxIzcjqCNRIwsj" ascii wide
    // x64 base64 + xor 0x23 utf16
    $s16 = "3yNrI6AjxyPTI8sj6yMjIyMjIyNiI3IjYiNzI3EjciN1I2sjEiPxI0YjayOoI3Ej" ascii wide
    // x86 vba
    $s17 = "Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117" ascii wide
    $s18 = "Array(-4, -24, -119, 0, 0, 0, 96, -119, -27, 49, -46, 100, -117, 82, 48, -117" ascii wide
    // x64 vba
    $s19 = "Array(-4,72,-125,-28,-16,-24,-56,0,0,0,65,81,65,80,82,81" ascii wide
    $s20 = "Array(-4, 72, -125, -28, -16, -24, -56, 0, 0, 0, 65, 81, 65, 80, 82, 81" ascii wide
    // x86 vbs
    $s21 = "Chr(-4)&Chr(-24)&Chr(-119)&Chr(0)&Chr(0)&Chr(0)&Chr(96)&Chr(-119)&Chr(-27)&\"1\"&Chr(-46)&\"d\"&Chr(-117)&\"R0\"&Chr(-117)" ascii wide
    // x64 vbs
    $s22 = "Chr(-4)&\"H\"&Chr(-125)&Chr(-28)&Chr(-16)&Chr(-24)&Chr(-56)&Chr(0)&Chr(0)&Chr(0)&\"AQAPRQVH" ascii wide
    // x86 veil
    $s23 = "\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b" ascii wide nocase
    // x64 veil
    $s24 = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51" ascii wide nocase

  condition:
        any of them
}