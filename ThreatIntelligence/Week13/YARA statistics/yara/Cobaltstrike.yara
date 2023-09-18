import "pe"
import "math"
import "hash"

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

rule INDICATOR_KB_CERT_0a1f3a057a1dce4bf7d76d0c7adf837e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8279b87c89507bc6e209a7bd8b5c24b31fb9a6dc"
        hash = "2df05a70d3ce646285a0f888df15064b4e73034b67e06d9a4f4da680ed62e926"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Qihu Technology Co., Ltd." and
            pe.signatures[i].serial == "0a:1f:3a:05:7a:1d:ce:4b:f7:d7:6d:0c:7a:df:83:7e"
        )
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

rule MALWARE_Win_CobaltStrike {
    meta:
        author = "ditekSHen"
        description = "CobaltStrike payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii

        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)) 
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

rule Cobaltbaltstrike_Beacon_Encoded
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
    // x86 array
    $s01 = "0x4d, 0x5a, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x89, 0xdf, 0x52, 0x45, 0x55, 0x89, 0xe5, 0x81" ascii wide nocase
    $s02 = "0x4d,0x5a,0xe8,0x00,0x00,0x00,0x00,0x5b,0x89,0xdf,0x52,0x45,0x55,0x89,0xe5,0x81" ascii wide nocase
    // x64 array
    $s03 = "0x4d, 0x5a, 0x41, 0x52, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x20, 0x00, 0x00, 0x00, 0x48" ascii wide nocase
    $s04 = "0x4d,0x5a,0x41,0x52,0x55,0x48,0x89,0xe5,0x48,0x81,0xec,0x20,0x00,0x00,0x00,0x48" ascii wide nocase
    // x86 hex
    $s05 = "4d5ae8000000005b89df52455589e581" ascii wide nocase
    $s06 = "4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81" ascii wide nocase
    // x64 hex
    $s07 = "4d5a4152554889e54881ec2000000048" ascii wide nocase
    $s08 = "4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48" ascii wide nocase
    // x86 base64
    $s09 = "TVroAAAAAFuJ31JFVYnlg" ascii wide
    // x64 base64
    $s10 = "TVpBUlVIieVIgewgAAAAS" ascii wide
    // x86 base64 + xor 0x23
    $s11 = "bnnLIyMjI3iq/HFmdqrGo" ascii wide
    // x64 base64 + xor 0x23
    $s12 = "bnlicXZrqsZros8DIyMja" ascii wide
    // x86 base64 utf16
    $s13 = "TQBaAOgAAAAAAAAAAABbAIkA3wBSAEUAVQCJAOUAg" ascii wide
    // x64 base64 utf16
    $s14 = "TQBaAEEAUgBVAEgAiQDlAEgAgQDsACAAAAAAAAAAS" ascii wide
    // x86 base64 + xor 0x23 utf16
    $s15 = "biN5I2IjcSN2I2sjqiPGI2sjoiPPIwMjIyMjIyMja" ascii wide
    // x64 base64 + xor 0x23 utf16
    $s16 = "biN5I8sjIyMjIyMjIyN4I6oj/CNxI2YjdiOqI8Yjo" ascii wide
    // x86 vba
    $s17 = "Array(77,90,-24,0,0,0,0,91,-119,-33,82,69,85,-119,-27,-127" ascii wide
    $s18 = "Array(77, 90, -24, 0, 0, 0, 0, 91, -119, -33, 82, 69, 85, -119, -27, -127" ascii wide
    // x64 vba
    $s19 = "Array(77,90,65,82,85,72,-119,-27,72,-127,-20,32,0,0,0,72" ascii wide
    $s20 = "Array(77, 90, 65, 82, 85, 72, -119, -27, 72, -127, -20, 32, 0, 0, 0, 72" ascii wide
    // x86 vbs
    $s21 = "MZ\"&Chr(-27)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(91)&Chr(-119)&Chr(-33)&\"REU\"&Chr(-119)&Chr(-27)&Chr(-127)" ascii wide
    // x64 vbs
    $s22 = "MZARUH\"&Chr(-119)&Chr(-27)&\"H\"&Chr(-127)&Chr(-20)&Chr(32)&Chr(0)&Chr(0)&Chr(0)&\"H" ascii wide
    // x86 veil
    $s23 = "\\x4d\\x5a\\xe8\\x00\\x00\\x00\\x00\\x5b\\x89\\xdf\\x52\\x45\\x55\\x89\\xe5\\x81" ascii wide nocase
    // x64 veil
    $s24 = "\\x4d\\x5a\\x41\\x52\\x55\\x48\\x89\\xe5\\x48\\x81\\xec\\x20\\x00\\x00\\x00\\x48" ascii wide nocase
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

rule HKTL_Win_CobaltStrike : Commodity {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-05-25"
      description = "The CobaltStrike malware family."
      hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
      reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
   strings:
      $s1 = "%s (admin)" fullword
      $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
      $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
      $s4 = "%s as %s\\%s: %d" fullword
      $s5 = "%s&%s=%s" fullword
      $s6 = "rijndael" fullword
      $s7 = "(null)"
   condition:
      all of them
}

rule CobaltStrike_C2_Encoded_XOR_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 encoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2021-07-08"
    strings:
		$s000 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? 00 04 00 02 00 04 ?? ?? ?? ?? 00 05 00 01 00 02 ?? ?? }
		$s001 = { 01 00 01 00 01 03 ?? ?? 01 03 01 00 01 03 ?? ?? 01 02 01 03 01 05 ?? ?? ?? ?? 01 05 01 03 01 05 ?? ?? ?? ?? 01 04 01 00 01 03 ?? ?? }
		$s002 = { 02 03 02 03 02 00 ?? ?? 02 00 02 03 02 00 ?? ?? 02 01 02 00 02 06 ?? ?? ?? ?? 02 06 02 00 02 06 ?? ?? ?? ?? 02 07 02 03 02 00 ?? ?? }
		$s003 = { 03 02 03 02 03 01 ?? ?? 03 01 03 02 03 01 ?? ?? 03 00 03 01 03 07 ?? ?? ?? ?? 03 07 03 01 03 07 ?? ?? ?? ?? 03 06 03 02 03 01 ?? ?? }
		$s004 = { 04 05 04 05 04 06 ?? ?? 04 06 04 05 04 06 ?? ?? 04 07 04 06 04 00 ?? ?? ?? ?? 04 00 04 06 04 00 ?? ?? ?? ?? 04 01 04 05 04 06 ?? ?? }
		$s005 = { 05 04 05 04 05 07 ?? ?? 05 07 05 04 05 07 ?? ?? 05 06 05 07 05 01 ?? ?? ?? ?? 05 01 05 07 05 01 ?? ?? ?? ?? 05 00 05 04 05 07 ?? ?? }
		$s006 = { 06 07 06 07 06 04 ?? ?? 06 04 06 07 06 04 ?? ?? 06 05 06 04 06 02 ?? ?? ?? ?? 06 02 06 04 06 02 ?? ?? ?? ?? 06 03 06 07 06 04 ?? ?? }
		$s007 = { 07 06 07 06 07 05 ?? ?? 07 05 07 06 07 05 ?? ?? 07 04 07 05 07 03 ?? ?? ?? ?? 07 03 07 05 07 03 ?? ?? ?? ?? 07 02 07 06 07 05 ?? ?? }
		$s008 = { 08 09 08 09 08 0A ?? ?? 08 0A 08 09 08 0A ?? ?? 08 0B 08 0A 08 0C ?? ?? ?? ?? 08 0C 08 0A 08 0C ?? ?? ?? ?? 08 0D 08 09 08 0A ?? ?? }
		$s009 = { 09 08 09 08 09 0B ?? ?? 09 0B 09 08 09 0B ?? ?? 09 0A 09 0B 09 0D ?? ?? ?? ?? 09 0D 09 0B 09 0D ?? ?? ?? ?? 09 0C 09 08 09 0B ?? ?? }
		$s010 = { 0A 0B 0A 0B 0A 08 ?? ?? 0A 08 0A 0B 0A 08 ?? ?? 0A 09 0A 08 0A 0E ?? ?? ?? ?? 0A 0E 0A 08 0A 0E ?? ?? ?? ?? 0A 0F 0A 0B 0A 08 ?? ?? }
		$s011 = { 0B 0A 0B 0A 0B 09 ?? ?? 0B 09 0B 0A 0B 09 ?? ?? 0B 08 0B 09 0B 0F ?? ?? ?? ?? 0B 0F 0B 09 0B 0F ?? ?? ?? ?? 0B 0E 0B 0A 0B 09 ?? ?? }
		$s012 = { 0C 0D 0C 0D 0C 0E ?? ?? 0C 0E 0C 0D 0C 0E ?? ?? 0C 0F 0C 0E 0C 08 ?? ?? ?? ?? 0C 08 0C 0E 0C 08 ?? ?? ?? ?? 0C 09 0C 0D 0C 0E ?? ?? }
		$s013 = { 0D 0C 0D 0C 0D 0F ?? ?? 0D 0F 0D 0C 0D 0F ?? ?? 0D 0E 0D 0F 0D 09 ?? ?? ?? ?? 0D 09 0D 0F 0D 09 ?? ?? ?? ?? 0D 08 0D 0C 0D 0F ?? ?? }
		$s014 = { 0E 0F 0E 0F 0E 0C ?? ?? 0E 0C 0E 0F 0E 0C ?? ?? 0E 0D 0E 0C 0E 0A ?? ?? ?? ?? 0E 0A 0E 0C 0E 0A ?? ?? ?? ?? 0E 0B 0E 0F 0E 0C ?? ?? }
		$s015 = { 0F 0E 0F 0E 0F 0D ?? ?? 0F 0D 0F 0E 0F 0D ?? ?? 0F 0C 0F 0D 0F 0B ?? ?? ?? ?? 0F 0B 0F 0D 0F 0B ?? ?? ?? ?? 0F 0A 0F 0E 0F 0D ?? ?? }
		$s016 = { 10 11 10 11 10 12 ?? ?? 10 12 10 11 10 12 ?? ?? 10 13 10 12 10 14 ?? ?? ?? ?? 10 14 10 12 10 14 ?? ?? ?? ?? 10 15 10 11 10 12 ?? ?? }
		$s017 = { 11 10 11 10 11 13 ?? ?? 11 13 11 10 11 13 ?? ?? 11 12 11 13 11 15 ?? ?? ?? ?? 11 15 11 13 11 15 ?? ?? ?? ?? 11 14 11 10 11 13 ?? ?? }
		$s018 = { 12 13 12 13 12 10 ?? ?? 12 10 12 13 12 10 ?? ?? 12 11 12 10 12 16 ?? ?? ?? ?? 12 16 12 10 12 16 ?? ?? ?? ?? 12 17 12 13 12 10 ?? ?? }
		$s019 = { 13 12 13 12 13 11 ?? ?? 13 11 13 12 13 11 ?? ?? 13 10 13 11 13 17 ?? ?? ?? ?? 13 17 13 11 13 17 ?? ?? ?? ?? 13 16 13 12 13 11 ?? ?? }
		$s020 = { 14 15 14 15 14 16 ?? ?? 14 16 14 15 14 16 ?? ?? 14 17 14 16 14 10 ?? ?? ?? ?? 14 10 14 16 14 10 ?? ?? ?? ?? 14 11 14 15 14 16 ?? ?? }
		$s021 = { 15 14 15 14 15 17 ?? ?? 15 17 15 14 15 17 ?? ?? 15 16 15 17 15 11 ?? ?? ?? ?? 15 11 15 17 15 11 ?? ?? ?? ?? 15 10 15 14 15 17 ?? ?? }
		$s022 = { 16 17 16 17 16 14 ?? ?? 16 14 16 17 16 14 ?? ?? 16 15 16 14 16 12 ?? ?? ?? ?? 16 12 16 14 16 12 ?? ?? ?? ?? 16 13 16 17 16 14 ?? ?? }
		$s023 = { 17 16 17 16 17 15 ?? ?? 17 15 17 16 17 15 ?? ?? 17 14 17 15 17 13 ?? ?? ?? ?? 17 13 17 15 17 13 ?? ?? ?? ?? 17 12 17 16 17 15 ?? ?? }
		$s024 = { 18 19 18 19 18 1A ?? ?? 18 1A 18 19 18 1A ?? ?? 18 1B 18 1A 18 1C ?? ?? ?? ?? 18 1C 18 1A 18 1C ?? ?? ?? ?? 18 1D 18 19 18 1A ?? ?? }
		$s025 = { 19 18 19 18 19 1B ?? ?? 19 1B 19 18 19 1B ?? ?? 19 1A 19 1B 19 1D ?? ?? ?? ?? 19 1D 19 1B 19 1D ?? ?? ?? ?? 19 1C 19 18 19 1B ?? ?? }
		$s026 = { 1A 1B 1A 1B 1A 18 ?? ?? 1A 18 1A 1B 1A 18 ?? ?? 1A 19 1A 18 1A 1E ?? ?? ?? ?? 1A 1E 1A 18 1A 1E ?? ?? ?? ?? 1A 1F 1A 1B 1A 18 ?? ?? }
		$s027 = { 1B 1A 1B 1A 1B 19 ?? ?? 1B 19 1B 1A 1B 19 ?? ?? 1B 18 1B 19 1B 1F ?? ?? ?? ?? 1B 1F 1B 19 1B 1F ?? ?? ?? ?? 1B 1E 1B 1A 1B 19 ?? ?? }
		$s028 = { 1C 1D 1C 1D 1C 1E ?? ?? 1C 1E 1C 1D 1C 1E ?? ?? 1C 1F 1C 1E 1C 18 ?? ?? ?? ?? 1C 18 1C 1E 1C 18 ?? ?? ?? ?? 1C 19 1C 1D 1C 1E ?? ?? }
		$s029 = { 1D 1C 1D 1C 1D 1F ?? ?? 1D 1F 1D 1C 1D 1F ?? ?? 1D 1E 1D 1F 1D 19 ?? ?? ?? ?? 1D 19 1D 1F 1D 19 ?? ?? ?? ?? 1D 18 1D 1C 1D 1F ?? ?? }
		$s030 = { 1E 1F 1E 1F 1E 1C ?? ?? 1E 1C 1E 1F 1E 1C ?? ?? 1E 1D 1E 1C 1E 1A ?? ?? ?? ?? 1E 1A 1E 1C 1E 1A ?? ?? ?? ?? 1E 1B 1E 1F 1E 1C ?? ?? }
		$s031 = { 1F 1E 1F 1E 1F 1D ?? ?? 1F 1D 1F 1E 1F 1D ?? ?? 1F 1C 1F 1D 1F 1B ?? ?? ?? ?? 1F 1B 1F 1D 1F 1B ?? ?? ?? ?? 1F 1A 1F 1E 1F 1D ?? ?? }
		$s032 = { 20 21 20 21 20 22 ?? ?? 20 22 20 21 20 22 ?? ?? 20 23 20 22 20 24 ?? ?? ?? ?? 20 24 20 22 20 24 ?? ?? ?? ?? 20 25 20 21 20 22 ?? ?? }
		$s033 = { 21 20 21 20 21 23 ?? ?? 21 23 21 20 21 23 ?? ?? 21 22 21 23 21 25 ?? ?? ?? ?? 21 25 21 23 21 25 ?? ?? ?? ?? 21 24 21 20 21 23 ?? ?? }
		$s034 = { 22 23 22 23 22 20 ?? ?? 22 20 22 23 22 20 ?? ?? 22 21 22 20 22 26 ?? ?? ?? ?? 22 26 22 20 22 26 ?? ?? ?? ?? 22 27 22 23 22 20 ?? ?? }
		$s035 = { 23 22 23 22 23 21 ?? ?? 23 21 23 22 23 21 ?? ?? 23 20 23 21 23 27 ?? ?? ?? ?? 23 27 23 21 23 27 ?? ?? ?? ?? 23 26 23 22 23 21 ?? ?? }
		$s036 = { 24 25 24 25 24 26 ?? ?? 24 26 24 25 24 26 ?? ?? 24 27 24 26 24 20 ?? ?? ?? ?? 24 20 24 26 24 20 ?? ?? ?? ?? 24 21 24 25 24 26 ?? ?? }
		$s037 = { 25 24 25 24 25 27 ?? ?? 25 27 25 24 25 27 ?? ?? 25 26 25 27 25 21 ?? ?? ?? ?? 25 21 25 27 25 21 ?? ?? ?? ?? 25 20 25 24 25 27 ?? ?? }
		$s038 = { 26 27 26 27 26 24 ?? ?? 26 24 26 27 26 24 ?? ?? 26 25 26 24 26 22 ?? ?? ?? ?? 26 22 26 24 26 22 ?? ?? ?? ?? 26 23 26 27 26 24 ?? ?? }
		$s039 = { 27 26 27 26 27 25 ?? ?? 27 25 27 26 27 25 ?? ?? 27 24 27 25 27 23 ?? ?? ?? ?? 27 23 27 25 27 23 ?? ?? ?? ?? 27 22 27 26 27 25 ?? ?? }
		$s040 = { 28 29 28 29 28 2A ?? ?? 28 2A 28 29 28 2A ?? ?? 28 2B 28 2A 28 2C ?? ?? ?? ?? 28 2C 28 2A 28 2C ?? ?? ?? ?? 28 2D 28 29 28 2A ?? ?? }
		$s041 = { 29 28 29 28 29 2B ?? ?? 29 2B 29 28 29 2B ?? ?? 29 2A 29 2B 29 2D ?? ?? ?? ?? 29 2D 29 2B 29 2D ?? ?? ?? ?? 29 2C 29 28 29 2B ?? ?? }
		$s042 = { 2A 2B 2A 2B 2A 28 ?? ?? 2A 28 2A 2B 2A 28 ?? ?? 2A 29 2A 28 2A 2E ?? ?? ?? ?? 2A 2E 2A 28 2A 2E ?? ?? ?? ?? 2A 2F 2A 2B 2A 28 ?? ?? }
		$s043 = { 2B 2A 2B 2A 2B 29 ?? ?? 2B 29 2B 2A 2B 29 ?? ?? 2B 28 2B 29 2B 2F ?? ?? ?? ?? 2B 2F 2B 29 2B 2F ?? ?? ?? ?? 2B 2E 2B 2A 2B 29 ?? ?? }
		$s044 = { 2C 2D 2C 2D 2C 2E ?? ?? 2C 2E 2C 2D 2C 2E ?? ?? 2C 2F 2C 2E 2C 28 ?? ?? ?? ?? 2C 28 2C 2E 2C 28 ?? ?? ?? ?? 2C 29 2C 2D 2C 2E ?? ?? }
		$s045 = { 2D 2C 2D 2C 2D 2F ?? ?? 2D 2F 2D 2C 2D 2F ?? ?? 2D 2E 2D 2F 2D 29 ?? ?? ?? ?? 2D 29 2D 2F 2D 29 ?? ?? ?? ?? 2D 28 2D 2C 2D 2F ?? ?? }
		$s046 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D 2E 2C 2E 2A ?? ?? ?? ?? 2E 2A 2E 2C 2E 2A ?? ?? ?? ?? 2E 2B 2E 2F 2E 2C ?? ?? }
		$s047 = { 2F 2E 2F 2E 2F 2D ?? ?? 2F 2D 2F 2E 2F 2D ?? ?? 2F 2C 2F 2D 2F 2B ?? ?? ?? ?? 2F 2B 2F 2D 2F 2B ?? ?? ?? ?? 2F 2A 2F 2E 2F 2D ?? ?? }
		$s048 = { 30 31 30 31 30 32 ?? ?? 30 32 30 31 30 32 ?? ?? 30 33 30 32 30 34 ?? ?? ?? ?? 30 34 30 32 30 34 ?? ?? ?? ?? 30 35 30 31 30 32 ?? ?? }
		$s049 = { 31 30 31 30 31 33 ?? ?? 31 33 31 30 31 33 ?? ?? 31 32 31 33 31 35 ?? ?? ?? ?? 31 35 31 33 31 35 ?? ?? ?? ?? 31 34 31 30 31 33 ?? ?? }
		$s050 = { 32 33 32 33 32 30 ?? ?? 32 30 32 33 32 30 ?? ?? 32 31 32 30 32 36 ?? ?? ?? ?? 32 36 32 30 32 36 ?? ?? ?? ?? 32 37 32 33 32 30 ?? ?? }
		$s051 = { 33 32 33 32 33 31 ?? ?? 33 31 33 32 33 31 ?? ?? 33 30 33 31 33 37 ?? ?? ?? ?? 33 37 33 31 33 37 ?? ?? ?? ?? 33 36 33 32 33 31 ?? ?? }
		$s052 = { 34 35 34 35 34 36 ?? ?? 34 36 34 35 34 36 ?? ?? 34 37 34 36 34 30 ?? ?? ?? ?? 34 30 34 36 34 30 ?? ?? ?? ?? 34 31 34 35 34 36 ?? ?? }
		$s053 = { 35 34 35 34 35 37 ?? ?? 35 37 35 34 35 37 ?? ?? 35 36 35 37 35 31 ?? ?? ?? ?? 35 31 35 37 35 31 ?? ?? ?? ?? 35 30 35 34 35 37 ?? ?? }
		$s054 = { 36 37 36 37 36 34 ?? ?? 36 34 36 37 36 34 ?? ?? 36 35 36 34 36 32 ?? ?? ?? ?? 36 32 36 34 36 32 ?? ?? ?? ?? 36 33 36 37 36 34 ?? ?? }
		$s055 = { 37 36 37 36 37 35 ?? ?? 37 35 37 36 37 35 ?? ?? 37 34 37 35 37 33 ?? ?? ?? ?? 37 33 37 35 37 33 ?? ?? ?? ?? 37 32 37 36 37 35 ?? ?? }
		$s056 = { 38 39 38 39 38 3A ?? ?? 38 3A 38 39 38 3A ?? ?? 38 3B 38 3A 38 3C ?? ?? ?? ?? 38 3C 38 3A 38 3C ?? ?? ?? ?? 38 3D 38 39 38 3A ?? ?? }
		$s057 = { 39 38 39 38 39 3B ?? ?? 39 3B 39 38 39 3B ?? ?? 39 3A 39 3B 39 3D ?? ?? ?? ?? 39 3D 39 3B 39 3D ?? ?? ?? ?? 39 3C 39 38 39 3B ?? ?? }
		$s058 = { 3A 3B 3A 3B 3A 38 ?? ?? 3A 38 3A 3B 3A 38 ?? ?? 3A 39 3A 38 3A 3E ?? ?? ?? ?? 3A 3E 3A 38 3A 3E ?? ?? ?? ?? 3A 3F 3A 3B 3A 38 ?? ?? }
		$s059 = { 3B 3A 3B 3A 3B 39 ?? ?? 3B 39 3B 3A 3B 39 ?? ?? 3B 38 3B 39 3B 3F ?? ?? ?? ?? 3B 3F 3B 39 3B 3F ?? ?? ?? ?? 3B 3E 3B 3A 3B 39 ?? ?? }
		$s060 = { 3C 3D 3C 3D 3C 3E ?? ?? 3C 3E 3C 3D 3C 3E ?? ?? 3C 3F 3C 3E 3C 38 ?? ?? ?? ?? 3C 38 3C 3E 3C 38 ?? ?? ?? ?? 3C 39 3C 3D 3C 3E ?? ?? }
		$s061 = { 3D 3C 3D 3C 3D 3F ?? ?? 3D 3F 3D 3C 3D 3F ?? ?? 3D 3E 3D 3F 3D 39 ?? ?? ?? ?? 3D 39 3D 3F 3D 39 ?? ?? ?? ?? 3D 38 3D 3C 3D 3F ?? ?? }
		$s062 = { 3E 3F 3E 3F 3E 3C ?? ?? 3E 3C 3E 3F 3E 3C ?? ?? 3E 3D 3E 3C 3E 3A ?? ?? ?? ?? 3E 3A 3E 3C 3E 3A ?? ?? ?? ?? 3E 3B 3E 3F 3E 3C ?? ?? }
		$s063 = { 3F 3E 3F 3E 3F 3D ?? ?? 3F 3D 3F 3E 3F 3D ?? ?? 3F 3C 3F 3D 3F 3B ?? ?? ?? ?? 3F 3B 3F 3D 3F 3B ?? ?? ?? ?? 3F 3A 3F 3E 3F 3D ?? ?? }
		$s064 = { 40 41 40 41 40 42 ?? ?? 40 42 40 41 40 42 ?? ?? 40 43 40 42 40 44 ?? ?? ?? ?? 40 44 40 42 40 44 ?? ?? ?? ?? 40 45 40 41 40 42 ?? ?? }
		$s065 = { 41 40 41 40 41 43 ?? ?? 41 43 41 40 41 43 ?? ?? 41 42 41 43 41 45 ?? ?? ?? ?? 41 45 41 43 41 45 ?? ?? ?? ?? 41 44 41 40 41 43 ?? ?? }
		$s066 = { 42 43 42 43 42 40 ?? ?? 42 40 42 43 42 40 ?? ?? 42 41 42 40 42 46 ?? ?? ?? ?? 42 46 42 40 42 46 ?? ?? ?? ?? 42 47 42 43 42 40 ?? ?? }
		$s067 = { 43 42 43 42 43 41 ?? ?? 43 41 43 42 43 41 ?? ?? 43 40 43 41 43 47 ?? ?? ?? ?? 43 47 43 41 43 47 ?? ?? ?? ?? 43 46 43 42 43 41 ?? ?? }
		$s068 = { 44 45 44 45 44 46 ?? ?? 44 46 44 45 44 46 ?? ?? 44 47 44 46 44 40 ?? ?? ?? ?? 44 40 44 46 44 40 ?? ?? ?? ?? 44 41 44 45 44 46 ?? ?? }
		$s069 = { 45 44 45 44 45 47 ?? ?? 45 47 45 44 45 47 ?? ?? 45 46 45 47 45 41 ?? ?? ?? ?? 45 41 45 47 45 41 ?? ?? ?? ?? 45 40 45 44 45 47 ?? ?? }
		$s070 = { 46 47 46 47 46 44 ?? ?? 46 44 46 47 46 44 ?? ?? 46 45 46 44 46 42 ?? ?? ?? ?? 46 42 46 44 46 42 ?? ?? ?? ?? 46 43 46 47 46 44 ?? ?? }
		$s071 = { 47 46 47 46 47 45 ?? ?? 47 45 47 46 47 45 ?? ?? 47 44 47 45 47 43 ?? ?? ?? ?? 47 43 47 45 47 43 ?? ?? ?? ?? 47 42 47 46 47 45 ?? ?? }
		$s072 = { 48 49 48 49 48 4A ?? ?? 48 4A 48 49 48 4A ?? ?? 48 4B 48 4A 48 4C ?? ?? ?? ?? 48 4C 48 4A 48 4C ?? ?? ?? ?? 48 4D 48 49 48 4A ?? ?? }
		$s073 = { 49 48 49 48 49 4B ?? ?? 49 4B 49 48 49 4B ?? ?? 49 4A 49 4B 49 4D ?? ?? ?? ?? 49 4D 49 4B 49 4D ?? ?? ?? ?? 49 4C 49 48 49 4B ?? ?? }
		$s074 = { 4A 4B 4A 4B 4A 48 ?? ?? 4A 48 4A 4B 4A 48 ?? ?? 4A 49 4A 48 4A 4E ?? ?? ?? ?? 4A 4E 4A 48 4A 4E ?? ?? ?? ?? 4A 4F 4A 4B 4A 48 ?? ?? }
		$s075 = { 4B 4A 4B 4A 4B 49 ?? ?? 4B 49 4B 4A 4B 49 ?? ?? 4B 48 4B 49 4B 4F ?? ?? ?? ?? 4B 4F 4B 49 4B 4F ?? ?? ?? ?? 4B 4E 4B 4A 4B 49 ?? ?? }
		$s076 = { 4C 4D 4C 4D 4C 4E ?? ?? 4C 4E 4C 4D 4C 4E ?? ?? 4C 4F 4C 4E 4C 48 ?? ?? ?? ?? 4C 48 4C 4E 4C 48 ?? ?? ?? ?? 4C 49 4C 4D 4C 4E ?? ?? }
		$s077 = { 4D 4C 4D 4C 4D 4F ?? ?? 4D 4F 4D 4C 4D 4F ?? ?? 4D 4E 4D 4F 4D 49 ?? ?? ?? ?? 4D 49 4D 4F 4D 49 ?? ?? ?? ?? 4D 48 4D 4C 4D 4F ?? ?? }
		$s078 = { 4E 4F 4E 4F 4E 4C ?? ?? 4E 4C 4E 4F 4E 4C ?? ?? 4E 4D 4E 4C 4E 4A ?? ?? ?? ?? 4E 4A 4E 4C 4E 4A ?? ?? ?? ?? 4E 4B 4E 4F 4E 4C ?? ?? }
		$s079 = { 4F 4E 4F 4E 4F 4D ?? ?? 4F 4D 4F 4E 4F 4D ?? ?? 4F 4C 4F 4D 4F 4B ?? ?? ?? ?? 4F 4B 4F 4D 4F 4B ?? ?? ?? ?? 4F 4A 4F 4E 4F 4D ?? ?? }
		$s080 = { 50 51 50 51 50 52 ?? ?? 50 52 50 51 50 52 ?? ?? 50 53 50 52 50 54 ?? ?? ?? ?? 50 54 50 52 50 54 ?? ?? ?? ?? 50 55 50 51 50 52 ?? ?? }
		$s081 = { 51 50 51 50 51 53 ?? ?? 51 53 51 50 51 53 ?? ?? 51 52 51 53 51 55 ?? ?? ?? ?? 51 55 51 53 51 55 ?? ?? ?? ?? 51 54 51 50 51 53 ?? ?? }
		$s082 = { 52 53 52 53 52 50 ?? ?? 52 50 52 53 52 50 ?? ?? 52 51 52 50 52 56 ?? ?? ?? ?? 52 56 52 50 52 56 ?? ?? ?? ?? 52 57 52 53 52 50 ?? ?? }
		$s083 = { 53 52 53 52 53 51 ?? ?? 53 51 53 52 53 51 ?? ?? 53 50 53 51 53 57 ?? ?? ?? ?? 53 57 53 51 53 57 ?? ?? ?? ?? 53 56 53 52 53 51 ?? ?? }
		$s084 = { 54 55 54 55 54 56 ?? ?? 54 56 54 55 54 56 ?? ?? 54 57 54 56 54 50 ?? ?? ?? ?? 54 50 54 56 54 50 ?? ?? ?? ?? 54 51 54 55 54 56 ?? ?? }
		$s085 = { 55 54 55 54 55 57 ?? ?? 55 57 55 54 55 57 ?? ?? 55 56 55 57 55 51 ?? ?? ?? ?? 55 51 55 57 55 51 ?? ?? ?? ?? 55 50 55 54 55 57 ?? ?? }
		$s086 = { 56 57 56 57 56 54 ?? ?? 56 54 56 57 56 54 ?? ?? 56 55 56 54 56 52 ?? ?? ?? ?? 56 52 56 54 56 52 ?? ?? ?? ?? 56 53 56 57 56 54 ?? ?? }
		$s087 = { 57 56 57 56 57 55 ?? ?? 57 55 57 56 57 55 ?? ?? 57 54 57 55 57 53 ?? ?? ?? ?? 57 53 57 55 57 53 ?? ?? ?? ?? 57 52 57 56 57 55 ?? ?? }
		$s088 = { 58 59 58 59 58 5A ?? ?? 58 5A 58 59 58 5A ?? ?? 58 5B 58 5A 58 5C ?? ?? ?? ?? 58 5C 58 5A 58 5C ?? ?? ?? ?? 58 5D 58 59 58 5A ?? ?? }
		$s089 = { 59 58 59 58 59 5B ?? ?? 59 5B 59 58 59 5B ?? ?? 59 5A 59 5B 59 5D ?? ?? ?? ?? 59 5D 59 5B 59 5D ?? ?? ?? ?? 59 5C 59 58 59 5B ?? ?? }
		$s090 = { 5A 5B 5A 5B 5A 58 ?? ?? 5A 58 5A 5B 5A 58 ?? ?? 5A 59 5A 58 5A 5E ?? ?? ?? ?? 5A 5E 5A 58 5A 5E ?? ?? ?? ?? 5A 5F 5A 5B 5A 58 ?? ?? }
		$s091 = { 5B 5A 5B 5A 5B 59 ?? ?? 5B 59 5B 5A 5B 59 ?? ?? 5B 58 5B 59 5B 5F ?? ?? ?? ?? 5B 5F 5B 59 5B 5F ?? ?? ?? ?? 5B 5E 5B 5A 5B 59 ?? ?? }
		$s092 = { 5C 5D 5C 5D 5C 5E ?? ?? 5C 5E 5C 5D 5C 5E ?? ?? 5C 5F 5C 5E 5C 58 ?? ?? ?? ?? 5C 58 5C 5E 5C 58 ?? ?? ?? ?? 5C 59 5C 5D 5C 5E ?? ?? }
		$s093 = { 5D 5C 5D 5C 5D 5F ?? ?? 5D 5F 5D 5C 5D 5F ?? ?? 5D 5E 5D 5F 5D 59 ?? ?? ?? ?? 5D 59 5D 5F 5D 59 ?? ?? ?? ?? 5D 58 5D 5C 5D 5F ?? ?? }
		$s094 = { 5E 5F 5E 5F 5E 5C ?? ?? 5E 5C 5E 5F 5E 5C ?? ?? 5E 5D 5E 5C 5E 5A ?? ?? ?? ?? 5E 5A 5E 5C 5E 5A ?? ?? ?? ?? 5E 5B 5E 5F 5E 5C ?? ?? }
		$s095 = { 5F 5E 5F 5E 5F 5D ?? ?? 5F 5D 5F 5E 5F 5D ?? ?? 5F 5C 5F 5D 5F 5B ?? ?? ?? ?? 5F 5B 5F 5D 5F 5B ?? ?? ?? ?? 5F 5A 5F 5E 5F 5D ?? ?? }
		$s096 = { 60 61 60 61 60 62 ?? ?? 60 62 60 61 60 62 ?? ?? 60 63 60 62 60 64 ?? ?? ?? ?? 60 64 60 62 60 64 ?? ?? ?? ?? 60 65 60 61 60 62 ?? ?? }
		$s097 = { 61 60 61 60 61 63 ?? ?? 61 63 61 60 61 63 ?? ?? 61 62 61 63 61 65 ?? ?? ?? ?? 61 65 61 63 61 65 ?? ?? ?? ?? 61 64 61 60 61 63 ?? ?? }
		$s098 = { 62 63 62 63 62 60 ?? ?? 62 60 62 63 62 60 ?? ?? 62 61 62 60 62 66 ?? ?? ?? ?? 62 66 62 60 62 66 ?? ?? ?? ?? 62 67 62 63 62 60 ?? ?? }
		$s099 = { 63 62 63 62 63 61 ?? ?? 63 61 63 62 63 61 ?? ?? 63 60 63 61 63 67 ?? ?? ?? ?? 63 67 63 61 63 67 ?? ?? ?? ?? 63 66 63 62 63 61 ?? ?? }
		$s100 = { 64 65 64 65 64 66 ?? ?? 64 66 64 65 64 66 ?? ?? 64 67 64 66 64 60 ?? ?? ?? ?? 64 60 64 66 64 60 ?? ?? ?? ?? 64 61 64 65 64 66 ?? ?? }
		$s101 = { 65 64 65 64 65 67 ?? ?? 65 67 65 64 65 67 ?? ?? 65 66 65 67 65 61 ?? ?? ?? ?? 65 61 65 67 65 61 ?? ?? ?? ?? 65 60 65 64 65 67 ?? ?? }
		$s102 = { 66 67 66 67 66 64 ?? ?? 66 64 66 67 66 64 ?? ?? 66 65 66 64 66 62 ?? ?? ?? ?? 66 62 66 64 66 62 ?? ?? ?? ?? 66 63 66 67 66 64 ?? ?? }
		$s103 = { 67 66 67 66 67 65 ?? ?? 67 65 67 66 67 65 ?? ?? 67 64 67 65 67 63 ?? ?? ?? ?? 67 63 67 65 67 63 ?? ?? ?? ?? 67 62 67 66 67 65 ?? ?? }
		$s104 = { 68 69 68 69 68 6A ?? ?? 68 6A 68 69 68 6A ?? ?? 68 6B 68 6A 68 6C ?? ?? ?? ?? 68 6C 68 6A 68 6C ?? ?? ?? ?? 68 6D 68 69 68 6A ?? ?? }
		$s105 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? }
		$s106 = { 6A 6B 6A 6B 6A 68 ?? ?? 6A 68 6A 6B 6A 68 ?? ?? 6A 69 6A 68 6A 6E ?? ?? ?? ?? 6A 6E 6A 68 6A 6E ?? ?? ?? ?? 6A 6F 6A 6B 6A 68 ?? ?? }
		$s107 = { 6B 6A 6B 6A 6B 69 ?? ?? 6B 69 6B 6A 6B 69 ?? ?? 6B 68 6B 69 6B 6F ?? ?? ?? ?? 6B 6F 6B 69 6B 6F ?? ?? ?? ?? 6B 6E 6B 6A 6B 69 ?? ?? }
		$s108 = { 6C 6D 6C 6D 6C 6E ?? ?? 6C 6E 6C 6D 6C 6E ?? ?? 6C 6F 6C 6E 6C 68 ?? ?? ?? ?? 6C 68 6C 6E 6C 68 ?? ?? ?? ?? 6C 69 6C 6D 6C 6E ?? ?? }
		$s109 = { 6D 6C 6D 6C 6D 6F ?? ?? 6D 6F 6D 6C 6D 6F ?? ?? 6D 6E 6D 6F 6D 69 ?? ?? ?? ?? 6D 69 6D 6F 6D 69 ?? ?? ?? ?? 6D 68 6D 6C 6D 6F ?? ?? }
		$s110 = { 6E 6F 6E 6F 6E 6C ?? ?? 6E 6C 6E 6F 6E 6C ?? ?? 6E 6D 6E 6C 6E 6A ?? ?? ?? ?? 6E 6A 6E 6C 6E 6A ?? ?? ?? ?? 6E 6B 6E 6F 6E 6C ?? ?? }
		$s111 = { 6F 6E 6F 6E 6F 6D ?? ?? 6F 6D 6F 6E 6F 6D ?? ?? 6F 6C 6F 6D 6F 6B ?? ?? ?? ?? 6F 6B 6F 6D 6F 6B ?? ?? ?? ?? 6F 6A 6F 6E 6F 6D ?? ?? }
		$s112 = { 70 71 70 71 70 72 ?? ?? 70 72 70 71 70 72 ?? ?? 70 73 70 72 70 74 ?? ?? ?? ?? 70 74 70 72 70 74 ?? ?? ?? ?? 70 75 70 71 70 72 ?? ?? }
		$s113 = { 71 70 71 70 71 73 ?? ?? 71 73 71 70 71 73 ?? ?? 71 72 71 73 71 75 ?? ?? ?? ?? 71 75 71 73 71 75 ?? ?? ?? ?? 71 74 71 70 71 73 ?? ?? }
		$s114 = { 72 73 72 73 72 70 ?? ?? 72 70 72 73 72 70 ?? ?? 72 71 72 70 72 76 ?? ?? ?? ?? 72 76 72 70 72 76 ?? ?? ?? ?? 72 77 72 73 72 70 ?? ?? }
		$s115 = { 73 72 73 72 73 71 ?? ?? 73 71 73 72 73 71 ?? ?? 73 70 73 71 73 77 ?? ?? ?? ?? 73 77 73 71 73 77 ?? ?? ?? ?? 73 76 73 72 73 71 ?? ?? }
		$s116 = { 74 75 74 75 74 76 ?? ?? 74 76 74 75 74 76 ?? ?? 74 77 74 76 74 70 ?? ?? ?? ?? 74 70 74 76 74 70 ?? ?? ?? ?? 74 71 74 75 74 76 ?? ?? }
		$s117 = { 75 74 75 74 75 77 ?? ?? 75 77 75 74 75 77 ?? ?? 75 76 75 77 75 71 ?? ?? ?? ?? 75 71 75 77 75 71 ?? ?? ?? ?? 75 70 75 74 75 77 ?? ?? }
		$s118 = { 76 77 76 77 76 74 ?? ?? 76 74 76 77 76 74 ?? ?? 76 75 76 74 76 72 ?? ?? ?? ?? 76 72 76 74 76 72 ?? ?? ?? ?? 76 73 76 77 76 74 ?? ?? }
		$s119 = { 77 76 77 76 77 75 ?? ?? 77 75 77 76 77 75 ?? ?? 77 74 77 75 77 73 ?? ?? ?? ?? 77 73 77 75 77 73 ?? ?? ?? ?? 77 72 77 76 77 75 ?? ?? }
		$s120 = { 78 79 78 79 78 7A ?? ?? 78 7A 78 79 78 7A ?? ?? 78 7B 78 7A 78 7C ?? ?? ?? ?? 78 7C 78 7A 78 7C ?? ?? ?? ?? 78 7D 78 79 78 7A ?? ?? }
		$s121 = { 79 78 79 78 79 7B ?? ?? 79 7B 79 78 79 7B ?? ?? 79 7A 79 7B 79 7D ?? ?? ?? ?? 79 7D 79 7B 79 7D ?? ?? ?? ?? 79 7C 79 78 79 7B ?? ?? }
		$s122 = { 7A 7B 7A 7B 7A 78 ?? ?? 7A 78 7A 7B 7A 78 ?? ?? 7A 79 7A 78 7A 7E ?? ?? ?? ?? 7A 7E 7A 78 7A 7E ?? ?? ?? ?? 7A 7F 7A 7B 7A 78 ?? ?? }
		$s123 = { 7B 7A 7B 7A 7B 79 ?? ?? 7B 79 7B 7A 7B 79 ?? ?? 7B 78 7B 79 7B 7F ?? ?? ?? ?? 7B 7F 7B 79 7B 7F ?? ?? ?? ?? 7B 7E 7B 7A 7B 79 ?? ?? }
		$s124 = { 7C 7D 7C 7D 7C 7E ?? ?? 7C 7E 7C 7D 7C 7E ?? ?? 7C 7F 7C 7E 7C 78 ?? ?? ?? ?? 7C 78 7C 7E 7C 78 ?? ?? ?? ?? 7C 79 7C 7D 7C 7E ?? ?? }
		$s125 = { 7D 7C 7D 7C 7D 7F ?? ?? 7D 7F 7D 7C 7D 7F ?? ?? 7D 7E 7D 7F 7D 79 ?? ?? ?? ?? 7D 79 7D 7F 7D 79 ?? ?? ?? ?? 7D 78 7D 7C 7D 7F ?? ?? }
		$s126 = { 7E 7F 7E 7F 7E 7C ?? ?? 7E 7C 7E 7F 7E 7C ?? ?? 7E 7D 7E 7C 7E 7A ?? ?? ?? ?? 7E 7A 7E 7C 7E 7A ?? ?? ?? ?? 7E 7B 7E 7F 7E 7C ?? ?? }
		$s127 = { 7F 7E 7F 7E 7F 7D ?? ?? 7F 7D 7F 7E 7F 7D ?? ?? 7F 7C 7F 7D 7F 7B ?? ?? ?? ?? 7F 7B 7F 7D 7F 7B ?? ?? ?? ?? 7F 7A 7F 7E 7F 7D ?? ?? }
		$s128 = { 80 81 80 81 80 82 ?? ?? 80 82 80 81 80 82 ?? ?? 80 83 80 82 80 84 ?? ?? ?? ?? 80 84 80 82 80 84 ?? ?? ?? ?? 80 85 80 81 80 82 ?? ?? }
		$s129 = { 81 80 81 80 81 83 ?? ?? 81 83 81 80 81 83 ?? ?? 81 82 81 83 81 85 ?? ?? ?? ?? 81 85 81 83 81 85 ?? ?? ?? ?? 81 84 81 80 81 83 ?? ?? }
		$s130 = { 82 83 82 83 82 80 ?? ?? 82 80 82 83 82 80 ?? ?? 82 81 82 80 82 86 ?? ?? ?? ?? 82 86 82 80 82 86 ?? ?? ?? ?? 82 87 82 83 82 80 ?? ?? }
		$s131 = { 83 82 83 82 83 81 ?? ?? 83 81 83 82 83 81 ?? ?? 83 80 83 81 83 87 ?? ?? ?? ?? 83 87 83 81 83 87 ?? ?? ?? ?? 83 86 83 82 83 81 ?? ?? }
		$s132 = { 84 85 84 85 84 86 ?? ?? 84 86 84 85 84 86 ?? ?? 84 87 84 86 84 80 ?? ?? ?? ?? 84 80 84 86 84 80 ?? ?? ?? ?? 84 81 84 85 84 86 ?? ?? }
		$s133 = { 85 84 85 84 85 87 ?? ?? 85 87 85 84 85 87 ?? ?? 85 86 85 87 85 81 ?? ?? ?? ?? 85 81 85 87 85 81 ?? ?? ?? ?? 85 80 85 84 85 87 ?? ?? }
		$s134 = { 86 87 86 87 86 84 ?? ?? 86 84 86 87 86 84 ?? ?? 86 85 86 84 86 82 ?? ?? ?? ?? 86 82 86 84 86 82 ?? ?? ?? ?? 86 83 86 87 86 84 ?? ?? }
		$s135 = { 87 86 87 86 87 85 ?? ?? 87 85 87 86 87 85 ?? ?? 87 84 87 85 87 83 ?? ?? ?? ?? 87 83 87 85 87 83 ?? ?? ?? ?? 87 82 87 86 87 85 ?? ?? }
		$s136 = { 88 89 88 89 88 8A ?? ?? 88 8A 88 89 88 8A ?? ?? 88 8B 88 8A 88 8C ?? ?? ?? ?? 88 8C 88 8A 88 8C ?? ?? ?? ?? 88 8D 88 89 88 8A ?? ?? }
		$s137 = { 89 88 89 88 89 8B ?? ?? 89 8B 89 88 89 8B ?? ?? 89 8A 89 8B 89 8D ?? ?? ?? ?? 89 8D 89 8B 89 8D ?? ?? ?? ?? 89 8C 89 88 89 8B ?? ?? }
		$s138 = { 8A 8B 8A 8B 8A 88 ?? ?? 8A 88 8A 8B 8A 88 ?? ?? 8A 89 8A 88 8A 8E ?? ?? ?? ?? 8A 8E 8A 88 8A 8E ?? ?? ?? ?? 8A 8F 8A 8B 8A 88 ?? ?? }
		$s139 = { 8B 8A 8B 8A 8B 89 ?? ?? 8B 89 8B 8A 8B 89 ?? ?? 8B 88 8B 89 8B 8F ?? ?? ?? ?? 8B 8F 8B 89 8B 8F ?? ?? ?? ?? 8B 8E 8B 8A 8B 89 ?? ?? }
		$s140 = { 8C 8D 8C 8D 8C 8E ?? ?? 8C 8E 8C 8D 8C 8E ?? ?? 8C 8F 8C 8E 8C 88 ?? ?? ?? ?? 8C 88 8C 8E 8C 88 ?? ?? ?? ?? 8C 89 8C 8D 8C 8E ?? ?? }
		$s141 = { 8D 8C 8D 8C 8D 8F ?? ?? 8D 8F 8D 8C 8D 8F ?? ?? 8D 8E 8D 8F 8D 89 ?? ?? ?? ?? 8D 89 8D 8F 8D 89 ?? ?? ?? ?? 8D 88 8D 8C 8D 8F ?? ?? }
		$s142 = { 8E 8F 8E 8F 8E 8C ?? ?? 8E 8C 8E 8F 8E 8C ?? ?? 8E 8D 8E 8C 8E 8A ?? ?? ?? ?? 8E 8A 8E 8C 8E 8A ?? ?? ?? ?? 8E 8B 8E 8F 8E 8C ?? ?? }
		$s143 = { 8F 8E 8F 8E 8F 8D ?? ?? 8F 8D 8F 8E 8F 8D ?? ?? 8F 8C 8F 8D 8F 8B ?? ?? ?? ?? 8F 8B 8F 8D 8F 8B ?? ?? ?? ?? 8F 8A 8F 8E 8F 8D ?? ?? }
		$s144 = { 90 91 90 91 90 92 ?? ?? 90 92 90 91 90 92 ?? ?? 90 93 90 92 90 94 ?? ?? ?? ?? 90 94 90 92 90 94 ?? ?? ?? ?? 90 95 90 91 90 92 ?? ?? }
		$s145 = { 91 90 91 90 91 93 ?? ?? 91 93 91 90 91 93 ?? ?? 91 92 91 93 91 95 ?? ?? ?? ?? 91 95 91 93 91 95 ?? ?? ?? ?? 91 94 91 90 91 93 ?? ?? }
		$s146 = { 92 93 92 93 92 90 ?? ?? 92 90 92 93 92 90 ?? ?? 92 91 92 90 92 96 ?? ?? ?? ?? 92 96 92 90 92 96 ?? ?? ?? ?? 92 97 92 93 92 90 ?? ?? }
		$s147 = { 93 92 93 92 93 91 ?? ?? 93 91 93 92 93 91 ?? ?? 93 90 93 91 93 97 ?? ?? ?? ?? 93 97 93 91 93 97 ?? ?? ?? ?? 93 96 93 92 93 91 ?? ?? }
		$s148 = { 94 95 94 95 94 96 ?? ?? 94 96 94 95 94 96 ?? ?? 94 97 94 96 94 90 ?? ?? ?? ?? 94 90 94 96 94 90 ?? ?? ?? ?? 94 91 94 95 94 96 ?? ?? }
		$s149 = { 95 94 95 94 95 97 ?? ?? 95 97 95 94 95 97 ?? ?? 95 96 95 97 95 91 ?? ?? ?? ?? 95 91 95 97 95 91 ?? ?? ?? ?? 95 90 95 94 95 97 ?? ?? }
		$s150 = { 96 97 96 97 96 94 ?? ?? 96 94 96 97 96 94 ?? ?? 96 95 96 94 96 92 ?? ?? ?? ?? 96 92 96 94 96 92 ?? ?? ?? ?? 96 93 96 97 96 94 ?? ?? }
		$s151 = { 97 96 97 96 97 95 ?? ?? 97 95 97 96 97 95 ?? ?? 97 94 97 95 97 93 ?? ?? ?? ?? 97 93 97 95 97 93 ?? ?? ?? ?? 97 92 97 96 97 95 ?? ?? }
		$s152 = { 98 99 98 99 98 9A ?? ?? 98 9A 98 99 98 9A ?? ?? 98 9B 98 9A 98 9C ?? ?? ?? ?? 98 9C 98 9A 98 9C ?? ?? ?? ?? 98 9D 98 99 98 9A ?? ?? }
		$s153 = { 99 98 99 98 99 9B ?? ?? 99 9B 99 98 99 9B ?? ?? 99 9A 99 9B 99 9D ?? ?? ?? ?? 99 9D 99 9B 99 9D ?? ?? ?? ?? 99 9C 99 98 99 9B ?? ?? }
		$s154 = { 9A 9B 9A 9B 9A 98 ?? ?? 9A 98 9A 9B 9A 98 ?? ?? 9A 99 9A 98 9A 9E ?? ?? ?? ?? 9A 9E 9A 98 9A 9E ?? ?? ?? ?? 9A 9F 9A 9B 9A 98 ?? ?? }
		$s155 = { 9B 9A 9B 9A 9B 99 ?? ?? 9B 99 9B 9A 9B 99 ?? ?? 9B 98 9B 99 9B 9F ?? ?? ?? ?? 9B 9F 9B 99 9B 9F ?? ?? ?? ?? 9B 9E 9B 9A 9B 99 ?? ?? }
		$s156 = { 9C 9D 9C 9D 9C 9E ?? ?? 9C 9E 9C 9D 9C 9E ?? ?? 9C 9F 9C 9E 9C 98 ?? ?? ?? ?? 9C 98 9C 9E 9C 98 ?? ?? ?? ?? 9C 99 9C 9D 9C 9E ?? ?? }
		$s157 = { 9D 9C 9D 9C 9D 9F ?? ?? 9D 9F 9D 9C 9D 9F ?? ?? 9D 9E 9D 9F 9D 99 ?? ?? ?? ?? 9D 99 9D 9F 9D 99 ?? ?? ?? ?? 9D 98 9D 9C 9D 9F ?? ?? }
		$s158 = { 9E 9F 9E 9F 9E 9C ?? ?? 9E 9C 9E 9F 9E 9C ?? ?? 9E 9D 9E 9C 9E 9A ?? ?? ?? ?? 9E 9A 9E 9C 9E 9A ?? ?? ?? ?? 9E 9B 9E 9F 9E 9C ?? ?? }
		$s159 = { 9F 9E 9F 9E 9F 9D ?? ?? 9F 9D 9F 9E 9F 9D ?? ?? 9F 9C 9F 9D 9F 9B ?? ?? ?? ?? 9F 9B 9F 9D 9F 9B ?? ?? ?? ?? 9F 9A 9F 9E 9F 9D ?? ?? }
		$s160 = { A0 A1 A0 A1 A0 A2 ?? ?? A0 A2 A0 A1 A0 A2 ?? ?? A0 A3 A0 A2 A0 A4 ?? ?? ?? ?? A0 A4 A0 A2 A0 A4 ?? ?? ?? ?? A0 A5 A0 A1 A0 A2 ?? ?? }
		$s161 = { A1 A0 A1 A0 A1 A3 ?? ?? A1 A3 A1 A0 A1 A3 ?? ?? A1 A2 A1 A3 A1 A5 ?? ?? ?? ?? A1 A5 A1 A3 A1 A5 ?? ?? ?? ?? A1 A4 A1 A0 A1 A3 ?? ?? }
		$s162 = { A2 A3 A2 A3 A2 A0 ?? ?? A2 A0 A2 A3 A2 A0 ?? ?? A2 A1 A2 A0 A2 A6 ?? ?? ?? ?? A2 A6 A2 A0 A2 A6 ?? ?? ?? ?? A2 A7 A2 A3 A2 A0 ?? ?? }
		$s163 = { A3 A2 A3 A2 A3 A1 ?? ?? A3 A1 A3 A2 A3 A1 ?? ?? A3 A0 A3 A1 A3 A7 ?? ?? ?? ?? A3 A7 A3 A1 A3 A7 ?? ?? ?? ?? A3 A6 A3 A2 A3 A1 ?? ?? }
		$s164 = { A4 A5 A4 A5 A4 A6 ?? ?? A4 A6 A4 A5 A4 A6 ?? ?? A4 A7 A4 A6 A4 A0 ?? ?? ?? ?? A4 A0 A4 A6 A4 A0 ?? ?? ?? ?? A4 A1 A4 A5 A4 A6 ?? ?? }
		$s165 = { A5 A4 A5 A4 A5 A7 ?? ?? A5 A7 A5 A4 A5 A7 ?? ?? A5 A6 A5 A7 A5 A1 ?? ?? ?? ?? A5 A1 A5 A7 A5 A1 ?? ?? ?? ?? A5 A0 A5 A4 A5 A7 ?? ?? }
		$s166 = { A6 A7 A6 A7 A6 A4 ?? ?? A6 A4 A6 A7 A6 A4 ?? ?? A6 A5 A6 A4 A6 A2 ?? ?? ?? ?? A6 A2 A6 A4 A6 A2 ?? ?? ?? ?? A6 A3 A6 A7 A6 A4 ?? ?? }
		$s167 = { A7 A6 A7 A6 A7 A5 ?? ?? A7 A5 A7 A6 A7 A5 ?? ?? A7 A4 A7 A5 A7 A3 ?? ?? ?? ?? A7 A3 A7 A5 A7 A3 ?? ?? ?? ?? A7 A2 A7 A6 A7 A5 ?? ?? }
		$s168 = { A8 A9 A8 A9 A8 AA ?? ?? A8 AA A8 A9 A8 AA ?? ?? A8 AB A8 AA A8 AC ?? ?? ?? ?? A8 AC A8 AA A8 AC ?? ?? ?? ?? A8 AD A8 A9 A8 AA ?? ?? }
		$s169 = { A9 A8 A9 A8 A9 AB ?? ?? A9 AB A9 A8 A9 AB ?? ?? A9 AA A9 AB A9 AD ?? ?? ?? ?? A9 AD A9 AB A9 AD ?? ?? ?? ?? A9 AC A9 A8 A9 AB ?? ?? }
		$s170 = { AA AB AA AB AA A8 ?? ?? AA A8 AA AB AA A8 ?? ?? AA A9 AA A8 AA AE ?? ?? ?? ?? AA AE AA A8 AA AE ?? ?? ?? ?? AA AF AA AB AA A8 ?? ?? }
		$s171 = { AB AA AB AA AB A9 ?? ?? AB A9 AB AA AB A9 ?? ?? AB A8 AB A9 AB AF ?? ?? ?? ?? AB AF AB A9 AB AF ?? ?? ?? ?? AB AE AB AA AB A9 ?? ?? }
		$s172 = { AC AD AC AD AC AE ?? ?? AC AE AC AD AC AE ?? ?? AC AF AC AE AC A8 ?? ?? ?? ?? AC A8 AC AE AC A8 ?? ?? ?? ?? AC A9 AC AD AC AE ?? ?? }
		$s173 = { AD AC AD AC AD AF ?? ?? AD AF AD AC AD AF ?? ?? AD AE AD AF AD A9 ?? ?? ?? ?? AD A9 AD AF AD A9 ?? ?? ?? ?? AD A8 AD AC AD AF ?? ?? }
		$s174 = { AE AF AE AF AE AC ?? ?? AE AC AE AF AE AC ?? ?? AE AD AE AC AE AA ?? ?? ?? ?? AE AA AE AC AE AA ?? ?? ?? ?? AE AB AE AF AE AC ?? ?? }
		$s175 = { AF AE AF AE AF AD ?? ?? AF AD AF AE AF AD ?? ?? AF AC AF AD AF AB ?? ?? ?? ?? AF AB AF AD AF AB ?? ?? ?? ?? AF AA AF AE AF AD ?? ?? }
		$s176 = { B0 B1 B0 B1 B0 B2 ?? ?? B0 B2 B0 B1 B0 B2 ?? ?? B0 B3 B0 B2 B0 B4 ?? ?? ?? ?? B0 B4 B0 B2 B0 B4 ?? ?? ?? ?? B0 B5 B0 B1 B0 B2 ?? ?? }
		$s177 = { B1 B0 B1 B0 B1 B3 ?? ?? B1 B3 B1 B0 B1 B3 ?? ?? B1 B2 B1 B3 B1 B5 ?? ?? ?? ?? B1 B5 B1 B3 B1 B5 ?? ?? ?? ?? B1 B4 B1 B0 B1 B3 ?? ?? }
		$s178 = { B2 B3 B2 B3 B2 B0 ?? ?? B2 B0 B2 B3 B2 B0 ?? ?? B2 B1 B2 B0 B2 B6 ?? ?? ?? ?? B2 B6 B2 B0 B2 B6 ?? ?? ?? ?? B2 B7 B2 B3 B2 B0 ?? ?? }
		$s179 = { B3 B2 B3 B2 B3 B1 ?? ?? B3 B1 B3 B2 B3 B1 ?? ?? B3 B0 B3 B1 B3 B7 ?? ?? ?? ?? B3 B7 B3 B1 B3 B7 ?? ?? ?? ?? B3 B6 B3 B2 B3 B1 ?? ?? }
		$s180 = { B4 B5 B4 B5 B4 B6 ?? ?? B4 B6 B4 B5 B4 B6 ?? ?? B4 B7 B4 B6 B4 B0 ?? ?? ?? ?? B4 B0 B4 B6 B4 B0 ?? ?? ?? ?? B4 B1 B4 B5 B4 B6 ?? ?? }
		$s181 = { B5 B4 B5 B4 B5 B7 ?? ?? B5 B7 B5 B4 B5 B7 ?? ?? B5 B6 B5 B7 B5 B1 ?? ?? ?? ?? B5 B1 B5 B7 B5 B1 ?? ?? ?? ?? B5 B0 B5 B4 B5 B7 ?? ?? }
		$s182 = { B6 B7 B6 B7 B6 B4 ?? ?? B6 B4 B6 B7 B6 B4 ?? ?? B6 B5 B6 B4 B6 B2 ?? ?? ?? ?? B6 B2 B6 B4 B6 B2 ?? ?? ?? ?? B6 B3 B6 B7 B6 B4 ?? ?? }
		$s183 = { B7 B6 B7 B6 B7 B5 ?? ?? B7 B5 B7 B6 B7 B5 ?? ?? B7 B4 B7 B5 B7 B3 ?? ?? ?? ?? B7 B3 B7 B5 B7 B3 ?? ?? ?? ?? B7 B2 B7 B6 B7 B5 ?? ?? }
		$s184 = { B8 B9 B8 B9 B8 BA ?? ?? B8 BA B8 B9 B8 BA ?? ?? B8 BB B8 BA B8 BC ?? ?? ?? ?? B8 BC B8 BA B8 BC ?? ?? ?? ?? B8 BD B8 B9 B8 BA ?? ?? }
		$s185 = { B9 B8 B9 B8 B9 BB ?? ?? B9 BB B9 B8 B9 BB ?? ?? B9 BA B9 BB B9 BD ?? ?? ?? ?? B9 BD B9 BB B9 BD ?? ?? ?? ?? B9 BC B9 B8 B9 BB ?? ?? }
		$s186 = { BA BB BA BB BA B8 ?? ?? BA B8 BA BB BA B8 ?? ?? BA B9 BA B8 BA BE ?? ?? ?? ?? BA BE BA B8 BA BE ?? ?? ?? ?? BA BF BA BB BA B8 ?? ?? }
		$s187 = { BB BA BB BA BB B9 ?? ?? BB B9 BB BA BB B9 ?? ?? BB B8 BB B9 BB BF ?? ?? ?? ?? BB BF BB B9 BB BF ?? ?? ?? ?? BB BE BB BA BB B9 ?? ?? }
		$s188 = { BC BD BC BD BC BE ?? ?? BC BE BC BD BC BE ?? ?? BC BF BC BE BC B8 ?? ?? ?? ?? BC B8 BC BE BC B8 ?? ?? ?? ?? BC B9 BC BD BC BE ?? ?? }
		$s189 = { BD BC BD BC BD BF ?? ?? BD BF BD BC BD BF ?? ?? BD BE BD BF BD B9 ?? ?? ?? ?? BD B9 BD BF BD B9 ?? ?? ?? ?? BD B8 BD BC BD BF ?? ?? }
		$s190 = { BE BF BE BF BE BC ?? ?? BE BC BE BF BE BC ?? ?? BE BD BE BC BE BA ?? ?? ?? ?? BE BA BE BC BE BA ?? ?? ?? ?? BE BB BE BF BE BC ?? ?? }
		$s191 = { BF BE BF BE BF BD ?? ?? BF BD BF BE BF BD ?? ?? BF BC BF BD BF BB ?? ?? ?? ?? BF BB BF BD BF BB ?? ?? ?? ?? BF BA BF BE BF BD ?? ?? }
		$s192 = { C0 C1 C0 C1 C0 C2 ?? ?? C0 C2 C0 C1 C0 C2 ?? ?? C0 C3 C0 C2 C0 C4 ?? ?? ?? ?? C0 C4 C0 C2 C0 C4 ?? ?? ?? ?? C0 C5 C0 C1 C0 C2 ?? ?? }
		$s193 = { C1 C0 C1 C0 C1 C3 ?? ?? C1 C3 C1 C0 C1 C3 ?? ?? C1 C2 C1 C3 C1 C5 ?? ?? ?? ?? C1 C5 C1 C3 C1 C5 ?? ?? ?? ?? C1 C4 C1 C0 C1 C3 ?? ?? }
		$s194 = { C2 C3 C2 C3 C2 C0 ?? ?? C2 C0 C2 C3 C2 C0 ?? ?? C2 C1 C2 C0 C2 C6 ?? ?? ?? ?? C2 C6 C2 C0 C2 C6 ?? ?? ?? ?? C2 C7 C2 C3 C2 C0 ?? ?? }
		$s195 = { C3 C2 C3 C2 C3 C1 ?? ?? C3 C1 C3 C2 C3 C1 ?? ?? C3 C0 C3 C1 C3 C7 ?? ?? ?? ?? C3 C7 C3 C1 C3 C7 ?? ?? ?? ?? C3 C6 C3 C2 C3 C1 ?? ?? }
		$s196 = { C4 C5 C4 C5 C4 C6 ?? ?? C4 C6 C4 C5 C4 C6 ?? ?? C4 C7 C4 C6 C4 C0 ?? ?? ?? ?? C4 C0 C4 C6 C4 C0 ?? ?? ?? ?? C4 C1 C4 C5 C4 C6 ?? ?? }
		$s197 = { C5 C4 C5 C4 C5 C7 ?? ?? C5 C7 C5 C4 C5 C7 ?? ?? C5 C6 C5 C7 C5 C1 ?? ?? ?? ?? C5 C1 C5 C7 C5 C1 ?? ?? ?? ?? C5 C0 C5 C4 C5 C7 ?? ?? }
		$s198 = { C6 C7 C6 C7 C6 C4 ?? ?? C6 C4 C6 C7 C6 C4 ?? ?? C6 C5 C6 C4 C6 C2 ?? ?? ?? ?? C6 C2 C6 C4 C6 C2 ?? ?? ?? ?? C6 C3 C6 C7 C6 C4 ?? ?? }
		$s199 = { C7 C6 C7 C6 C7 C5 ?? ?? C7 C5 C7 C6 C7 C5 ?? ?? C7 C4 C7 C5 C7 C3 ?? ?? ?? ?? C7 C3 C7 C5 C7 C3 ?? ?? ?? ?? C7 C2 C7 C6 C7 C5 ?? ?? }
		$s200 = { C8 C9 C8 C9 C8 CA ?? ?? C8 CA C8 C9 C8 CA ?? ?? C8 CB C8 CA C8 CC ?? ?? ?? ?? C8 CC C8 CA C8 CC ?? ?? ?? ?? C8 CD C8 C9 C8 CA ?? ?? }
		$s201 = { C9 C8 C9 C8 C9 CB ?? ?? C9 CB C9 C8 C9 CB ?? ?? C9 CA C9 CB C9 CD ?? ?? ?? ?? C9 CD C9 CB C9 CD ?? ?? ?? ?? C9 CC C9 C8 C9 CB ?? ?? }
		$s202 = { CA CB CA CB CA C8 ?? ?? CA C8 CA CB CA C8 ?? ?? CA C9 CA C8 CA CE ?? ?? ?? ?? CA CE CA C8 CA CE ?? ?? ?? ?? CA CF CA CB CA C8 ?? ?? }
		$s203 = { CB CA CB CA CB C9 ?? ?? CB C9 CB CA CB C9 ?? ?? CB C8 CB C9 CB CF ?? ?? ?? ?? CB CF CB C9 CB CF ?? ?? ?? ?? CB CE CB CA CB C9 ?? ?? }
		$s204 = { CC CD CC CD CC CE ?? ?? CC CE CC CD CC CE ?? ?? CC CF CC CE CC C8 ?? ?? ?? ?? CC C8 CC CE CC C8 ?? ?? ?? ?? CC C9 CC CD CC CE ?? ?? }
		$s205 = { CD CC CD CC CD CF ?? ?? CD CF CD CC CD CF ?? ?? CD CE CD CF CD C9 ?? ?? ?? ?? CD C9 CD CF CD C9 ?? ?? ?? ?? CD C8 CD CC CD CF ?? ?? }
		$s206 = { CE CF CE CF CE CC ?? ?? CE CC CE CF CE CC ?? ?? CE CD CE CC CE CA ?? ?? ?? ?? CE CA CE CC CE CA ?? ?? ?? ?? CE CB CE CF CE CC ?? ?? }
		$s207 = { CF CE CF CE CF CD ?? ?? CF CD CF CE CF CD ?? ?? CF CC CF CD CF CB ?? ?? ?? ?? CF CB CF CD CF CB ?? ?? ?? ?? CF CA CF CE CF CD ?? ?? }
		$s208 = { D0 D1 D0 D1 D0 D2 ?? ?? D0 D2 D0 D1 D0 D2 ?? ?? D0 D3 D0 D2 D0 D4 ?? ?? ?? ?? D0 D4 D0 D2 D0 D4 ?? ?? ?? ?? D0 D5 D0 D1 D0 D2 ?? ?? }
		$s209 = { D1 D0 D1 D0 D1 D3 ?? ?? D1 D3 D1 D0 D1 D3 ?? ?? D1 D2 D1 D3 D1 D5 ?? ?? ?? ?? D1 D5 D1 D3 D1 D5 ?? ?? ?? ?? D1 D4 D1 D0 D1 D3 ?? ?? }
		$s210 = { D2 D3 D2 D3 D2 D0 ?? ?? D2 D0 D2 D3 D2 D0 ?? ?? D2 D1 D2 D0 D2 D6 ?? ?? ?? ?? D2 D6 D2 D0 D2 D6 ?? ?? ?? ?? D2 D7 D2 D3 D2 D0 ?? ?? }
		$s211 = { D3 D2 D3 D2 D3 D1 ?? ?? D3 D1 D3 D2 D3 D1 ?? ?? D3 D0 D3 D1 D3 D7 ?? ?? ?? ?? D3 D7 D3 D1 D3 D7 ?? ?? ?? ?? D3 D6 D3 D2 D3 D1 ?? ?? }
		$s212 = { D4 D5 D4 D5 D4 D6 ?? ?? D4 D6 D4 D5 D4 D6 ?? ?? D4 D7 D4 D6 D4 D0 ?? ?? ?? ?? D4 D0 D4 D6 D4 D0 ?? ?? ?? ?? D4 D1 D4 D5 D4 D6 ?? ?? }
		$s213 = { D5 D4 D5 D4 D5 D7 ?? ?? D5 D7 D5 D4 D5 D7 ?? ?? D5 D6 D5 D7 D5 D1 ?? ?? ?? ?? D5 D1 D5 D7 D5 D1 ?? ?? ?? ?? D5 D0 D5 D4 D5 D7 ?? ?? }
		$s214 = { D6 D7 D6 D7 D6 D4 ?? ?? D6 D4 D6 D7 D6 D4 ?? ?? D6 D5 D6 D4 D6 D2 ?? ?? ?? ?? D6 D2 D6 D4 D6 D2 ?? ?? ?? ?? D6 D3 D6 D7 D6 D4 ?? ?? }
		$s215 = { D7 D6 D7 D6 D7 D5 ?? ?? D7 D5 D7 D6 D7 D5 ?? ?? D7 D4 D7 D5 D7 D3 ?? ?? ?? ?? D7 D3 D7 D5 D7 D3 ?? ?? ?? ?? D7 D2 D7 D6 D7 D5 ?? ?? }
		$s216 = { D8 D9 D8 D9 D8 DA ?? ?? D8 DA D8 D9 D8 DA ?? ?? D8 DB D8 DA D8 DC ?? ?? ?? ?? D8 DC D8 DA D8 DC ?? ?? ?? ?? D8 DD D8 D9 D8 DA ?? ?? }
		$s217 = { D9 D8 D9 D8 D9 DB ?? ?? D9 DB D9 D8 D9 DB ?? ?? D9 DA D9 DB D9 DD ?? ?? ?? ?? D9 DD D9 DB D9 DD ?? ?? ?? ?? D9 DC D9 D8 D9 DB ?? ?? }
		$s218 = { DA DB DA DB DA D8 ?? ?? DA D8 DA DB DA D8 ?? ?? DA D9 DA D8 DA DE ?? ?? ?? ?? DA DE DA D8 DA DE ?? ?? ?? ?? DA DF DA DB DA D8 ?? ?? }
		$s219 = { DB DA DB DA DB D9 ?? ?? DB D9 DB DA DB D9 ?? ?? DB D8 DB D9 DB DF ?? ?? ?? ?? DB DF DB D9 DB DF ?? ?? ?? ?? DB DE DB DA DB D9 ?? ?? }
		$s220 = { DC DD DC DD DC DE ?? ?? DC DE DC DD DC DE ?? ?? DC DF DC DE DC D8 ?? ?? ?? ?? DC D8 DC DE DC D8 ?? ?? ?? ?? DC D9 DC DD DC DE ?? ?? }
		$s221 = { DD DC DD DC DD DF ?? ?? DD DF DD DC DD DF ?? ?? DD DE DD DF DD D9 ?? ?? ?? ?? DD D9 DD DF DD D9 ?? ?? ?? ?? DD D8 DD DC DD DF ?? ?? }
		$s222 = { DE DF DE DF DE DC ?? ?? DE DC DE DF DE DC ?? ?? DE DD DE DC DE DA ?? ?? ?? ?? DE DA DE DC DE DA ?? ?? ?? ?? DE DB DE DF DE DC ?? ?? }
		$s223 = { DF DE DF DE DF DD ?? ?? DF DD DF DE DF DD ?? ?? DF DC DF DD DF DB ?? ?? ?? ?? DF DB DF DD DF DB ?? ?? ?? ?? DF DA DF DE DF DD ?? ?? }
		$s224 = { E0 E1 E0 E1 E0 E2 ?? ?? E0 E2 E0 E1 E0 E2 ?? ?? E0 E3 E0 E2 E0 E4 ?? ?? ?? ?? E0 E4 E0 E2 E0 E4 ?? ?? ?? ?? E0 E5 E0 E1 E0 E2 ?? ?? }
		$s225 = { E1 E0 E1 E0 E1 E3 ?? ?? E1 E3 E1 E0 E1 E3 ?? ?? E1 E2 E1 E3 E1 E5 ?? ?? ?? ?? E1 E5 E1 E3 E1 E5 ?? ?? ?? ?? E1 E4 E1 E0 E1 E3 ?? ?? }
		$s226 = { E2 E3 E2 E3 E2 E0 ?? ?? E2 E0 E2 E3 E2 E0 ?? ?? E2 E1 E2 E0 E2 E6 ?? ?? ?? ?? E2 E6 E2 E0 E2 E6 ?? ?? ?? ?? E2 E7 E2 E3 E2 E0 ?? ?? }
		$s227 = { E3 E2 E3 E2 E3 E1 ?? ?? E3 E1 E3 E2 E3 E1 ?? ?? E3 E0 E3 E1 E3 E7 ?? ?? ?? ?? E3 E7 E3 E1 E3 E7 ?? ?? ?? ?? E3 E6 E3 E2 E3 E1 ?? ?? }
		$s228 = { E4 E5 E4 E5 E4 E6 ?? ?? E4 E6 E4 E5 E4 E6 ?? ?? E4 E7 E4 E6 E4 E0 ?? ?? ?? ?? E4 E0 E4 E6 E4 E0 ?? ?? ?? ?? E4 E1 E4 E5 E4 E6 ?? ?? }
		$s229 = { E5 E4 E5 E4 E5 E7 ?? ?? E5 E7 E5 E4 E5 E7 ?? ?? E5 E6 E5 E7 E5 E1 ?? ?? ?? ?? E5 E1 E5 E7 E5 E1 ?? ?? ?? ?? E5 E0 E5 E4 E5 E7 ?? ?? }
		$s230 = { E6 E7 E6 E7 E6 E4 ?? ?? E6 E4 E6 E7 E6 E4 ?? ?? E6 E5 E6 E4 E6 E2 ?? ?? ?? ?? E6 E2 E6 E4 E6 E2 ?? ?? ?? ?? E6 E3 E6 E7 E6 E4 ?? ?? }
		$s231 = { E7 E6 E7 E6 E7 E5 ?? ?? E7 E5 E7 E6 E7 E5 ?? ?? E7 E4 E7 E5 E7 E3 ?? ?? ?? ?? E7 E3 E7 E5 E7 E3 ?? ?? ?? ?? E7 E2 E7 E6 E7 E5 ?? ?? }
		$s232 = { E8 E9 E8 E9 E8 EA ?? ?? E8 EA E8 E9 E8 EA ?? ?? E8 EB E8 EA E8 EC ?? ?? ?? ?? E8 EC E8 EA E8 EC ?? ?? ?? ?? E8 ED E8 E9 E8 EA ?? ?? }
		$s233 = { E9 E8 E9 E8 E9 EB ?? ?? E9 EB E9 E8 E9 EB ?? ?? E9 EA E9 EB E9 ED ?? ?? ?? ?? E9 ED E9 EB E9 ED ?? ?? ?? ?? E9 EC E9 E8 E9 EB ?? ?? }
		$s234 = { EA EB EA EB EA E8 ?? ?? EA E8 EA EB EA E8 ?? ?? EA E9 EA E8 EA EE ?? ?? ?? ?? EA EE EA E8 EA EE ?? ?? ?? ?? EA EF EA EB EA E8 ?? ?? }
		$s235 = { EB EA EB EA EB E9 ?? ?? EB E9 EB EA EB E9 ?? ?? EB E8 EB E9 EB EF ?? ?? ?? ?? EB EF EB E9 EB EF ?? ?? ?? ?? EB EE EB EA EB E9 ?? ?? }
		$s236 = { EC ED EC ED EC EE ?? ?? EC EE EC ED EC EE ?? ?? EC EF EC EE EC E8 ?? ?? ?? ?? EC E8 EC EE EC E8 ?? ?? ?? ?? EC E9 EC ED EC EE ?? ?? }
		$s237 = { ED EC ED EC ED EF ?? ?? ED EF ED EC ED EF ?? ?? ED EE ED EF ED E9 ?? ?? ?? ?? ED E9 ED EF ED E9 ?? ?? ?? ?? ED E8 ED EC ED EF ?? ?? }
		$s238 = { EE EF EE EF EE EC ?? ?? EE EC EE EF EE EC ?? ?? EE ED EE EC EE EA ?? ?? ?? ?? EE EA EE EC EE EA ?? ?? ?? ?? EE EB EE EF EE EC ?? ?? }
		$s239 = { EF EE EF EE EF ED ?? ?? EF ED EF EE EF ED ?? ?? EF EC EF ED EF EB ?? ?? ?? ?? EF EB EF ED EF EB ?? ?? ?? ?? EF EA EF EE EF ED ?? ?? }
		$s240 = { F0 F1 F0 F1 F0 F2 ?? ?? F0 F2 F0 F1 F0 F2 ?? ?? F0 F3 F0 F2 F0 F4 ?? ?? ?? ?? F0 F4 F0 F2 F0 F4 ?? ?? ?? ?? F0 F5 F0 F1 F0 F2 ?? ?? }
		$s241 = { F1 F0 F1 F0 F1 F3 ?? ?? F1 F3 F1 F0 F1 F3 ?? ?? F1 F2 F1 F3 F1 F5 ?? ?? ?? ?? F1 F5 F1 F3 F1 F5 ?? ?? ?? ?? F1 F4 F1 F0 F1 F3 ?? ?? }
		$s242 = { F2 F3 F2 F3 F2 F0 ?? ?? F2 F0 F2 F3 F2 F0 ?? ?? F2 F1 F2 F0 F2 F6 ?? ?? ?? ?? F2 F6 F2 F0 F2 F6 ?? ?? ?? ?? F2 F7 F2 F3 F2 F0 ?? ?? }
		$s243 = { F3 F2 F3 F2 F3 F1 ?? ?? F3 F1 F3 F2 F3 F1 ?? ?? F3 F0 F3 F1 F3 F7 ?? ?? ?? ?? F3 F7 F3 F1 F3 F7 ?? ?? ?? ?? F3 F6 F3 F2 F3 F1 ?? ?? }
		$s244 = { F4 F5 F4 F5 F4 F6 ?? ?? F4 F6 F4 F5 F4 F6 ?? ?? F4 F7 F4 F6 F4 F0 ?? ?? ?? ?? F4 F0 F4 F6 F4 F0 ?? ?? ?? ?? F4 F1 F4 F5 F4 F6 ?? ?? }
		$s245 = { F5 F4 F5 F4 F5 F7 ?? ?? F5 F7 F5 F4 F5 F7 ?? ?? F5 F6 F5 F7 F5 F1 ?? ?? ?? ?? F5 F1 F5 F7 F5 F1 ?? ?? ?? ?? F5 F0 F5 F4 F5 F7 ?? ?? }
		$s246 = { F6 F7 F6 F7 F6 F4 ?? ?? F6 F4 F6 F7 F6 F4 ?? ?? F6 F5 F6 F4 F6 F2 ?? ?? ?? ?? F6 F2 F6 F4 F6 F2 ?? ?? ?? ?? F6 F3 F6 F7 F6 F4 ?? ?? }
		$s247 = { F7 F6 F7 F6 F7 F5 ?? ?? F7 F5 F7 F6 F7 F5 ?? ?? F7 F4 F7 F5 F7 F3 ?? ?? ?? ?? F7 F3 F7 F5 F7 F3 ?? ?? ?? ?? F7 F2 F7 F6 F7 F5 ?? ?? }
		$s248 = { F8 F9 F8 F9 F8 FA ?? ?? F8 FA F8 F9 F8 FA ?? ?? F8 FB F8 FA F8 FC ?? ?? ?? ?? F8 FC F8 FA F8 FC ?? ?? ?? ?? F8 FD F8 F9 F8 FA ?? ?? }
		$s249 = { F9 F8 F9 F8 F9 FB ?? ?? F9 FB F9 F8 F9 FB ?? ?? F9 FA F9 FB F9 FD ?? ?? ?? ?? F9 FD F9 FB F9 FD ?? ?? ?? ?? F9 FC F9 F8 F9 FB ?? ?? }
		$s250 = { FA FB FA FB FA F8 ?? ?? FA F8 FA FB FA F8 ?? ?? FA F9 FA F8 FA FE ?? ?? ?? ?? FA FE FA F8 FA FE ?? ?? ?? ?? FA FF FA FB FA F8 ?? ?? }
		$s251 = { FB FA FB FA FB F9 ?? ?? FB F9 FB FA FB F9 ?? ?? FB F8 FB F9 FB FF ?? ?? ?? ?? FB FF FB F9 FB FF ?? ?? ?? ?? FB FE FB FA FB F9 ?? ?? }
		$s252 = { FC FD FC FD FC FE ?? ?? FC FE FC FD FC FE ?? ?? FC FF FC FE FC F8 ?? ?? ?? ?? FC F8 FC FE FC F8 ?? ?? ?? ?? FC F9 FC FD FC FE ?? ?? }
		$s253 = { FD FC FD FC FD FF ?? ?? FD FF FD FC FD FF ?? ?? FD FE FD FF FD F9 ?? ?? ?? ?? FD F9 FD FF FD F9 ?? ?? ?? ?? FD F8 FD FC FD FF ?? ?? }
		$s254 = { FE FF FE FF FE FC ?? ?? FE FC FE FF FE FC ?? ?? FE FD FE FC FE FA ?? ?? ?? ?? FE FA FE FC FE FA ?? ?? ?? ?? FE FB FE FF FE FC ?? ?? }
		$s255 = { FF FE FF FE FF FD ?? ?? FF FD FF FE FF FD ?? ?? FF FC FF FD FF FB ?? ?? ?? ?? FF FB FF FD FF FB ?? ?? ?? ?? FF FA FF FE FF FD ?? ?? }
		
		$fp1 = "ICSharpCode.Decompiler" wide
    condition:
		any of ($s*) and not 1 of ($fp*)
}

rule Trojan_Raw_Generic_4
{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}

rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2022-05-13"
      score = 65
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide

      $fp1 = "Sentinel Labs" wide
      $fp2 = "<filter object at" ascii /* Norton Security */
   condition:
      $xo1 and not $xof1 and not 1 of ($fp*)
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

rule HKTL_Imphashes_Aug22_1 {
   meta:
      description = "Detects different hacktools based on their imphash"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 80
      date = "2022-08-17"
      modified = "2023-03-21"
   condition:
      uint16(0) == 0x5a4d and (
            pe.imphash() == "bcca3c247b619dcd13c8cdff5f123932" or // PetitPotam
            pe.imphash() == "3a19059bd7688cb88e70005f18efc439" or // PetitPotam
            pe.imphash() == "bf6223a49e45d99094406777eb6004ba" or // PetitPotam
            pe.imphash() == "0c106686a31bfe2ba931ae1cf6e9dbc6" or // Mimikatz
            pe.imphash() == "0d1447d4b3259b3c2a1d4cfb7ece13c3" or // Mimikatz
            pe.imphash() == "1b0369a1e06271833f78ffa70ffb4eaf" or // Mimikatz
            pe.imphash() == "4c1b52a19748428e51b14c278d0f58e3" or // Mimikatz
            pe.imphash() == "4d927a711f77d62cebd4f322cb57ec6f" or // Mimikatz
            pe.imphash() == "66ee036df5fc1004d9ed5e9a94a1086a" or // Mimikatz
            pe.imphash() == "672b13f4a0b6f27d29065123fe882dfc" or // Mimikatz
            pe.imphash() == "6bbd59cea665c4afcc2814c1327ec91f" or // Mimikatz
            pe.imphash() == "725bb81dc24214f6ecacc0cfb36ad30d" or // Mimikatz
            pe.imphash() == "9528a0e91e28fbb88ad433feabca2456" or // Mimikatz
            pe.imphash() == "9da6d5d77be11712527dcab86df449a3" or // Mimikatz
            pe.imphash() == "a6e01bc1ab89f8d91d9eab72032aae88" or // Mimikatz
            pe.imphash() == "b24c5eddaea4fe50c6a96a2a133521e4" or // Mimikatz
            pe.imphash() == "d21bbc50dcc169d7b4d0f01962793154" or // Mimikatz
            pe.imphash() == "fcc251cceae90d22c392215cc9a2d5d6" or // Mimikatz
            pe.imphash() == "23867a89c2b8fc733be6cf5ef902f2d1" or // JuicyPotato
            pe.imphash() == "a37ff327f8d48e8a4d2f757e1b6e70bc" or // JuicyPotato
            pe.imphash() == "f9a28c458284584a93b14216308d31bd" or // JuicyPotatoNG
            pe.imphash() == "6118619783fc175bc7ebecff0769b46e" or // RoguePotato
            pe.imphash() == "959a83047e80ab68b368fdb3f4c6e4ea" or // RoguePotato
            pe.imphash() == "563233bfa169acc7892451f71ad5850a" or // RoguePotato
            pe.imphash() == "87575cb7a0e0700eb37f2e3668671a08" or // RoguePotato
            pe.imphash() == "13f08707f759af6003837a150a371ba1" or // Pwdump
            pe.imphash() == "1781f06048a7e58b323f0b9259be798b" or // Pwdump
            pe.imphash() == "233f85f2d4bc9d6521a6caae11a1e7f5" or // Pwdump
            pe.imphash() == "24af2584cbf4d60bbe5c6d1b31b3be6d" or // Pwdump
            pe.imphash() == "632969ddf6dbf4e0f53424b75e4b91f2" or // Pwdump
            pe.imphash() == "713c29b396b907ed71a72482759ed757" or // Pwdump
            pe.imphash() == "749a7bb1f0b4c4455949c0b2bf7f9e9f" or // Pwdump
            pe.imphash() == "8628b2608957a6b0c6330ac3de28ce2e" or // Pwdump
            pe.imphash() == "8b114550386e31895dfab371e741123d" or // Pwdump
            pe.imphash() == "94cb940a1a6b65bed4d5a8f849ce9793" or // PwDumpX
            pe.imphash() == "9d68781980370e00e0bd939ee5e6c141" or // Pwdump
            pe.imphash() == "b18a1401ff8f444056d29450fbc0a6ce" or // Pwdump
            pe.imphash() == "cb567f9498452721d77a451374955f5f" or // Pwdump
            pe.imphash() == "730073214094cd328547bf1f72289752" or // Htran
            pe.imphash() == "17b461a082950fc6332228572138b80c" or // Cobalt Strike beacons
            pe.imphash() == "dc25ee78e2ef4d36faa0badf1e7461c9" or // Cobalt Strike beacons
            pe.imphash() == "819b19d53ca6736448f9325a85736792" or // Cobalt Strike beacons
            pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or // Cobalt Strike beacons
            pe.imphash() == "c547f2e66061a8dffb6f5a3ff63c0a74" or // PPLDump
            pe.imphash() == "0588081ab0e63ba785938467e1b10cca" or // PPLDump
            pe.imphash() == "0d9ec08bac6c07d9987dfd0f1506587c" or // NanoDump
            pe.imphash() == "bc129092b71c89b4d4c8cdf8ea590b29" or // NanoDump
            pe.imphash() == "4da924cf622d039d58bce71cdf05d242" or // NanoDump
            pe.imphash() == "e7a3a5c377e2d29324093377d7db1c66" or // NanoDump
            pe.imphash() == "9a9dbec5c62f0380b4fa5fd31deffedf" or // NanoDump
            pe.imphash() == "af8a3976ad71e5d5fdfb67ddb8dadfce" or // NanoDump
            pe.imphash() == "0c477898bbf137bbd6f2a54e3b805ff4" or // NanoDump
            pe.imphash() == "0ca9f02b537bcea20d4ea5eb1a9fe338" or // NanoDump
            pe.imphash() == "3ab3655e5a14d4eefc547f4781bf7f9e" or // NanoDump
            pe.imphash() == "e6f9d5152da699934b30daab206471f6" or // NanoDump
            pe.imphash() == "3ad59991ccf1d67339b319b15a41b35d" or // NanoDump
            pe.imphash() == "ffdd59e0318b85a3e480874d9796d872" or // NanoDump
            pe.imphash() == "0cf479628d7cc1ea25ec7998a92f5051" or // NanoDump
            pe.imphash() == "07a2d4dcbd6cb2c6a45e6b101f0b6d51" or // NanoDump
            pe.imphash() == "d6d0f80386e1380d05cb78e871bc72b1" or // NanoDump
            pe.imphash() == "38d9e015591bbfd4929e0d0f47fa0055" or // HandleKatz
            pe.imphash() == "0e2216679ca6e1094d63322e3412d650" or // HandleKatz
            pe.imphash() == "ada161bf41b8e5e9132858cb54cab5fb" or // DripLoader
            pe.imphash() == "2a1bc4913cd5ecb0434df07cb675b798" or // DripLoader
            pe.imphash() == "11083e75553baae21dc89ce8f9a195e4" or // DripLoader
            pe.imphash() == "a23d29c9e566f2fa8ffbb79267f5df80" or // DripLoader
            pe.imphash() == "4a07f944a83e8a7c2525efa35dd30e2f" or // CreateMiniDump
            pe.imphash() == "767637c23bb42cd5d7397cf58b0be688" or // UACMe Akagi
            pe.imphash() == "14c4e4c72ba075e9069ee67f39188ad8" or // UACMe Akagi
            pe.imphash() == "3c782813d4afce07bbfc5a9772acdbdc" or // UACMe Akagi
            pe.imphash() == "7d010c6bb6a3726f327f7e239166d127" or // UACMe Akagi
            pe.imphash() == "89159ba4dd04e4ce5559f132a9964eb3" or // UACMe Akagi
            pe.imphash() == "6f33f4a5fc42b8cec7314947bd13f30f" or // UACMe Akagi
            pe.imphash() == "5834ed4291bdeb928270428ebbaf7604" or // UACMe Akagi
            pe.imphash() == "5a8a8a43f25485e7ee1b201edcbc7a38" or // UACMe Akagi
            pe.imphash() == "dc7d30b90b2d8abf664fbed2b1b59894" or // UACMe Akagi
            pe.imphash() == "41923ea1f824fe63ea5beb84db7a3e74" or // UACMe Akagi
            pe.imphash() == "3de09703c8e79ed2ca3f01074719906b" or // UACMe Akagi
            pe.imphash() == "a53a02b997935fd8eedcb5f7abab9b9f" or // WCE
            pe.imphash() == "e96a73c7bf33a464c510ede582318bf2" or // WCE
            pe.imphash() == "32089b8851bbf8bc2d014e9f37288c83" or // Sliver Stagers
            pe.imphash() == "09D278F9DE118EF09163C6140255C690" or // Dumpert
            pe.imphash() == "03866661686829d806989e2fc5a72606" or // Dumpert
            pe.imphash() == "e57401fbdadcd4571ff385ab82bd5d6d" or // Dumpert
            pe.imphash() == "84B763C45C0E4A3E7CA5548C710DB4EE" or // SysmonEnte
            pe.imphash() == "19584675d94829987952432e018d5056" or // SysmonQuiet
            pe.imphash() == "330768a4f172e10acb6287b87289d83b" // ShaprEvtMute Hook
      )
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

rule CobaltStrike_Unmodifed_Beacon {
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"
	condition:
		all of them
}

rule Cobaltbaltstrike_Beacon_XORed_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
        // x64 xor decrypt loop
    $h01 = { FC 4883E4F0 EB33 5D 8B4500 4883C504 8B4D00 31C1 4883C504 55 8B5500 31C2 895500 31D0 4883C504 83E904 31D2 39D1 7402 EBE7 58 FC 4883E4F0 FFD0 E8C8FFFFFF }
    // end of xor decrypt loop
        $h11 = { FC 4883E4F0 FFD0 E8C8FFFFFF }
  condition:
        $h01 and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5A4152 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5A41 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}

rule Cobaltbaltstrike_Beacon_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
    // x64 default MZ header
    $h01 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D EA FF FF FF 48 89 }
    // decoded config blob
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    // xored config blob v3
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    // xored config blob v4
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule CobaltStrike_MZ_Launcher {
	meta:
		description = "Detects CobaltStrike MZ header ReflectiveLoader launcher"
		author = "yara@s3c.za.net"
		date = "2021-07-08"
    strings:
        $mz_launcher = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D }
	condition:
		$mz_launcher
}

rule CobaltStrike_Sleep_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2021-07-19"
	strings:
		$sleep_decoder = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B 51 08 41 8B F0 48 8B EA 48 8B D9 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }
	condition:
		$sleep_decoder
}

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

/* requires YARA 3.11 */

rule HKTL_CobaltStrike_SleepMask_Jul22 {
   meta:
      description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
      author = "CodeX"
      date = "2022-07-04"
      reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
      score = 80
   strings:
      $sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
   condition:
      $sleep_mask
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

rule SUSP_PS1_FromBase64String_Content_Indicator : FILE {
   meta:
      description = "Detects suspicious base64 encoded PowerShell expressions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
      date = "2020-01-25"
   strings:
      $ = "::FromBase64String(\"H4s" ascii wide
      $ = "::FromBase64String(\"TVq" ascii wide
      $ = "::FromBase64String(\"UEs" ascii wide
      $ = "::FromBase64String(\"JAB" ascii wide
      $ = "::FromBase64String(\"SUVY" ascii wide
      $ = "::FromBase64String(\"SQBFAF" ascii wide
      $ = "::FromBase64String(\"SQBuAH" ascii wide
      $ = "::FromBase64String(\"PAA" ascii wide
      $ = "::FromBase64String(\"cwBhA" ascii wide
      $ = "::FromBase64String(\"aWV4" ascii wide
      $ = "::FromBase64String(\"aQBlA" ascii wide
      $ = "::FromBase64String(\"R2V0" ascii wide
      $ = "::FromBase64String(\"dmFy" ascii wide
      $ = "::FromBase64String(\"dgBhA" ascii wide
      $ = "::FromBase64String(\"dXNpbm" ascii wide
      $ = "::FromBase64String(\"H4sIA" ascii wide
      $ = "::FromBase64String(\"Y21k" ascii wide
      $ = "::FromBase64String(\"Qzpc" ascii wide
      $ = "::FromBase64String(\"Yzpc" ascii wide
      $ = "::FromBase64String(\"IAB" ascii wide

      $ = "::FromBase64String('H4s" ascii wide
      $ = "::FromBase64String('TVq" ascii wide
      $ = "::FromBase64String('UEs" ascii wide
      $ = "::FromBase64String('JAB" ascii wide
      $ = "::FromBase64String('SUVY" ascii wide
      $ = "::FromBase64String('SQBFAF" ascii wide
      $ = "::FromBase64String('SQBuAH" ascii wide
      $ = "::FromBase64String('PAA" ascii wide
      $ = "::FromBase64String('cwBhA" ascii wide
      $ = "::FromBase64String('aWV4" ascii wide
      $ = "::FromBase64String('aQBlA" ascii wide
      $ = "::FromBase64String('R2V0" ascii wide
      $ = "::FromBase64String('dmFy" ascii wide
      $ = "::FromBase64String('dgBhA" ascii wide
      $ = "::FromBase64String('dXNpbm" ascii wide
      $ = "::FromBase64String('H4sIA" ascii wide
      $ = "::FromBase64String('Y21k" ascii wide
      $ = "::FromBase64String('Qzpc" ascii wide
      $ = "::FromBase64String('Yzpc" ascii wide
      $ = "::FromBase64String('IAB" ascii wide
   condition:
      filesize < 5000KB and 1 of them
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

rule SUSP_PE_Signed_by_Suspicious_Entitiy_Mar23
{
    meta:
        author = "Arnim Rupp (https://github.com/ruppde)"
        date_created = "2023-03-06"
        description = "Find driver signed by suspicious company (see references)"
        score = 60
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        reference = "https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware"
        reference = "https://news.sophos.com/en-us/2022/12/13/signed-driver-malware-moves-up-the-software-trust-chain/"
        reference = "https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/"
        hash = "2fb7a38e69a88e3da8fece4c6a1a81842c1be6ae9d6ac299afa4aef4eb55fd4b"
        hash = "9a24befcc0c0926abb49d43174fe25c2469cca06d6ab3b5000d7c9d434c42fe9"
        hash = "9ad716f0173489e74fefe086000dfbea9dc093b1c3460bed9cdb82f923073806"
        hash = "a007c8c6c1aecfff1065429fef691e7ae1c0ce20012a113f01ac57c61564a627"
        hash = "fbe82a21939d04735aa3bbf23fbabd45ac491a143396e8e62ee20509c1257918"
        hash = "d12c6ea0a86c58ea2d80d1dc9b793ba28a0db92c72bb5b6f4ee2b800fe42091b"
        hash = "4cf31d000f1542690cbc0ace41e4166651a71747978dc408e3cce32e82713917"
        hash = "e1adaea335b20d4d2e351f7bea496cd40cb379376900434866db342f851d9ddf"
        hash = "031408cf2f2c282bcc05066356fcc2bb862b7e3c504ab7ffb0220bea341404a5"
        hash = "2f13d4e1bd35f6c0ad0978af19006c17193cf3d42b71cba763cca68f7e9d7fca"
        hash = "cb40a5dc4f6a27b1dc50176770026b827f8baa05fa95a98a4e880652f6729d96"
        hash = "a7591b7384bd10eb934f0dac8dcbfdff8c352eba2309f4d75553567fa2376efa"
        hash = "d517ce5f132b3274f0b9783a5b0c37d1d648e6079874960af24ca764b011c042"
        hash = "aeec903013d5b66f0ae1c6fa50bb892759149c1cec86db8089a4e60482e02250"
        hash = "0d22828724cb7fbc6cef7f98665d020867d2eb801cff2c21f2e97e481040499b"
        hash = "4b2e874d51d332fd840dadd463a393f9f019de46e49de73be910b9b1365e4e4e"
        hash = "3839c0925acf836238ba9a0c5798b84b1c089a8353cc27ae7e6b75d273b539e3"
        hash = "c470f519fb0d4a2862035e0d9e105a0a6918adc51842b12ad14b5b5f34879963"
        hash = "cc6d174bc86f84f5a4c516e9c04947e2fecc0509a84748ea80576aeee5950aed"
        hash = "6fe8df70254f9b5f53452815f0163cb2ffb2d7f0f5aefbb9b149ad1be9284e31"
        hash = "4cde473fb68fa9b2709ea8a23349cd2fce8b8b3991b9fea12f95d12292b8aa7a"
        hash = "e2c40c8dd60bb395807c39c76bfdf5cd158ebefd2a47ad3306a96662c50057c0"
        hash = "9c12b09b529fa517eaeb49df22527d7563b5432d62776166048d97f83b2dce5c"
        hash = "5a4e17287f3dceb5bf1ed411e5fdd7e8692aebf2a19b334327733fc1c158b0ba"
        hash = "c42964aa7fa354b1a285bdbcbd9e84b6bdd8813ff9361955e0e455d032803cce"
        hash = "ffd6955bf40957a35901d82fd5b96d0cb191b651d3eca7afa779eebfed0d9f7e"
        hash = "f6874335eb0d611d47b2ec99a6b70f7b373a50d8d1f62d290b06174f42279f36"
        hash = "4e6d7fd70a143f19429fead2c14779aea9d9140e270bb9e91e47fa601643e40e"
        hash = "7b0e4aae37660b1099de69f4c14f5d976f260c64a4af8495ff1415512a6268ba"
        hash = "db45cbfb094f3e1ebf1cb3880087a24d4e771cc43ba48ad373e6283cbe7391da"
        hash = "813edc804f59a97ec9391ea0db4b779443bd8daf1e64c622b5e3c9a22ee9c2e0"
        hash = "8d66a4b7c2ae468390d32e5e70b3f9b7cb796b54b7c404cde038de9786be8d1d"
        hash = "85936141f0f32cf8f3173655e7200236d1fce6ef9c2616fd2b19ae7951c644c5"
        hash = "b5fc0cc9980fc594a18682d2b0d5b0d0f19ba7a35d35106693a78f4aaba346ac"
        hash = "7aae36c5ffa8baaab19724dae051673ddafd36107cb61c505926bfceaadcd516"
        hash = "5d0228a0d321e2ddac5502da04ca7a2b2744f3dc1382daa5f02faa9da5aface1"
        hash = "2af1ac8bc8ae8d7cad703d2695f2f6c6d79b82eebba01253a8ec527e11e83fcd"
        hash = "c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497"
        hash = "0e339c9c8a6702b32ee9f2915512cbeb3391ced74b16c7e0aed9b1a80c9e58c8"
        hash = "80bdeaa4f162c65722b700e4ffba31701d0d634f5533e59bf3885dc67ee92f3f"
        hash = "4570f64f2000bdaf53aec0fc2214c8bd54e0f5cb75987cdf1f8bda6ea5fc4c43"
        hash = "a9c906bde6c8a693d5d46c9922dafa2dfd2dec0fff554f3f6a953c2e36d3f7b7"
        hash = "520df3ddd7c9ecdeecac8e443d75ac258c26b45d37ecec22501afdda797f6a0a"
        hash = "4d3e0f27a7bcfd4b442b489c63641af22285ca41c6d56ac1db734196ab10b315"
        hash = "5000b3b1d593ba40cc10098644af1551259590ac67d3726fab2be87aad460877"
        hash = "7c27bd6104fc67dd16e655f3bf67c2abd8b5bf2a693ba714ac86904c5765b316"
        hash = "34b1234eab7ff10edde9e09ecf73c5e4bfe9ee047ccfdb43de1e1f6155afad0c"
        hash = "f6fe2cc9ea31f85273c26e84422137df21cfce4b9e972b0db94fe3a67b54f6ca"
        hash = "ec4d0828196926bd36325f4b021895d37cfaaa024f754b36618c78b2574f0122"
        hash = "2a89f263d85da8fb0c934d287b5b524744479741491c740aaa46ac9f694f6d1b"
        hash = "c8d0122974fc10a7d82c62f3e6573a94379c026dd741fd73497afdf36d3929be"
        hash = "0345f71876bc4c888deadba7284565a8da112901f343e54b8522279968abd1b2"
        hash = "6c0e10650be9e795dc6adfbe8aad8c1c3a8657e4c45cb82a7d5188ee24021ca0"
        hash = "90b8d9c4ff3e4e0a0342e0d91da3a25be2fead29f3b32888bb35f8575845259d"
        hash = "0310400c9e62c3fe08dc6506313e26f7c5c89035c81b0141ce57543910c1c42e"
        hash = "b0da0316443f878aad0b3d9764b631d5df60e119ab59324c37640da1b431893a"
        hash = "cc4bd06f27a5f266bc8825a08e5f45dcaa4352eb6d69214b5037d28cc8de6908"
        hash = "2d4b7c6931203923db9a07e1ac92124e799f3747ab20e95e191e99c7b98f3fbd"
        hash = "b5965de0d883fd0602037f3dc26fd4461e6328612f1a34798cff0066142e13c4"
        hash = "86ce17183ddf32379db53ecaedefe0811252165b05cd326025bb8eca2e6a25d7"
        hash = "6edca16d5aa751aa4c212e6477121d51e4d9b9432896d25b41938a27a554bbe7"
        hash = "cdd8966e0cf08a6578e34de7498a44413a6adabae04d81ef3129f26305966db2"
        hash = "df890974589ed2435f53b8c8f147a06752f1b37404afd4431362c1938fcb451e"
        hash = "3e05d8abaaa95af359e5b09efb30546d0aa693859ebc8a0970a2641556ea644c"
        hash = "1c8ddf4b9c99c8f1945abf1527c7fa93141430680ac156a405d9a927d32f3b5e"
        hash = "5d2ed5930ab1a650f9fb9293f49a9f35737139fdfa9f14e46a07e5d4d721ae3e"
        hash = "18834de3e4844a418970c2184cc78c2d7cb61d18e9f7c7c0e88e994b4212edc5"
        hash = "a6b6fc94d8e582059af0fe30c2c93c687fccd5a0073a6a26a2cd097ea96adc7c"
        hash = "28b40fa160c915f13f046d36725c055d6c827a4d28674ea33c75a9b410321290"
        hash = "efab0fbf77dc67a792efd1fe2b3f46bbdfdee30a9321acc189c53a6c5e90f05c"
        hash = "348781221d1a2886923de089d1b7b12c32cfdd38628b71203da925b5736561e9"
        hash = "a1a5f410e6eab2445d64bfcd742fe1a802a0a2d9af45c7ab398f84894dd5dc3d"
        hash = "9de05ce0d9e9de05ebdc2859a5156f044f98bb180723f427a779d36b1913e5d3"
        hash = "eeff7e85c50a7f11fc8a99f7048953719fb1d2a6451161a0796eac43119ece21"
        hash = "383cc025800a3b3d089f7697e78fe4d5695a8d1ee26dcad0b0956ad6800ccae4"
        hash = "41be6f393cea4d8d5869fff526c4d75ec66c855f7e9c176042c39b9682ea9c14"
        hash = "71552e65433c8bbf14e5bcbc35a708bc10d6fded740c5f4783edce84aea4aabf"
        hash = "3c1b3e8666b58a78c70f36ed557c7ecc52e84457e87e5884b42e5cd9e8c1a303"
        hash = "4288d7113031151a2636a164c0dc6fce78c86f322271afec9ef2d4b54494c334"
        hash = "f73a39332be393a9bc23ec27ff6d025bc90d7320dde97f37cc585ecf6c0436a2"
        hash = "018f5103635992aa9ddc1c46cafe2b7ba659fcfbc8f8ab29dcea28e155b033ee"
        hash = "fe650fc138dcfbbd4ab6aa5718bf3cd36f50898ae19d3aceaa12f7d4f39d0b43"
        hash = "fa21b39cd5a24ba35433e90cae486454b7400b50e7f7f5c190fdbec6704b4352"
        hash = "3dd36c798cc89bfad7cdbf58d7da90ba113fe043ca46bdbcab7ae7fb9dc2f42b"
        hash = "674f4444f0de5c81c766c376a65fbdf1f7116228a61c71ffb504995c9e160183"
        hash = "cd3d25b2842bb2d6a5580f72e819acd344ce7f3a2478fb6d53ff668ad6531228"
        hash = "1668f4eb8a85914db46ff308b9f8a5040a024acc93259dfc004ea2b80ab6bcf1"
        hash = "4f31cab6c011b79bf862bb6acea3086308b0576afe33affdb09039c97e723beb"
        hash = "6b0ff48b8113076d2875edb7bea7f120b7b9d9a990ae296a5b5a95660ae7edfc"
        hash = "956a00dd6382e83d3f7490378ae98e4fc8d9b8ec2cd549519f007091e3ccce1f"
        hash = "8c7f938cf55728d8d41a7fa6b9953c4f81cf05ed3d7b7435ec8999e130257f7f"
        hash = "427ee4d4d18fc0c1196326215e94947f7d8c03794de36d0127231690bf5bf3c0"
        hash = "b6f3ece5bf7b9f6ecf99104d3c76b9007106fad98d20500956dd1e42d4ec5e8d"
        hash = "47a0ad6150c5a1de4c788827662a9cafbd2816a7d32be2028721e49a464acbed"
        hash = "8743ac81384fd10c0459f3574489d626e13c95dd73274dcf1d872bcd3630b9e8"
        hash = "a1755415a12f85bea3f65807860f902cf41e56b0ab2c155ac742af3166ef1dfd"
        hash = "3f5a91500bfade2d9708e1fbe76ae81dacdb7b0f65f335fee598546ccfc267e3"
        hash = "5be43b773dbde6542d6a0d53cd6616ea95a49dd38659edc6ba0d580a0d9777ab"
        hash = "90e080a63916c768b0b65787fe5695fd903d44e1b0b688d06c14988ba30b5ea7"
        hash = "d1184ee3f26919b8f5a4b1a6d089f14e79e0c89260590156111f72a979c8e446"
        hash = "c13ddd2bafcfdfc00fb5cb87d8eb533ae094b0dd5784df77c98bddeac9d72725"
        hash = "9bb3035610bd09ba769c0335f23f98dd85c2f32351cdd907d4761b41ab5d099c"
        hash = "1703025c4aed71d0ca29a3cd0e15047c24cc9adbb5239765f63e205ef7d65753"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"
        hash = "5654ed1205de6860e66383a27231e4ac2bb7639b07504121d313a8503ece3305"
        hash = "5d1e3c495d08982459b4bd4fd2ab073ed2078fce9347627718a7c25adee152e9"
        hash = "458702ae1b2ef8a113344be76af185ee137b7aac3646ece626d2eeeadcc9e003"
        hash = "2c703e562a6266175379fa48f06f58aab109dbe56e0cde24b4b0db5f22f810a3"
        hash = "49faf70c0978c21a68bc8395cf326f50c491e379f55b5df7d17f0af953861ece"
        hash = "a2b16bbef0a7cb545597828466cd13225efaba6e7006bfbf59040bbff54c463c"
        hash = "b08449d42f140c7e4d070c5f81ce7509f48282a5bb0e06948b7ed65053696a37"
        hash = "c1633ad8c9e6c2b4cc23578655fc6cf5cd0122cfd24395d1551af1d092f89db2"
        hash = "01f42f949a37d9d479b8021f27dcf0d0e6f0b0b6cd2e0883c6b4b494f0a1d32a"
        hash = "4943d53a38ac123ed7c04ad44742a67ea06bb54ea02fa241d9c4ebadab4cb99a"
        hash = "597ce12c9fbecc71299ba6fc3e4df36cc49222878d0e080c4c35bbfdffd30083"
        hash = "0265fbd9cfc27c26c42374fce7cf0ef11f38e086308d51648b45f040d767c51d"
        hash = "0dc92a1a6fd27144b3e35a9900038653892d25c2db8ede8b9e0aee04839f165a"
        hash = "682582c324cb1eafacf80090f6108c1580fee12dbfdfe8b51771d429fdcce718"
        hash = "e9e6f6e22b5924f80164fbad45be28299e9ec0bd2f404551b6ca772509a7135a"
        hash = "a8db750f82906fb9cf9fb371ec65be76275d9b81b95e351fcb3db4ef345884ab"
        hash = "e900b4016177259d07011139a55c0571c1e824fb7e9dddc11df493b3c8209173"
        hash = "f8a7a26d51a5e938325deee86cbf5aa8263d3a50818c15d5a395b98658630c18"
        hash = "861b87fc6c4758cfe1e26c7a038cffb64054ad633b7ea81319c9a98b7b49df0d"
        hash = "848fdb491307ed7b002dbdf99796df2b286d53b2e0066d78f3554f2f38a2c438"
        hash = "4b0c05bc33c9e7d0ed2d97dbefb6292469b9d74d650d5cfb2691345a11c0f54a"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"

    strings:
        // works well enough with string search so no need to use the pe module
        $cert1 = "91210242MA0YGH36" wide ascii ///serialNumber=91210242MA0YGH36XJ/jurisdictionC=CN/businessCategory=Private Organization/C=CN/ST=\xE8\xBE\xBD\xE5\xAE\x81\xE7\x9C\x81
        $cert2 = "Copyright (C) 2013-2021 QuickZip. All rights reserved." wide ascii 
        $cert3 = "Qi Lijun" wide ascii // short but no fp
        $cert4 = {51 00 69 00 20 00 4c 00 69 00 6a 00 75 00 6e} // string above in hex(utf16-be minus first 00) because of https://github.com/VirusTotal/yara/issues/1891
        $cert5 = "Luck Bigger Technology Co., Ltd" wide ascii
        $cert6 = {4c 00 75 00 63 00 6b 00 20 00 42 00 69 00 67 00 67 00 65 00 72 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 20 00 43 00 6f 00 2e 00 2c 00 20 00 4c 00 74 00 64 } // above in hex
        $cert7 = "XinSing Network Service Co., Ltd" wide ascii
        $cert8 = "Hangzhou Shunwang Technology Co.,Ltd" wide ascii
        $cert9 = "Zhuhai liancheng Technology Co., Ltd." wide ascii
        $cert10 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert11 = { e5 8c 97 e4 ba ac e5 bc 98 e9 81 93 e9 95 bf e5 85 b4 e5 9b bd e9 99 85 e8 b4 b8 e6 98 93 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert12 = { e7 a6 8f e5 bb ba e5 a5 a5 e5 88 9b e4 ba 92 e5 a8 b1 e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert13 = { e5 8e a6 e9 97 a8 e6 81 92 e4 bf a1 e5 8d 93 e8 b6 8a e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 0a }
        $cert14 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 20MB and
        any of ( $cert* )

}

rule Cobaltbaltstrike_Beacon_XORed_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
    // x86 xor decrypt loop
        // 52 bytes variant
        $h01 = { FC E8??000000 [0-32] EB27 ?? 8B?? 83??04 8B?? 31?? 83??04 ?? 8B?? 31?? 89?? 31?? 83??04 83??04 31?? 39?? 7402 EBEA ?? FF?? E8D4FFFFFF }
        // 56 bytes variant
        $h02 = { FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }
    // end of xor decrypt loop
        $h11 = { 7402 EB(E8|EA) ?? FF?? E8(D0|D4)FFFFFF }
  condition:
        any of ($h0*) and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5AE800 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5AE8 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}

rule Beacon_K5om {
   meta:
      description = "Detects Meterpreter Beacon - file K5om.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html"
      date = "2017-06-07"
      hash1 = "e3494fd2cc7e9e02cff76841630892e4baed34a3e1ef2b9ae4e2608f9a4d7be9"
   strings:
      $x1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii

      $s1 = "Could not open process token: %d (%u)" fullword ascii
      $s2 = "0fd00b.dll" fullword ascii
      $s3 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s4 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them ) )
}

rule Leviathan_CobaltStrike_Sample_1 {
   meta:
      description = "Detects Cobalt Strike sample from Leviathan report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"
   strings:
      $x1 = "a54c81.dll" fullword ascii
      $x2 = "%d is an x64 process (can't inject x86 content)" fullword ascii
      $x3 = "Failed to impersonate logged on user %d (%u)" fullword ascii

      $s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $s2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $s3 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
      $s4 = "could not write to process memory: %d" fullword ascii
      $s5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s6 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them )
}

rule WiltedTulip_ReflectiveLoader {
   meta:
      description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
      hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
      hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
      hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
      hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x4 = "Failed to impersonate token from %d (%u)" fullword ascii
      $x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or
      ( 2 of them ) or
      pe.exports("_ReflectiveLoader@4")
}

rule Malware_QA_vqgk {
	meta:
		description = "VT Research QA uploaded malware - file vqgk.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		modified = "2022-12-21"
		score = 80
		hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
	strings:
		$x1 = "Z:\\devcenter\\aggressor\\external" ascii
		$x2 = "\\beacon\\Release\\beacon.pdb" ascii
		$x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii
		$x4 = "%d is an x64 process (can't inject x86 content)" fullword ascii

		$s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$s2 = "Could not open process token: %d (%u)" fullword ascii
		$s3 = "\\\\%s\\pipe\\msagent_%x" fullword ascii
		$s4 = "\\sysnative\\rundll32.exe" ascii
		$s5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
		$s6 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
		$s7 = "could not write to process memory: %d" fullword ascii
		$s8 = "beacon.dll" fullword ascii
		$s9 = "Failed to impersonate token from %d (%u)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 5 of ($s*) ) ) or ( 7 of them )
}


rule PowerShell_Susp_Parameter_Combo : HIGHVOL FILE {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      modified = "2022-09-15"
      score = 60
   strings:
      /* Encoded Command */
      $sa1 = " -enc " ascii wide nocase
      $sa2 = " -EncodedCommand " ascii wide nocase
      $sa3 = " /enc " ascii wide nocase
      $sa4 = " /EncodedCommand " ascii wide nocase

      /* Window Hidden */
      $sb1 = " -w hidden " ascii wide nocase
      $sb2 = " -window hidden " ascii wide nocase
      $sb3 = " -windowstyle hidden " ascii wide nocase
      $sb4 = " /w hidden " ascii wide nocase
      $sb5 = " /window hidden " ascii wide nocase
      $sb6 = " /windowstyle hidden " ascii wide nocase

      /* Non Profile */
      $sc1 = " -nop " ascii wide nocase
      $sc2 = " -noprofile " ascii wide nocase
      $sc3 = " /nop " ascii wide nocase
      $sc4 = " /noprofile " ascii wide nocase

      /* Non Interactive */
      $sd1 = " -noni " ascii wide nocase
      $sd2 = " -noninteractive " ascii wide nocase
      $sd3 = " /noni " ascii wide nocase
      $sd4 = " /noninteractive " ascii wide nocase

      /* Exec Bypass */
      $se1 = " -ep bypass " ascii wide nocase
      $se2 = " -exec bypass " ascii wide nocase
      $se3 = " -executionpolicy bypass " ascii wide nocase
      $se4 = " -exec bypass " ascii wide nocase
      $se5 = " /ep bypass " ascii wide nocase
      $se6 = " /exec bypass " ascii wide nocase
      $se7 = " /executionpolicy bypass " ascii wide nocase
      $se8 = " /exec bypass " ascii wide nocase

      /* Single Threaded - PowerShell Empire */
      $sf1 = " -sta " ascii wide
      $sf2 = " /sta " ascii wide

      $fp1 = "Chocolatey Software" ascii wide
      $fp2 = "VBOX_MSI_INSTALL_PATH" ascii wide
      $fp3 = "\\Local\\Temp\\en-US.ps1" ascii wide
      $fp4 = "Lenovo Vantage - Battery Gauge Helper" wide fullword
      $fp5 = "\\LastPass\\lpwinmetro\\AppxUpgradeUwp.ps1" ascii
      $fp6 = "# use the encoded form to mitigate quoting complications that full scriptblock transfer exposes" ascii /* MS TSSv2 - https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2 */
      $fp7 = "Write-AnsibleLog \"INFO - s" ascii
      $fp8 = "\\Packages\\Matrix42\\" ascii
      $fp9 = "echo " ascii
      $fp10 = "install" ascii fullword
      $fp11 = "REM " ascii
      $fp12 = "set /p " ascii
      $fp13 = "rxScan Application" wide

      $fpa1 = "All Rights"
      $fpa2 = "<html"
      $fpa2b = "<HTML"
      $fpa3 = "Copyright"
      $fpa4 = "License"
      $fpa5 = "<?xml"
      $fpa6 = "Help" fullword
      $fpa7 = "COPYRIGHT"
   condition:
      filesize < 3000KB and 4 of ($s*) and not 1 of ($fp*) and uint32be(0) != 0x456C6646 /* EVTX - we don't wish to mix the entries together */
}

rule APT_CobaltStrike_Beacon_Indicator {
   meta:
      description = "Detects CobaltStrike beacons"
      author = "JPCERT"
      reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
      date = "2018-11-09"
   strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Cobaltbaltstrike_Beacon_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
  strings:
    // x86 default MZ header
    $h01 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 ?? ?? ?? ?? FF D3 68 }
    // decoded config blob
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    // xored config blob v3
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    // xored config blob v4
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule Methodology_Suspicious_Shortcut_SMB_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects remote SMB path for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    sample = "e0bef7497fcb284edb0c65b59d511830"
    score = 50
    date = "27.09.2019"
  strings:
    $file = /URL=file:\/\/[a-z0-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
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

rule Windows_Trojan_CobaltStrike_7f8da98a {
    meta:
        author = "Elastic Security"
        id = "7f8da98a-3336-482b-91da-82c7cef34c62"
        fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }
    condition:
        all of them
}

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

rule Windows_Trojan_CobaltStrike_3dc22d14 {
    meta:
        author = "Elastic Security"
        id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
        fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $a2 = "%s as %s\\%s: %d" fullword
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_c851687a {
    meta:
        author = "Elastic Security"
        id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
        fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC Bypass module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
    condition:
        2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_09b79efa {
    meta:
        author = "Elastic Security"
        id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
        fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Invoke Assembly module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "invokeassembly.x64.dll" ascii fullword
        $a2 = "invokeassembly.dll" ascii fullword
        $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $b3 = "[-] Failed to create the runtime host" ascii fullword
        $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $b6 = "ReflectiveLoader"
        $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $b8 = "[-] No .NET runtime found. :(" ascii fullword
        $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
    condition:
        1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb {
    meta:
        author = "Elastic Security"
        id = "15f680fb-a04f-472d-a182-0b9bee111351"
        fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netview module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "netview.x64.dll" ascii fullword
        $a2 = "netview.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\netview" ascii fullword
        $b1 = "Sessions for \\\\%s:" ascii fullword
        $b2 = "Account information for %s on \\\\%s:" ascii fullword
        $b3 = "Users for \\\\%s:" ascii fullword
        $b4 = "Shares at \\\\%s:" ascii fullword
        $b5 = "ReflectiveLoader" ascii fullword
        $b6 = "Password changeable" ascii fullword
        $b7 = "User's Comment" wide fullword
        $b8 = "List of hosts for domain '%s':" ascii fullword
        $b9 = "Password changeable" ascii fullword
        $b10 = "Logged on users at \\\\%s:" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
    meta:
        author = "Elastic Security"
        id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
        fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Portscan module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "portscan.x64.dll" ascii fullword
        $a2 = "portscan.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\portscan" ascii fullword
        $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $b2 = "(ARP) Target '%s' is alive. " ascii fullword
        $b3 = "TARGETS!12345" ascii fullword
        $b4 = "ReflectiveLoader" ascii fullword
        $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $b6 = "Scanner module is complete" ascii fullword
        $b7 = "pingpong" ascii fullword
        $b8 = "PORTS!12345" ascii fullword
        $b9 = "%s:%d (%s)" ascii fullword
        $b10 = "PREFERENCES!12345" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
    meta:
        author = "Elastic Security"
        id = "91e08059-46a8-47d0-91c9-e86874951a4a"
        fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Post Ex module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "postex.x64.dll" ascii fullword
        $a2 = "postex.dll" ascii fullword
        $a3 = "RunAsAdminCMSTP" ascii fullword
        $a4 = "KerberosTicketPurge" ascii fullword
        $b1 = "GetSystem" ascii fullword
        $b2 = "HelloWorld" ascii fullword
        $b3 = "KerberosTicketUse" ascii fullword
        $b4 = "SpawnAsAdmin" ascii fullword
        $b5 = "RunAsAdmin" ascii fullword
        $b6 = "NetDomain" ascii fullword
    condition:
        2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
    meta:
        author = "Elastic Security"
        id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
        fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Screenshot module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "screenshot.x64.dll" ascii fullword
        $a2 = "screenshot.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $b2 = "GetDesktopWindow" ascii fullword
        $b3 = "CreateCompatibleBitmap" ascii fullword
        $b4 = "GDI32.dll" ascii fullword
        $b5 = "ReflectiveLoader"
        $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
    condition:
        2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_1787eef5 {
    meta:
        author = "Elastic Security"
        id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
        fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
        creation_date = "2022-08-29"
        last_modified = "2022-09-29"
        description = "CS shellcode variants"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_663fc95d {
    meta:
        author = "Elastic Security"
        id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
        fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
        creation_date = "2021-04-01"
        last_modified = "2021-12-17"
        description = "Identifies CobaltStrike via unidentified function code"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        author = "Elastic Security"
        id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
        fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep obfuscation routine"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
    meta:
        author = "Elastic Security"
        id = "ee756db7-e177-41f0-af99-c44646d334f7"
        fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
    meta:
        author = "Elastic Security"
        id = "29374056-03ce-484b-8b2d-fbf75be86e27"
        fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike MZ Reflective Loader."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_Metasploit_38b8ceec {
    meta:
        author = "Elastic Security"
        id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
        fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 85
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_7bc0f998 {
    meta:
        author = "Elastic Security"
        id = "7bc0f998-7014-4883-8a56-d5ee00c15aed"
        fingerprint = "fdb5c665503f07b2fc1ed7e4e688295e1222a500bfb68418661db60c8e75e835"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function leverage by metasploit shellcode"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 84
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_c9773203 {
    meta:
        author = "Elastic Security"
        id = "c9773203-6d1e-4246-a1e0-314217e0207a"
        fingerprint = "afde93eeb14b4d0c182f475a22430f101394938868741ffa06445e478b6ece36"
        creation_date = "2021-04-07"
        last_modified = "2021-08-23"
        description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
        threat_name = "Windows.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
        severity = 10
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }
    condition:
        all of them
}

rule CobaltStrikeBeacon
{
    meta:
        author = "ditekshen, enzo & Elastic"
        description = "Cobalt Strike Beacon Payload"
        cape_type = "CobaltStrikeBeacon Payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii
        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
        $ver3a = {69 68 69 68 69 6b ?? ?? 69}
        $ver3b = {69 69 69 69}
        $ver4a = {2e 2f 2e 2f 2e 2c ?? ?? 2e}
        $ver4b = {2e 2e 2e 2e}
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x00-0xff)
        $a2 = "Started service %s on %s" xor(0x00-0xff)
        $a3 = "%s as %s\\%s: %d" xor(0x00-0xff)
        $b_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
        $b_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
    condition:
        all of ($ver3*) or all of ($ver4*) or 2 of ($a*) or any of ($b*) or 5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)
}

rule GetTickCountAntiVM
{
    meta:
        author = "kevoreilly"
        description = "GetTickCountAntiVM bypass"
        cape_options = "bp0=$antivm1-13,bp0=$antivm5-40,bp0=$antivm6,action0=wret,hc0=1,bp1=$antivm2-6,action1=wret,hc1=1,count=1,bp2=$antivm3+42,action2=jmp:96,bp3=$antivm4-9,action3=wret,hc3=1"
        hash = "662bc7839ed7ddd82d5fdafa29fafd9a9ec299c28820fe4104fbba9be1a09c42"
        hash = "00f1537b13933762e1146e41f3bac668123fac7eacd0aa1f7be0aa37a91ef3ce"
        hash = "549bca48d0bac94b6a1e6eb36647cd007fed5c0e75a0e4aa315ceabdafe46541"
        hash = "90c29a66209be554dfbd2740f6a54d12616da35d0e5e4af97eb2376b9d053457"
    strings:
        $antivm1 = {57 FF D6 FF D6 BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm2 = {F2 0F 11 45 ?? FF 15 [4] 6A 00 68 10 27 00 00 52 50 E8 [4] 8B C8 E8 [4] F2 0F 59 45}
        $antivm3 = {0F 57 C0 E8 [4] 8B 35 [4] BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm4 = {F2 0F 11 45 EC FF 15 [4] 8B DA 8B C8 BA [4] 89 5D FC F7 E2 BF [4] 89 45 F4 8B F2 8B C1 B9}
        $antivm5 = {BB 01 00 00 00 8B FB 90 FF 15 [4] FF C7 66 0F 6E C7 F3 0F E6 C0 66 0F 2F F8 73 EA}
        $antivm6 = {48 81 EC 88 00 00 00 0F 57 C0 F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11}
    condition:
        any of them
}

rule trojan_win_cobaltstrike : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-25"
        description = "The CobaltStrike malware family."
        hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "%s (admin)" fullword
        $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
        $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $s4 = "%s as %s\\%s: %d" fullword
        $s5 = "%s&%s=%s" fullword
        $s6 = "rijndael" fullword
        $s7 = "(null)"

    condition:
        all of them
}

rule ISO_exec
{
    meta:
        id = "2QhuTkbDSP1KGwZGeesrla"
        fingerprint = "27b4636deff9f19acfbbdc00cf198904d3eb630896514fb168a3dc5256abd7b4"
        version = "1.0"
        first_imported = "2022-07-29"
        last_modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in ISO files, seen in malware such as Bumblebee."
        category = "MALWARE"

strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}


private rule isLNK
{
    meta:
        id = "1XKPrHhGUVGxZ9ZtveVhF9"
        fingerprint = "399c994f697568637efb30910b80f5ae7bedd42bf1cf4188cb74610e46cb23a8"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "INFO"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk at 0
}

rule PS_in_LNK
{
    meta:
        id = "5PjnTrwMNGYdZahLd6yrPa"
        fingerprint = "d89b0413d59b57e5177261530ed1fb60f0f6078951a928caf11b2db1c2ec5109"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerShell artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".ps1" ascii wide nocase
        $ = "powershell" ascii wide nocase
        $ = "invoke" ascii wide nocase
        $ = "[Convert]" ascii wide nocase
        $ = "FromBase" ascii wide nocase
        $ = "-exec" ascii wide nocase
        $ = "-nop" ascii wide nocase
        $ = "-noni" ascii wide nocase
        $ = "-w hidden" ascii wide nocase
        $ = "-enc" ascii wide nocase
        $ = "-decode" ascii wide nocase
        $ = "bypass" ascii wide nocase

    condition:
        isLNK and any of them
}

rule EXE_in_LNK
{
    meta:
        id = "3SSZmnnXU0l4qoc9wubdhN"
        fingerprint = "f169fab39da34f827cdff5ee022374f7c1cc0b171da9c2bb718d8fee9657d7a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".exe" ascii wide nocase
        $ = ".dll" ascii wide nocase
        $ = ".scr" ascii wide nocase
        $ = ".pif" ascii wide nocase
        $ = "This program" ascii wide nocase
        $ = "TVqQAA" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Archive_in_LNK
{
    meta:
        id = "2ku4ClpAScswD86dAiYijX"
        fingerprint = "91946edcd14021c70c3dc4e1898b346f671095e87715df73fa4db3a70074b918"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies archive (compressed) files in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".7z" ascii wide nocase
        $ = ".zip" ascii wide nocase
        $ = ".cab" ascii wide nocase
        $ = ".iso" ascii wide nocase
        $ = ".rar" ascii wide nocase
        $ = ".bz2" ascii wide nocase
        $ = ".tar" ascii wide nocase
        $ = ".lzh" ascii wide nocase
        $ = ".dat" ascii wide nocase
        $ = "WinRAR\\Rar.exe" ascii wide nocase
        $ = "expand" ascii wide nocase
        $ = "makecab" ascii wide nocase
        $ = "UEsDBA" ascii wide nocase
        $ = "TVNDRg" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Download_in_LNK
{
    meta:
        id = "4oUWRvBhzXFLJVKxasN6Cd"
        fingerprint = "9b95b86b48df38523f1e382483c7a7fd96da1a0244b5ebdd2327eaf904afd117"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies download artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "bitsadmin" ascii wide nocase
        $ = "certutil" ascii wide nocase
        $ = "ServerXMLHTTP" ascii wide nocase
        $ = "http" ascii wide nocase
        $ = "ftp" ascii wide nocase
        $ = ".url" ascii wide nocase

    condition:
        isLNK and any of them
}

rule PyInstaller
{
    meta:
        id = "6Pyq57uDDAEHbltmbp7xRT"
        fingerprint = "ae849936b19be3eb491d658026b252c2f72dcb3c07c6bddecb7f72ad74903eee"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller."
        category = "MALWARE"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}

rule MALW_cobaltrike
{
    meta:
    
        description = "Rule to detect CobaltStrike beacon"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-07-19"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/CobaltStrike"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
    
    strings:

        $pattern_0 = { e9???????? eb0a b801000000 e9???????? }
        $pattern_1 = { 3bc7 750d ff15???????? 3d33270000 }
        $pattern_2 = { 8bd0 e8???????? 85c0 7e0e }
        $pattern_3 = { 50 8d8d24efffff 51 e8???????? }
        $pattern_4 = { 03b5d4eeffff 89b5c8eeffff 3bf7 72bd 3bf7 }
        $pattern_5 = { 8b450c 8945f4 8d45f4 50 }
        $pattern_6 = { 33c5 8945fc 8b4508 53 56 ff750c 33db }
        $pattern_7 = { e8???????? e9???????? 833d????????01 7505 e8???????? }
        $pattern_8 = { 53 53 8d85f4faffff 50 }
        $pattern_9 = { 68???????? 53 50 e8???????? 83c424 }
        $pattern_10 = { 488b4c2420 8b0401 8b4c2408 33c8 8bc1 89442408 }
        $pattern_11 = { 488d4d97 e8???????? 4c8d9c24d0000000 418bc7 498b5b20 498b7328 498b7b30 }
        $pattern_12 = { bd08000000 85d2 7459 ffcf 4d85ed }
        $pattern_13 = { 4183c9ff 33d2 ff15???????? 4c63c0 4983f8ff }
        $pattern_14 = { 49c1e002 e8???????? 03f3 4d8d349e 3bf5 7d13 }
        $pattern_15 = { 752c 4c8d45af 488d55af 488d4d27 }
   
    condition:

        7 of them and filesize < 696320
}

rule CobaltStrike {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $v2 = { 69 69 69 69 69 69 69 69 }

          condition: all of them
}



