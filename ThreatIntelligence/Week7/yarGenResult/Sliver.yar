/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-19
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_2b786b8895d814c5d825f4eac99b009eb6aa16f66f6e5191b023e4ebc99fda66 {
   meta:
      description = "mw - file 2b786b8895d814c5d825f4eac99b009eb6aa16f66f6e5191b023e4ebc99fda66"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2b786b8895d814c5d825f4eac99b009eb6aa16f66f6e5191b023e4ebc99fda66"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Espio-main\\loader\\x64\\Release\\Espio.pdb" fullword ascii /* score: '42.00'*/
      $x2 = "C:\\windows\\system32\\ntdll.dll" fullword ascii /* score: '37.00'*/
      $s3 = "\\??\\C:\\Windows\\System32\\werfault.exe" fullword wide /* score: '30.00'*/
      $s4 = "MHg0OTB4MTIweDRkMHg5MzB4NzcweDE1MHg3MzB4Y2IweDY1MHgwOTB4OTUweDlmMHgxYTB4NDQweDUzMHg2NzB4YTQweGJmMHhkMjB4NjUweDZmMHg2NDB4M2EweDll" ascii /* base64 encoded string '0x490x120x4d0x930x770x150x730xcb0x650x090x950x9f0x1a0x440x530x670xa40xbf0xd20x650x6f0x640x3a0x9e' */ /* score: '26.00'*/
      $s5 = "MHgxZTB4NTcweDhiMHhlMDB4MWEweDcyMHg5NjB4ZDMweGVkMHg3NTB4MTEweDRmMHgwZTB4ODIweDZkMHg5MDB4MjUweDllMHhiOTB4YTcweGZiMHhjMzB4OWQweDky" ascii /* base64 encoded string '0x1e0x570x8b0xe00x1a0x720x960xd30xed0x750x110x4f0x0e0x820x6d0x900x250x9e0xb90xa70xfb0xc30x9d0x92' */ /* score: '26.00'*/
      $s6 = "MHhiMzB4MzkweGIwMHg1NTB4OWMweGE2MHg0NTB4NjIweDdjMHg5MjB4MWMweDU0MHg2ODB4NTIweDU3MHhmMzB4MmIweDlhMHhlNTB4NmIweGUwMHgyYjB4M2IweDll" ascii /* base64 encoded string '0xb30x390xb00x550x9c0xa60x450x620x7c0x920x1c0x540x680x520x570xf30x2b0x9a0xe50x6b0xe00x2b0x3b0x9e' */ /* score: '26.00'*/
      $s7 = "MHhmZDB4ZmYweDgxMHgzNjB4N2YweGQ1MHgwYTB4N2UweDEzMHgxZjB4OTAweGZlMHg4NjB4ODIweDllMHhiZDB4MjkweGQyMHgyNzB4MWEweDc1MHhiZjB4ZDgweDI5" ascii /* base64 encoded string '0xfd0xff0x810x360x7f0xd50x0a0x7e0x130x1f0x900xfe0x860x820x9e0xbd0x290xd20x270x1a0x750xbf0xd80x29' */ /* score: '26.00'*/
      $s8 = "MHhkYzB4NzQweDUyMHg3ZDB4NTQweDZiMHg2OTB4NDkweDllMHhjMDB4OTUweDBlMHgyNjB4N2IweDQzMHhkMjB4NjcweGNkMHg0ZjB4MGUweDc0MHhjYTB4ZWMweDU5" ascii /* base64 encoded string '0xdc0x740x520x7d0x540x6b0x690x490x9e0xc00x950x0e0x260x7b0x430xd20x670xcd0x4f0x0e0x740xca0xec0x59' */ /* score: '26.00'*/
      $s9 = "MHg0ZTB4NjIweGFhMHgyODB4NjkweDBiMHgzNjB4ZTEweDllMHhhOTB4YTYweGJhMHhjOTB4ZDUweGU2MHhmMDB4NDYweDIxMHgyNDB4MDcweDUyMHgwZjB4ZmMweGFi" ascii /* base64 encoded string '0x4e0x620xaa0x280x690x0b0x360xe10x9e0xa90xa60xba0xc90xd50xe60xf00x460x210x240x070x520x0f0xfc0xab' */ /* score: '26.00'*/
      $s10 = "MHg1YTB4YWQweDQ2MHg1NDB4YTkweGJkMHhhNzB4MmIweDUzMHg0ZDB4ZDMweGI3MHg5YjB4ZTEweDllMHhiZjB4ZWQweDJlMHg0MjB4ZjUweDE1MHgzNDB4YzIweGJh" ascii /* base64 encoded string '0x5a0xad0x460x540xa90xbd0xa70x2b0x530x4d0xd30xb70x9b0xe10x9e0xbf0xed0x2e0x420xf50x150x340xc20xba' */ /* score: '26.00'*/
      $s11 = "MHg5NjB4YjgweDk4MHhiMzB4OTMweDllMHhjOTB4NDQweDM2MHhkZTB4NzQweDk0MHg1NjB4N2EweDY5MHg2ODB4ZTYweGE1MHg0MTB4MzAweDJiMHhiYzB4NGUweGEw" ascii /* base64 encoded string '0x960xb80x980xb30x930x9e0xc90x440x360xde0x740x940x560x7a0x690x680xe60xa50x410x300x2b0xbc0x4e0xa0' */ /* score: '26.00'*/
      $s12 = "MHhiMzB4YzAweDFjMHg3MzB4MDkweGQ1MHgyOTB4MmQweGM3MHgzNzB4ZTUweDQwMHg4MTB4MjAweGU4MHg0MjB4ZTEweDllMHhiNDB4NGEweDliMHg3ZjB4MjEweDI3" ascii /* base64 encoded string '0xb30xc00x1c0x730x090xd50x290x2d0xc70x370xe50x400x810x200xe80x420xe10x9e0xb40x4a0x9b0x7f0x210x27' */ /* score: '26.00'*/
      $s13 = "MHhkODB4OWEweDc1MHgzYzB4ZjEweDZmMHgwMTB4YjYweDllMHg2ZjB4NzEweDdkMHgyMjB4YzEweDM0MHg1NzB4ZDMweGRjMHg4NzB4OTcweGYwMHg4NTB4MjAweGY4" ascii /* base64 encoded string '0xd80x9a0x750x3c0xf10x6f0x010xb60x9e0x6f0x710x7d0x220xc10x340x570xd30xdc0x870x970xf00x850x200xf8' */ /* score: '26.00'*/
      $s14 = "MHhmZjB4M2UweGU1MHgwMjB4ZDIweDg5MHg5YjB4NTEweDllMHg3MDB4NDMweDkyMHg5ZTB4YTMweDNlMHgwNTB4OWMweGMzMHhjMjB4ZjYweGZlMHg5ZjB4N2YweDgy" ascii /* base64 encoded string '0xff0x3e0xe50x020xd20x890x9b0x510x9e0x700x430x920x9e0xa30x3e0x050x9c0xc30xc20xf60xfe0x9f0x7f0x82' */ /* score: '26.00'*/
      $s15 = "MHgwNjB4OTYweDYwMHg2ZDB4YjAweDA3MHhlODB4NDkweDllMHg4NzB4ODEweDU2MHhkOTB4ZTkweDFlMHgwZjB4ZGYweGJkMHg2NDB4MDcweDAxMHgyYzB4ZTcweGYz" ascii /* base64 encoded string '0x060x960x600x6d0xb00x070xe80x490x9e0x870x810x560xd90xe90x1e0x0f0xdf0xbd0x640x070x010x2c0xe70xf3' */ /* score: '26.00'*/
      $s16 = "MHg3ZDB4NGIweGJkMHg5MzB4NjEweDAxMHgxMTB4NGQweDc0MHhlZDB4ZTYweDNhMHgyNjB4ODkweDdjMHg2MjB4ZDUweGI3MHgwZTB4ZmUweDllMHgzNTB4NDgweGUy" ascii /* base64 encoded string '0x7d0x4b0xbd0x930x610x010x110x4d0x740xed0xe60x3a0x260x890x7c0x620xd50xb70x0e0xfe0x9e0x350x480xe2' */ /* score: '26.00'*/
      $s17 = "MHgxZDB4MWIweGIzMHg4OTB4ZmUweGZmMHg2MDB4OTEweDllMHg1YjB4MjYweDdhMHhhNzB4Y2QweDQwMHg1ODB4MGIweDZlMHg5NzB4MzgweDczMHg1YjB4MTcweGRm" ascii /* base64 encoded string '0x1d0x1b0xb30x890xfe0xff0x600x910x9e0x5b0x260x7a0xa70xcd0x400x580x0b0x6e0x970x380x730x5b0x170xdf' */ /* score: '26.00'*/
      $s18 = "MHhhMzB4MTgweDQ2MHgxYjB4MDAweDllMHg3NzB4NjMweDI3MHhmYjB4NzMweDY4MHgyZjB4N2MweDAwMHhiYjB4MjMweDY1MHg3YjB4NjYweGFkMHg0YTB4MWMweDZk" ascii /* base64 encoded string '0xa30x180x460x1b0x000x9e0x770x630x270xfb0x730x680x2f0x7c0x000xbb0x230x650x7b0x660xad0x4a0x1c0x6d' */ /* score: '26.00'*/
      $s19 = "MHg2YzB4NDgweGUyMHhjNzB4OGQweDY2MHg1NzB4YWMweGM3MHgxNzB4OTgweDllMHg5MjB4MTgweGZkMHgxYTB4MmIweDY0MHhkODB4ZTUweGE5MHhiNDB4ZDYweDli" ascii /* base64 encoded string '0x6c0x480xe20xc70x8d0x660x570xac0xc70x170x980x9e0x920x180xfd0x1a0x2b0x640xd80xe50xa90xb40xd60x9b' */ /* score: '26.00'*/
      $s20 = "MHgyNTB4MjYweDBiMHg5MDB4ZjcweDQ0MHhkNDB4YTcweDgzMHg1ODB4OWQweDMxMHgxZDB4YTcweDllMHg0ZDB4ZDMweDJjMHgwYzB4ZTAweGNhMHg0MjB4NTAweGZj" ascii /* base64 encoded string '0x250x260x0b0x900xf70x440xd40xa70x830x580x9d0x310x1d0xa70x9e0x4d0xd30x2c0x0c0xe00xca0x420x500xfc' */ /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805 {
   meta:
      description = "mw - file 31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '32.00'*/
      $s3 = "@[!] GsWmHFJarAVjglIbqBGnQwFw FAILED to write decoded payload to allocated memory: " fullword ascii /* score: '26.00'*/
      $s4 = "@[*] GsWmHFJarAVjglIbqBGnQwFw wrote decoded payload to allocated memory successfully." fullword ascii /* score: '23.00'*/
      $s5 = "@[!] GsWmHFJarAVjglIbqBGnQwFw failed to write bytes to target address: " fullword ascii /* score: '20.00'*/
      $s6 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii /* score: '19.00'*/
      $s7 = "@Ws2_32.dll" fullword ascii /* score: '17.00'*/
      $s8 = "queryIdleProcessorCycleTime" fullword ascii /* score: '15.00'*/
      $s9 = "queryProcessCycleTime" fullword ascii /* score: '15.00'*/
      $s10 = "@TnRBbGVydFJlc3VtZVRocmVhZA==" fullword ascii /* base64 encoded string 'NtAlertResumeThread' */ /* score: '14.00'*/
      $s11 = "@TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtAllocateVirtualMemory' */ /* score: '14.00'*/
      $s12 = "@TnRXYWl0Rm9yU2luZ2xlT2JqZWN0" fullword ascii /* base64 encoded string 'NtWaitForSingleObject' */ /* score: '14.00'*/
      $s13 = "@TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" fullword ascii /* base64 encoded string 'NtProtectVirtualMemory' */ /* score: '14.00'*/
      $s14 = "SIGSEGV: Illegal storage access. (Attempt to read from nil?)" fullword ascii /* score: '14.00'*/
      $s15 = "@[!] xdTmEyhXSKxTloJELzjZvWor FAILED to allocate memory in created process, exiting: " fullword ascii /* score: '14.00'*/
      $s16 = "@TnRDbG9zZQ==" fullword ascii /* base64 encoded string 'NtClose' */ /* score: '14.00'*/
      $s17 = "@TnRPcGVuUHJvY2Vzcw==" fullword ascii /* base64 encoded string 'NtOpenProcess' */ /* score: '14.00'*/
      $s18 = "@TnRDcmVhdGVUaHJlYWRFeA==" fullword ascii /* base64 encoded string 'NtCreateThreadEx' */ /* score: '14.00'*/
      $s19 = "@TnRRdWV1ZUFwY1RocmVhZA==" fullword ascii /* base64 encoded string 'NtQueueApcThread' */ /* score: '14.00'*/
      $s20 = "@TnRXcml0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtWriteVirtualMemory' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697 {
   meta:
      description = "mw - file 3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '32.00'*/
      $s3 = "@[!] AqnzeLtjVUxxQqTIqpWSbRZD FAILED to write decoded payload to allocated memory: " fullword ascii /* score: '26.00'*/
      $s4 = "@[*] AqnzeLtjVUxxQqTIqpWSbRZD wrote decoded payload to allocated memory successfully." fullword ascii /* score: '23.00'*/
      $s5 = "@[!] AqnzeLtjVUxxQqTIqpWSbRZD failed to write bytes to target address: " fullword ascii /* score: '20.00'*/
      $s6 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii /* score: '19.00'*/
      $s7 = "@Ws2_32.dll" fullword ascii /* score: '17.00'*/
      $s8 = "queryIdleProcessorCycleTime" fullword ascii /* score: '15.00'*/
      $s9 = "queryProcessCycleTime" fullword ascii /* score: '15.00'*/
      $s10 = "@TnRBbGVydFJlc3VtZVRocmVhZA==" fullword ascii /* base64 encoded string 'NtAlertResumeThread' */ /* score: '14.00'*/
      $s11 = "@TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtAllocateVirtualMemory' */ /* score: '14.00'*/
      $s12 = "@TnRXYWl0Rm9yU2luZ2xlT2JqZWN0" fullword ascii /* base64 encoded string 'NtWaitForSingleObject' */ /* score: '14.00'*/
      $s13 = "@TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" fullword ascii /* base64 encoded string 'NtProtectVirtualMemory' */ /* score: '14.00'*/
      $s14 = "SIGSEGV: Illegal storage access. (Attempt to read from nil?)" fullword ascii /* score: '14.00'*/
      $s15 = "@TnRDbG9zZQ==" fullword ascii /* base64 encoded string 'NtClose' */ /* score: '14.00'*/
      $s16 = "@TnRPcGVuUHJvY2Vzcw==" fullword ascii /* base64 encoded string 'NtOpenProcess' */ /* score: '14.00'*/
      $s17 = "@TnRDcmVhdGVUaHJlYWRFeA==" fullword ascii /* base64 encoded string 'NtCreateThreadEx' */ /* score: '14.00'*/
      $s18 = "@TnRRdWV1ZUFwY1RocmVhZA==" fullword ascii /* base64 encoded string 'NtQueueApcThread' */ /* score: '14.00'*/
      $s19 = "@TnRXcml0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtWriteVirtualMemory' */ /* score: '14.00'*/
      $s20 = "@[!] ktVIbmzybiQtPMlVKEPFmsgj FAILED to allocate memory in created process, exiting: " fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1 {
   meta:
      description = "mw - file 443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '32.00'*/
      $s3 = "@[!] zscLENGBBDjRNCaGVqWPolkp FAILED to write decoded payload to allocated memory: " fullword ascii /* score: '26.00'*/
      $s4 = "@[*] zscLENGBBDjRNCaGVqWPolkp wrote decoded payload to allocated memory successfully." fullword ascii /* score: '23.00'*/
      $s5 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii /* score: '19.00'*/
      $s6 = "@Ws2_32.dll" fullword ascii /* score: '17.00'*/
      $s7 = "@[!] zscLENGBBDjRNCaGVqWPolkp failed to write bytes to target address: " fullword ascii /* score: '16.00'*/
      $s8 = "queryIdleProcessorCycleTime" fullword ascii /* score: '15.00'*/
      $s9 = "queryProcessCycleTime" fullword ascii /* score: '15.00'*/
      $s10 = "@TnRBbGVydFJlc3VtZVRocmVhZA==" fullword ascii /* base64 encoded string 'NtAlertResumeThread' */ /* score: '14.00'*/
      $s11 = "@TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtAllocateVirtualMemory' */ /* score: '14.00'*/
      $s12 = "@TnRXYWl0Rm9yU2luZ2xlT2JqZWN0" fullword ascii /* base64 encoded string 'NtWaitForSingleObject' */ /* score: '14.00'*/
      $s13 = "@TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" fullword ascii /* base64 encoded string 'NtProtectVirtualMemory' */ /* score: '14.00'*/
      $s14 = "SIGSEGV: Illegal storage access. (Attempt to read from nil?)" fullword ascii /* score: '14.00'*/
      $s15 = "@TnRDbG9zZQ==" fullword ascii /* base64 encoded string 'NtClose' */ /* score: '14.00'*/
      $s16 = "@TnRPcGVuUHJvY2Vzcw==" fullword ascii /* base64 encoded string 'NtOpenProcess' */ /* score: '14.00'*/
      $s17 = "@TnRDcmVhdGVUaHJlYWRFeA==" fullword ascii /* base64 encoded string 'NtCreateThreadEx' */ /* score: '14.00'*/
      $s18 = "@TnRRdWV1ZUFwY1RocmVhZA==" fullword ascii /* base64 encoded string 'NtQueueApcThread' */ /* score: '14.00'*/
      $s19 = "@TnRXcml0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtWriteVirtualMemory' */ /* score: '14.00'*/
      $s20 = "@[!] GzSoswnfrMSnFcEzRlrfRSzZ FAILED to allocate memory in created process, exiting: " fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb {
   meta:
      description = "mw - file a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb"
   strings:
      $s1 = "PD1iWjxXRTUt" fullword ascii /* base64 encoded string '<=bZ<WE5-' */ /* score: '14.00'*/
      $s2 = "RlBaRWVrIlD" fullword ascii /* base64 encoded string 'FPZEek"P' */ /* score: '14.00'*/
      $s3 = "nfmaforftpg" fullword ascii /* score: '13.00'*/
      $s4 = "loIw!!!" fullword ascii /* score: '13.00'*/
      $s5 = "gAAF.dAA@" fullword ascii /* score: '10.00'*/
      $s6 = "RtlGetC" fullword ascii /* score: '9.00'*/
      $s7 = "2GETlIkZ04NFqhC7" fullword ascii /* score: '9.00'*/
      $s8 = "8B$7= - !" fullword ascii /* score: '9.00'*/
      $s9 = "2!0-3&023" fullword ascii /* score: '9.00'*/ /* hex encoded string ' 0#' */
      $s10 = "wDEYEKLIN_a" fullword ascii /* score: '9.00'*/
      $s11 = "* 8;B`" fullword ascii /* score: '9.00'*/
      $s12 = "<36373839" fullword ascii /* score: '9.00'*/ /* hex encoded string '6789' */
      $s13 = "'4/1@4%164" fullword ascii /* score: '9.00'*/ /* hex encoded string 'AAd' */
      $s14 = "2\\\\\\'9" fullword ascii /* score: '9.00'*/ /* hex encoded string ')' */
      $s15 = "kmaFPIRCzZVbSU9gu" fullword ascii /* score: '9.00'*/
      $s16 = "\"(/69:;<<<=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s17 = "2;?7=/,42&;" fullword ascii /* score: '9.00'*/ /* hex encoded string ''B' */
      $s18 = "a33IRcFJqbiBbymTUeQRt" fullword ascii /* score: '9.00'*/
      $s19 = "3  \"'5\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '5' */
      $s20 = "?ciXddirC" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule sig_5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0 {
   meta:
      description = "mw - file 5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
   strings:
      $x1 = "findrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negative nmspinningincompatible key" ascii /* score: '75.50'*/
      $x2 = "field %v contains invalid UTF-8fmt: unknown base; can't happeninternal error - misuse of itabinvalid Go type %v for field %vinva" ascii /* score: '72.50'*/
      $x3 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '71.50'*/
      $x4 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii /* score: '67.50'*/
      $x5 = "_NSCreateObjectFileImageFromMemoryadding nil Certificate to CertPoolarchive/tar: header field too longarchive/tar: sockets not s" ascii /* score: '66.50'*/
      $x6 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '59.50'*/
      $x7 = "unknown channel type: %vunpacking Question.Classunrecognized command[%d]x509: malformed validityzlib: invalid dictionary to unus" ascii /* score: '58.50'*/
      $x8 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii /* score: '58.50'*/
      $x9 = " to non-Go memory , locked to thread298023223876953125: day out of rangeCaucasian_AlbanianENOLINK (Reserved)Issuer must be setRC" ascii /* score: '52.00'*/
      $x10 = "invalid Mutable on map with non-message value typemallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii /* score: '51.50'*/
      $x11 = "Inscriptional_ParthianInt.Scan: invalid verbNyiakeng_Puachue_HmongSIGTSTP: keyboard stopXXX_InternalExtensionsaddress already in" ascii /* score: '51.00'*/
      $x12 = "non-IPv4 addressnon-IPv6 addresspacer: H_m_prev=policy not foundreflect mismatchregexp: Compile(result too largeruntime:  g:  g=" ascii /* score: '51.00'*/
      $x13 = "heapBitsSetTypeGCProg: small allocationinvalid name in dynamic library commandinvalid value: merging into nil messagemath/big: b" ascii /* score: '50.50'*/
      $x14 = "tls: handshake message of length %d bytes exceeds maximum of %d bytestls: peer doesn't support the certificate custom signature " ascii /* score: '47.50'*/
      $x15 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPr" ascii /* score: '46.00'*/
      $x16 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeSpawnDllReq).GetProcessName" fullword ascii /* score: '45.00'*/
      $x17 = " to unallocated span/usr/share/zoneinfo/37252902984619140625EMULTIHOP (Reserved)Egyptian_HieroglyphsFormat specifies GNUFormat s" ascii /* score: '44.00'*/
      $x18 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeExecuteAssemblyReq).GetProcess" fullword ascii /* score: '44.00'*/
      $x19 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetResponse" fullword ascii /* score: '43.00'*/
      $x20 = "%s%d.%09d(unknown), newval=, oldval=, plugin:, size = , tail = -infinity/bin/bash/dev/null/dev/ptmx2001::/322002::/162441406253f" ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 24000KB and
      1 of ($x*)
}

rule f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a {
   meta:
      description = "mw - file f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '71.50'*/
      $x2 = "findrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negative nmspinningincompatible key" ascii /* score: '70.50'*/
      $x3 = "; DNSSEC ALGORITHM UNDERSTOOD: ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyzagent: generic extension failurebad input point: low order pointb" ascii /* score: '69.50'*/
      $x4 = "; agent: failed to list keysagent: unknown type tag %dasn1: invalid UTF-8 stringbad CPU type in executablebad certificate hash v" ascii /* score: '67.50'*/
      $x5 = "_NSCreateObjectFileImageFromMemoryadding nil Certificate to CertPoolarchive/tar: header field too longarchive/tar: sockets not s" ascii /* score: '66.50'*/
      $x6 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '59.50'*/
      $x7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii /* score: '56.50'*/
      $x8 = "unknown channel type: %vunpacking Question.Classunrecognized command[%d]x509: malformed validityzlib: invalid dictionary to unus" ascii /* score: '53.50'*/
      $x9 = "PrivateExponent: bad authenticationbad extended rcodebad lfnode addressbad manualFreeListbufio: buffer fullchunk out of ordercle" ascii /* score: '52.00'*/
      $x10 = "invalid Mutable on map with non-message value typemallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii /* score: '51.50'*/
      $x11 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPr" ascii /* score: '51.00'*/
      $x12 = "heapBitsSetTypeGCProg: small allocationinvalid name in dynamic library commandinvalid value: merging into nil messagemath/big: b" ascii /* score: '50.50'*/
      $x13 = "address already in useaes128-gcm@openssh.comargument list too longassembly checks failedbad g->status in readybad sweepgen in re" ascii /* score: '48.00'*/
      $x14 = "tls: handshake message of length %d bytes exceeds maximum of %d bytestls: peer doesn't support the certificate custom signature " ascii /* score: '47.50'*/
      $x15 = "%s%d.%09d(unknown), newval=, oldval=, plugin:, size = , tail = -infinity/bin/bash/dev/null/dev/ptmx2001::/322002::/162441406253f" ascii /* score: '47.00'*/
      $x16 = ", i = , id: , not , val .local.onion0.%02d390625; and <-chanACARIDACPKIXALIYOSARGALSASLOPEAnswerArabicAugustBADALGBADKEYBADSIGBI" ascii /* score: '47.00'*/
      $x17 = "= is not  mcount= minutes nalloc= newval= nfreed= packed= pointer stack=[ status %!Month(%d to %d%s: (%s)%s:%d:%d/tmp/.%s0000000" ascii /* score: '46.50'*/
      $x18 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeSpawnDllReq).GetProcessName" fullword ascii /* score: '45.00'*/
      $x19 = "Algorithm: SIGEMT: emulate instruction executedTime.UnmarshalBinary: invalid lengthaddress and mask lengths don't matcharchive/t" ascii /* score: '45.00'*/
      $x20 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeExecuteAssemblyReq).GetProcess" fullword ascii /* score: '44.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 27000KB and
      1 of ($x*)
}

rule fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4 {
   meta:
      description = "mw - file fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
   strings:
      $x1 = "field %v contains invalid UTF-8fmt: unknown base; can't happeninternal error - misuse of itabinvalid Go type %v for field %vinva" ascii /* score: '72.50'*/
      $x2 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '71.50'*/
      $x3 = "findrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negative nmspinningincompatible key" ascii /* score: '70.50'*/
      $x4 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii /* score: '67.50'*/
      $x5 = "_NSCreateObjectFileImageFromMemoryadding nil Certificate to CertPoolarchive/tar: header field too longarchive/tar: sockets not s" ascii /* score: '66.50'*/
      $x6 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '59.50'*/
      $x7 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii /* score: '58.50'*/
      $x8 = "unknown channel type: %vunpacking Question.Classunrecognized command[%d]x509: malformed validityzlib: invalid dictionary to unus" ascii /* score: '58.50'*/
      $x9 = " to non-Go memory , locked to thread298023223876953125: day out of rangeCaucasian_AlbanianENOLINK (Reserved)Issuer must be setRC" ascii /* score: '52.00'*/
      $x10 = "invalid Mutable on map with non-message value typemallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii /* score: '51.50'*/
      $x11 = "Inscriptional_ParthianInt.Scan: invalid verbNyiakeng_Puachue_HmongSIGTSTP: keyboard stopXXX_InternalExtensionsaddress already in" ascii /* score: '51.00'*/
      $x12 = "non-IPv4 addressnon-IPv6 addresspacer: H_m_prev=policy not foundreflect mismatchregexp: Compile(result too largeruntime:  g:  g=" ascii /* score: '51.00'*/
      $x13 = "heapBitsSetTypeGCProg: small allocationinvalid name in dynamic library commandinvalid value: merging into nil messagemath/big: b" ascii /* score: '50.50'*/
      $x14 = "tls: handshake message of length %d bytes exceeds maximum of %d bytestls: peer doesn't support the certificate custom signature " ascii /* score: '47.50'*/
      $x15 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPr" ascii /* score: '46.00'*/
      $x16 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeSpawnDllReq).GetProcessName" fullword ascii /* score: '45.00'*/
      $x17 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeExecuteAssemblyReq).GetProcess" fullword ascii /* score: '44.00'*/
      $x18 = " to unallocated span/usr/share/zoneinfo/37252902984619140625EMULTIHOP (Reserved)Egyptian_HieroglyphsFormat specifies GNUFormat s" ascii /* score: '44.00'*/
      $x19 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetResponse" fullword ascii /* score: '43.00'*/
      $x20 = "%s%d.%09d(unknown), newval=, oldval=, plugin:, size = , tail = -infinity/bin/bash/dev/null/dev/ptmx2001::/322002::/162441406253f" ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 24000KB and
      1 of ($x*)
}

/* Super Rules ------------------------------------------------------------- */

rule _5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0_f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4df_0 {
   meta:
      description = "mw - from files 5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0, f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a, fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
      hash2 = "f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
      hash3 = "fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
   strings:
      $x1 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeSpawnDllReq).GetProcessName" fullword ascii /* score: '45.00'*/
      $x2 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeExecuteAssemblyReq).GetProcess" fullword ascii /* score: '44.00'*/
      $x3 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetResponse" fullword ascii /* score: '43.00'*/
      $x4 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetTimeout" fullword ascii /* score: '43.00'*/
      $x5 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetRequest" fullword ascii /* score: '43.00'*/
      $x6 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetData" fullword ascii /* score: '43.00'*/
      $x7 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetPid" fullword ascii /* score: '43.00'*/
      $x8 = "github.com/bishopfox/sliver/protobuf/commonpb.(*Process).GetExecutable" fullword ascii /* score: '42.00'*/
      $x9 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeSpawnDllReq).GetProcessName" fullword ascii /* score: '42.00'*/
      $x10 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeGetSystemReq).GetHostingProcess" fullword ascii /* score: '42.00'*/
      $x11 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*SpawnDllReq).GetProcessName" fullword ascii /* score: '41.00'*/
      $x12 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).Descriptor" fullword ascii /* score: '41.00'*/
      $x13 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*InvokeExecuteAssemblyReq).GetProcess" fullword ascii /* score: '41.00'*/
      $x14 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).Descriptor" fullword ascii /* score: '41.00'*/
      $x15 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetPid" fullword ascii /* score: '40.00'*/
      $x16 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetResponse" fullword ascii /* score: '40.00'*/
      $x17 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetTimeout" fullword ascii /* score: '40.00'*/
      $x18 = "github.com/bishopfox/sliver/protobuf/sliverpb.(*ExecuteAssemblyReq).GetProcess" fullword ascii /* score: '40.00'*/
      $x19 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDump).GetData" fullword ascii /* score: '40.00'*/
      $x20 = "_github.com/bishopfox/sliver/protobuf/sliverpb.(*ProcessDumpReq).GetRequest" fullword ascii /* score: '40.00'*/
   condition:
      ( uint16(0) == 0xfacf and filesize < 27000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0_fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd8018304462_1 {
   meta:
      description = "mw - from files 5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0, fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
      hash2 = "fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '71.50'*/
      $x2 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii /* score: '67.50'*/
      $x3 = "_NSCreateObjectFileImageFromMemoryadding nil Certificate to CertPoolarchive/tar: header field too longarchive/tar: sockets not s" ascii /* score: '66.50'*/
      $x4 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '59.50'*/
      $x5 = "ssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have " ascii /* score: '58.50'*/
      $x6 = " to non-Go memory , locked to thread298023223876953125: day out of rangeCaucasian_AlbanianENOLINK (Reserved)Issuer must be setRC" ascii /* score: '52.00'*/
      $x7 = "invalid Mutable on map with non-message value typemallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii /* score: '51.50'*/
      $x8 = "Inscriptional_ParthianInt.Scan: invalid verbNyiakeng_Puachue_HmongSIGTSTP: keyboard stopXXX_InternalExtensionsaddress already in" ascii /* score: '51.00'*/
      $x9 = "non-IPv4 addressnon-IPv6 addresspacer: H_m_prev=policy not foundreflect mismatchregexp: Compile(result too largeruntime:  g:  g=" ascii /* score: '51.00'*/
      $x10 = "heapBitsSetTypeGCProg: small allocationinvalid name in dynamic library commandinvalid value: merging into nil messagemath/big: b" ascii /* score: '50.50'*/
      $x11 = "tls: handshake message of length %d bytes exceeds maximum of %d bytestls: peer doesn't support the certificate custom signature " ascii /* score: '47.50'*/
      $x12 = "%s%d.%09d(unknown), newval=, oldval=, plugin:, size = , tail = -infinity/bin/bash/dev/null/dev/ptmx2001::/322002::/162441406253f" ascii /* score: '43.00'*/
      $x13 = "34694469519536141888238489627838134765625GODEBUG sys/cpu: no value specified for \"MapIter.Next called on exhausted iteratorTime" ascii /* score: '42.50'*/
      $x14 = "/dev/urandom127.0.0.1:53152587890625762939453125<unknown:%d>Bidi_ControlCIDR addressEAFNOSUPPORTECDSA-SHA256ECDSA-SHA384ECDSA-SH" ascii /* score: '41.00'*/
      $x15 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii /* score: '38.50'*/
      $x16 = "^[_a-zA-Z][_a-zA-Z0-9]*$bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertific" ascii /* score: '38.00'*/
      $x17 = "childfailed to get request, %vgot %v, want *struct kindinconsistent poll.fdMutexinvalid encoded signatureinvalid network interfa" ascii /* score: '37.50'*/
      $x18 = "invalid network interface nameinvalid pointer found on stackno message available on STREAMnotetsleep - waitm out of syncoverlapp" ascii /* score: '37.50'*/
      $x19 = "bufio.Scanner: Read returned impossible countcharacter string exceeds maximum length (255)context: internal error: missing cance" ascii /* score: '37.00'*/
      $x20 = ", i = , not , val .local.onion390625; and <-chanAnswerArabicAugustBrahmiBundleCLOSEDCarianChakmaCommonCopticCpu386CpuArmCpuPpcEA" ascii /* score: '35.00'*/
   condition:
      ( uint16(0) == 0xfacf and filesize < 24000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805_3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6_2 {
   meta:
      description = "mw - from files 31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805, 3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697, 443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
      hash2 = "3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
      hash3 = "443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '32.00'*/
      $s3 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii /* score: '19.00'*/
      $s4 = "@Ws2_32.dll" fullword ascii /* score: '17.00'*/
      $s5 = "queryIdleProcessorCycleTime" fullword ascii /* score: '15.00'*/
      $s6 = "queryProcessCycleTime" fullword ascii /* score: '15.00'*/
      $s7 = "@TnRBbGVydFJlc3VtZVRocmVhZA==" fullword ascii /* base64 encoded string 'NtAlertResumeThread' */ /* score: '14.00'*/
      $s8 = "@TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtAllocateVirtualMemory' */ /* score: '14.00'*/
      $s9 = "@TnRXYWl0Rm9yU2luZ2xlT2JqZWN0" fullword ascii /* base64 encoded string 'NtWaitForSingleObject' */ /* score: '14.00'*/
      $s10 = "@TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" fullword ascii /* base64 encoded string 'NtProtectVirtualMemory' */ /* score: '14.00'*/
      $s11 = "SIGSEGV: Illegal storage access. (Attempt to read from nil?)" fullword ascii /* score: '14.00'*/
      $s12 = "@TnRDbG9zZQ==" fullword ascii /* base64 encoded string 'NtClose' */ /* score: '14.00'*/
      $s13 = "@TnRPcGVuUHJvY2Vzcw==" fullword ascii /* base64 encoded string 'NtOpenProcess' */ /* score: '14.00'*/
      $s14 = "@TnRDcmVhdGVUaHJlYWRFeA==" fullword ascii /* base64 encoded string 'NtCreateThreadEx' */ /* score: '14.00'*/
      $s15 = "@TnRRdWV1ZUFwY1RocmVhZA==" fullword ascii /* base64 encoded string 'NtQueueApcThread' */ /* score: '14.00'*/
      $s16 = "@TnRXcml0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtWriteVirtualMemory' */ /* score: '14.00'*/
      $s17 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s18 = "strformat.nim" fullword ascii /* score: '10.00'*/
      $s19 = "fatal.nim" fullword ascii /* score: '10.00'*/
      $s20 = "base64.nim" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0_a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78af_3 {
   meta:
      description = "mw - from files 5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0, a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb, f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a, fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
      hash2 = "a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb"
      hash3 = "f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
      hash4 = "fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
   strings:
      $s1 = "2Uiwp\"9" fullword ascii /* score: '4.00'*/
      $s2 = "'oBFX}k6U" fullword ascii /* score: '4.00'*/
      $s3 = "Cupv]dB" fullword ascii /* score: '4.00'*/
      $s4 = "qKguDid" fullword ascii /* score: '4.00'*/
      $s5 = "v$ZQld#/9h" fullword ascii /* score: '4.00'*/
      $s6 = "DwZhN\"" fullword ascii /* score: '4.00'*/
      $s7 = "sJfw>7G9@>" fullword ascii /* score: '4.00'*/
      $s8 = "Haaf$b%77|X" fullword ascii /* score: '4.00'*/
      $s9 = "so=H*m" fullword ascii /* score: '1.00'*/
      $s10 = "]dW8-n" fullword ascii /* score: '1.00'*/
      $s11 = "#P0_?G0" fullword ascii /* score: '1.00'*/
      $s12 = "hy={uh=" fullword ascii /* score: '1.00'*/
      $s13 = "y#y&Jb" fullword ascii /* score: '1.00'*/
      $s14 = "_ee/?P" fullword ascii /* score: '1.00'*/
      $s15 = "X>Ps.r" fullword ascii /* score: '1.00'*/
      $s16 = "S=v<y5" fullword ascii /* score: '1.00'*/
      $s17 = "wN=:&O" fullword ascii /* score: '1.00'*/
      $s18 = "z1_|'B" fullword ascii /* score: '1.00'*/
      $s19 = "8>G#g$" fullword ascii /* score: '1.00'*/
      $s20 = "?_15]>" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0_f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4df_4 {
   meta:
      description = "mw - from files 5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0, f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5568131f894caf1217f4cbda3dd40c1f39e680ce7727ed4a767cd1986e7805f0"
      hash2 = "f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
   strings:
      $s1 = "github.com/bishopfox/sliver/implant/sliver/cryptography.GetServerECCPublicKey" fullword ascii /* score: '29.00'*/
      $s2 = "_github.com/bishopfox/sliver/implant/sliver/cryptography.GetServerECCPublicKey" fullword ascii /* score: '26.00'*/
      $s3 = "github.com/bishopfox/sliver/implant/sliver/cryptography.ECCEncryptToServer" fullword ascii /* score: '23.00'*/
      $s4 = "_github.com/bishopfox/sliver/implant/sliver/cryptography.eccServerPublicKey" fullword ascii /* score: '21.00'*/
      $s5 = "_github.com/bishopfox/sliver/implant/sliver/cryptography.ECCEncryptToServer" fullword ascii /* score: '20.00'*/
      $s6 = "berGetValue call failedEd25519 verification failureEvalSymlinks: too many linksFixedStack is not power-of-2Prepended_Concatenati" ascii /* score: '8.00'*/
      $s7 = "ReadEnvelope" fullword ascii /* score: '7.00'*/
      $s8 = "time.ParseDuration" fullword ascii /* score: '7.00'*/
      $s9 = "time.leadingFraction" fullword ascii /* score: '7.00'*/
      $s10 = "namedpipL9" fullword ascii /* score: '5.00'*/
      $s11 = "WriteEnvelope" fullword ascii /* score: '4.00'*/
      $s12 = "_time.ParseDuration" fullword ascii /* score: '4.00'*/
      $s13 = "!$'-037" fullword ascii /* score: '1.00'*/
      $s14 = "t$Ow1M" fullword ascii /* score: '1.00'*/
      $s15 = "> work.nprocx509: malformed certificate args stack map entries for 18189894035458564758300781259094947017729282379150390625CFNum" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0xfacf and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805_3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6_5 {
   meta:
      description = "mw - from files 31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805, 3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
      hash2 = "3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
   strings:
      $s1 = "AVVWUSP" fullword ascii /* score: '6.50'*/
      $s2 = "UAVVWSH" fullword ascii /* score: '6.50'*/
      $s3 = "D$HH;D$`" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "D$8H;D$X" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "D$`H;D$h" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "H+D$8H+D$@H" fullword ascii /* score: '1.00'*/
      $s7 = "T$(H+L$(H)" fullword ascii /* score: '1.00'*/
      $s8 = "@[]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s9 = " []_^A^" fullword ascii /* score: '1.00'*/
      $s10 = "[_^A^]" fullword ascii /* score: '1.00'*/
      $s11 = "[]_^A^" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a_fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd8018304462_6 {
   meta:
      description = "mw - from files f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a, fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "f13deec28f6f6d3f4f555f5a2db48cd8a541be52c331ccfccba929e4dfd6bc7a"
      hash2 = "fa647a34b88c5409a58d2f2568147fa03112eb8bfa34bccd801830446213d7c4"
   strings:
      $s1 = "_github.com/bishopfox/sliver/implant/sliver/transports.C2Generator.func1.dwrap.7" fullword ascii /* score: '18.00'*/
      $s2 = "tls: handshake hash for a client certificate requested after discarding the handshake buffertls: unsupported certificate: privat" ascii /* score: '14.50'*/
      $s3 = "comment: minisign public key: E446F78820F7A2FD" fullword ascii /* score: '13.00'*/
      $s4 = "RWT9ovcgiPdG5K/TcYXQi7lkqgjBGzWpe8cTgHdRp+9dop8yu4simkut394020061963944792122790401001436138050797392704654466679482934042457217" ascii /* score: '11.00'*/
      $s5 = "untrusted comment: signature from private key: E446F78820F7A2FD" fullword ascii /* score: '10.00'*/
      $s6 = "namedpip" fullword ascii /* score: '8.00'*/
      $s7 = "namedpipH" fullword ascii /* score: '4.00'*/
      $s8 = "unlock: lock countsignal received during forksigsend: inconsistent statesocket is already connectedssh: scalar is out of rangest" ascii /* score: '3.00'*/
      $s9 = "10003125" ascii /* score: '1.00'*/
      $s10 = "E446F78820F7A2FD" ascii /* score: '1.00'*/
      $s11 = "c04fd430c8Dec" ascii /* score: '1.00'*/
      $s12 = "ack size not a power of 2startm: negative nmspinningstopTheWorld: holding lockstime: invalid location nametimer when must be pos" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0xfacf and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697_443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8_7 {
   meta:
      description = "mw - from files 3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697, 443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3c7965274416eb4007c1d96838bb0d144b2a5e32886a6975d236696ad6824697"
      hash2 = "443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
   strings:
      $s1 = "AWAVAUATVWUSP" fullword ascii /* score: '6.50'*/
      $s2 = "AVVWSH" fullword ascii /* score: '3.50'*/
      $s3 = "D$8H;D$`" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "`[]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s5 = "P[]_^A^" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805_443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8_8 {
   meta:
      description = "mw - from files 31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805, 443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
      hash2 = "443909fd3bd656508ee545e7de7162a83a2820fd844ef64e9b155605f8408dd1"
   strings:
      $s1 = "D$0H;D$H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "P[]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s3 = "H+D$8H)" fullword ascii /* score: '1.00'*/
      $s4 = "p[]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s5 = " []_^A\\A^A_" fullword ascii /* score: '1.00'*/
      $s6 = "\"\"\"\"\"\"\"\"H" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

