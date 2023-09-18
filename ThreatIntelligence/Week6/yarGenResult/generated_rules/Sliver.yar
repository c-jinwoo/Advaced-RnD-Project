/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805 {
   meta:
      description = "mw - file 31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "31e21a23b571fb59b029dbf521ba63302aff87a9de53f16e5e2599060f168805"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii /* score: '36.00'*/
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '32.00'*/
      $s3 = "@[!] GsWmHFJarAVjglIbqBGnQwFw FAILED to write decoded payload to allocated memory: " fullword ascii /* score: '26.00'*/
      $s4 = "@[*] GsWmHFJarAVjglIbqBGnQwFw wrote decoded payload to allocated memory successfully." fullword ascii /* score: '23.00'*/
      $s5 = "@[!] GsWmHFJarAVjglIbqBGnQwFw failed to write bytes to target address: " fullword ascii /* score: '20.00'*/
      $s6 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii /* score: '19.00'*/
      $s7 = "@Ws2_32.dll" fullword ascii /* score: '17.00'*/
      $s8 = "queryProcessCycleTime" fullword ascii /* score: '15.00'*/
      $s9 = "queryIdleProcessorCycleTime" fullword ascii /* score: '15.00'*/
      $s10 = "@[!] xdTmEyhXSKxTloJELzjZvWor FAILED to allocate memory in created process, exiting: " fullword ascii /* score: '14.00'*/
      $s11 = "@TnRXcml0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtWriteVirtualMemory' */ /* score: '14.00'*/
      $s12 = "@TnRRdWV1ZUFwY1RocmVhZA==" fullword ascii /* base64 encoded string 'NtQueueApcThread' */ /* score: '14.00'*/
      $s13 = "@TnRDbG9zZQ==" fullword ascii /* base64 encoded string 'NtClose' */ /* score: '14.00'*/
      $s14 = "SIGSEGV: Illegal storage access. (Attempt to read from nil?)" fullword ascii /* score: '14.00'*/
      $s15 = "@TnRPcGVuUHJvY2Vzcw==" fullword ascii /* base64 encoded string 'NtOpenProcess' */ /* score: '14.00'*/
      $s16 = "@TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" fullword ascii /* base64 encoded string 'NtProtectVirtualMemory' */ /* score: '14.00'*/
      $s17 = "@TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" fullword ascii /* base64 encoded string 'NtAllocateVirtualMemory' */ /* score: '14.00'*/
      $s18 = "@TnRDcmVhdGVUaHJlYWRFeA==" fullword ascii /* base64 encoded string 'NtCreateThreadEx' */ /* score: '14.00'*/
      $s19 = "@TnRBbGVydFJlc3VtZVRocmVhZA==" fullword ascii /* base64 encoded string 'NtAlertResumeThread' */ /* score: '14.00'*/
      $s20 = "@TnRXYWl0Rm9yU2luZ2xlT2JqZWN0" fullword ascii /* base64 encoded string 'NtWaitForSingleObject' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb {
   meta:
      description = "mw - file a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a3a0c54e73818117c90f4b1086144b4975abb6531a9abc6ebd7eef78aff359fb"
   strings:
      $s1 = "RlBaRWVrIlD" fullword ascii /* base64 encoded string 'FPZEek"P' */ /* score: '14.00'*/
      $s2 = "PD1iWjxXRTUt" fullword ascii /* base64 encoded string '<=bZ<WE5-' */ /* score: '14.00'*/
      $s3 = "nfmaforftpg" fullword ascii /* score: '13.00'*/
      $s4 = "loIw!!!" fullword ascii /* score: '13.00'*/
      $s5 = "gAAF.dAA@" fullword ascii /* score: '10.00'*/
      $s6 = "2!0-3&023" fullword ascii /* score: '9.00'*/ /* hex encoded string ' 0#' */
      $s7 = "8B$7= - !" fullword ascii /* score: '9.00'*/
      $s8 = "* 8;B`" fullword ascii /* score: '9.00'*/
      $s9 = "2\\\\\\'9" fullword ascii /* score: '9.00'*/ /* hex encoded string ')' */
      $s10 = "2GETlIkZ04NFqhC7" fullword ascii /* score: '9.00'*/
      $s11 = "\"(/69:;<<<=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s12 = "2;?7=/,42&;" fullword ascii /* score: '9.00'*/ /* hex encoded string ''B' */
      $s13 = "RtlGetC" fullword ascii /* score: '9.00'*/
      $s14 = "3  \"'5\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '5' */
      $s15 = "?ciXddirC" fullword ascii /* score: '9.00'*/
      $s16 = "<36373839" fullword ascii /* score: '9.00'*/ /* hex encoded string '6789' */
      $s17 = "wDEYEKLIN_a" fullword ascii /* score: '9.00'*/
      $s18 = "a33IRcFJqbiBbymTUeQRt" fullword ascii /* score: '9.00'*/
      $s19 = "kmaFPIRCzZVbSU9gu" fullword ascii /* score: '9.00'*/
      $s20 = "'4/1@4%164" fullword ascii /* score: '9.00'*/ /* hex encoded string 'AAd' */
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule sig_9ba024231d4aed094757324d8c65c35d605a51cdc1e18ae570f1b059085c2454 {
   meta:
      description = "mw - file 9ba024231d4aed094757324d8c65c35d605a51cdc1e18ae570f1b059085c2454"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ba024231d4aed094757324d8c65c35d605a51cdc1e18ae570f1b059085c2454"
   strings:
      $s1 = "[BloodyHell]::White('RegAsm.exe',$vHRo)" fullword ascii /* score: '16.00'*/
      $s2 = "Process {" fullword ascii /* score: '15.00'*/
      $s3 = "            $zdzkzHV = New-Object System.IO.Compression.GzipStream $cQFdzHhY, $gkdf" fullword ascii /* score: '9.00'*/
      $s4 = "[byte[]]$decompressedByteArray = CuZjgAU $MNB" fullword ascii /* score: '7.00'*/
      $s5 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s6 = "$t=[System.Reflection.Assembly]::Load($decompressedByteArray)" fullword ascii /* score: '6.00'*/
      $s7 = "    $gkdf=('([IO.Compression.CompressionMode]::Decompress)')|I`E`X" fullword ascii /* score: '6.00'*/
      $s8 = "function CuZjgAU {" fullword ascii /* score: '4.00'*/
      $s9 = "[byte[]] $bout = $FBZjUpPj.ToArray()" fullword ascii /* score: '4.00'*/
      $s10 = ">FD,>>73,>>BC,>>FE,>>37,>>F5,>>F4,>>AA,>>35,>>00,>>62,>>03,>>00'.replace('>>','0x'))| g" fullword ascii /* score: '4.00'*/
      $s11 = "1,>>CB,>>EC,>>2F,>>00,>>78,>>02,>>00'.replace('>>','0x'))| g;" fullword ascii /* score: '4.00'*/
      $s12 = "[Byte[]]$vHRo=('>>1F,>>8B,>>08,>>00,>>00,>>00,>>00,>>00,>>04,>>00,>>CC,>>BD,>>09,>>98,>>5C,>>45,>>B5,>>38,>>7E,>>FB,>>76,>>F7,>>" ascii /* score: '4.00'*/
      $s13 = "$t0='DEX'.replace('D','I');sal g $t0;[Byte[]]$MNB=('>>1F,>>8B,>>08,>>00,>>00,>>00,>>00,>>00,>>04,>>00,>>EC,>>BD,>>77,>>58,>>93,>" ascii /* score: '4.00'*/
      $s14 = "        if ($suZL -le 0){break}" fullword ascii /* score: '3.00'*/
      $s15 = "        $suZL = $zdzkzHV.Read($zZvPkvWeK, 0, 1024)" fullword ascii /* score: '2.00'*/
      $s16 = "        $cQFdzHhY = New-Object System.IO.MemoryStream( , $byteArray )" fullword ascii /* score: '2.00'*/
      $s17 = "    $FBZjUpPj = New-Object System.IO.MemoryStream" fullword ascii /* score: '2.00'*/
      $s18 = ">4E,>>5E,>>B0,>>0A,>>D3,>>3B,>>96,>>09,>>DF,>>7B,>>75,>>BC,>>90,>>51,>>41,>>BE,>>57,>>EA,>>F8,>>31,>>A0,>>22,>>59,>>22,>>A0,>>D5" ascii /* score: '1.00'*/
      $s19 = ">2F,>>E0,>>04,>>40,>>A2,>>81,>>BB,>>E5,>>1E,>>20,>>45,>>DF,>>85,>>2D,>>EC,>>07,>>55,>>D3,>>DD,>>05,>>F6,>>02,>>5F,>>83,>>75,>>FA" ascii /* score: '1.00'*/
      $s20 = ">95,>>45,>>57,>>2B,>>0B,>>AE,>>15,>>DE,>>6A,>>2C,>>B9,>>59,>>76,>>B9,>>E1,>>56,>>D5,>>CD,>>A2,>>C6,>>82,>>84,>>C2,>>6A,>>57,>>17" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 4000KB and
      8 of them
}

rule a3e9fa0774c4a74508d8e082f19b4890ce4103cdb9fb9eb8e4814939c364a60c {
   meta:
      description = "mw - file a3e9fa0774c4a74508d8e082f19b4890ce4103cdb9fb9eb8e4814939c364a60c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a3e9fa0774c4a74508d8e082f19b4890ce4103cdb9fb9eb8e4814939c364a60c"
   strings:
      $x1 = "[Reflection.Assembly]::\"Load\"($UC).\"Get`T`y`p`e\"('NV.b').\"GetMet`h`o`d\"('Execute').Invoke($null - 1000 - 1000 - 1000 - 100" ascii /* score: '46.00'*/
      $x2 = "00 - 1000,[object[]] ('C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe',$MC))" fullword ascii /* score: '31.00'*/
      $s3 = "[Reflection.Assembly]::\"Load\"($UC).\"Get`T`y`p`e\"('NV.b').\"GetMet`h`o`d\"('Execute').Invoke($null - 1000 - 1000 - 1000 - 100" ascii /* score: '27.00'*/
      $s4 = "AMQBhADIAMABkADUAOQA0AGUANQBmADEAZABjAGIANQAxADYAYgAyADUAOQBjADEAOABmADgAOAAzADMAMgBlADEANgBjAGQAMgBlADMAZgBiADUANwA5ADUAZABjADI" ascii /* base64 encoded string '1 a 2 0 d 5 9 4 e 5 f 1 d c b 5 1 6 b 2 5 9 c 1 8 f 8 8 3 3 2 e 1 6 c d 2 e 3 f b 5 7 9 5 d c 2' */ /* score: '21.00'*/
      $s5 = "ANABjADEAMwBhADMANQBlADMAMgA2ADIAZgAzAGIAOAA4ADEAYwBhAGEAOAAwADIAMQA5AGIAZAAwADAANQAzAGEAOQBiAGIAYwBmAGYAYwBmADEAZQA1AGUAZQA2ADI" ascii /* base64 encoded string '4 c 1 3 a 3 5 e 3 2 6 2 f 3 b 8 8 1 c a a 8 0 2 1 9 b d 0 0 5 3 a 9 b b c f f c f 1 e 5 e e 6 2' */ /* score: '21.00'*/
      $s6 = "ANABlADMAYgA4ADEAMwAxADIAYgBjADAANgA0AGYAYgBhAGEANAA4ADEAZgBjADQAMgBlAGQAZQBlAGIAYgAyAGEAOAAzAGEAMgBiADQAMQBjADUAOQAyAGYANgBhAGU" ascii /* base64 encoded string '4 e 3 b 8 1 3 1 2 b c 0 6 4 f b a a 4 8 1 f c 4 2 e d e e b b 2 a 8 3 a 2 b 4 1 c 5 9 2 f 6 a e' */ /* score: '21.00'*/
      $s7 = "ANgAyADQAYwAwAGYANABkADQAYgA0ADQAZQAwADMAZgA3ADYAYwBjADUAMQBkAGMAZABmADEAZAA0AGMANQAzAGUANAA2AGUAMAAwADMAOQBjAGQAMAA0AGUAOQAzADk" ascii /* base64 encoded string '6 2 4 c 0 f 4 d 4 b 4 4 e 0 3 f 7 6 c c 5 1 d c d f 1 d 4 c 5 3 e 4 6 e 0 0 3 9 c d 0 4 e 9 3 9' */ /* score: '21.00'*/
      $s8 = "ANwAwAGMANAA1ADAANgA5ADEAMAA0AGMANgA2ADAAYgAxAGMAOQAwADgANABjADgANgAxADAAYgBlADMAZQBhADIAYQA3ADMAZgAxAGMAZQA2AGEAMgA4AGQANwA3AGM" ascii /* base64 encoded string '7 0 c 4 5 0 6 9 1 0 4 c 6 6 0 b 1 c 9 0 8 4 c 8 6 1 0 b e 3 e a 2 a 7 3 f 1 c e 6 a 2 8 d 7 7 c' */ /* score: '21.00'*/
      $s9 = "AZQBkAGMAMAA4AGEAOQA0ADYAZgA3ADgAYQAyADUAZAA2AGYAOAA1ADQAZgAxADAAZQA0ADkAMQBjAGQANAA1ADUAZgBmAGIAZgBkADUAYgBkAGMAMgA4ADMAZgBhAGY" ascii /* base64 encoded string 'e d c 0 8 a 9 4 6 f 7 8 a 2 5 d 6 f 8 5 4 f 1 0 e 4 9 1 c d 4 5 5 f f b f d 5 b d c 2 8 3 f a f' */ /* score: '21.00'*/
      $s10 = "ANwA5AGYAYwBmAGYANwA3AGEANgA2AGUAZQA5ADEAOAA2AGQAYwA5AGYANAAxADkAOQA3ADAANAA2AGYAZgA5ADIANAA0ADkAOQBjAGMANwA0ADIANQBiADIAMQBiAGM" ascii /* base64 encoded string '7 9 f c f f 7 7 a 6 6 e e 9 1 8 6 d c 9 f 4 1 9 9 7 0 4 6 f f 9 2 4 4 9 9 c c 7 4 2 5 b 2 1 b c' */ /* score: '21.00'*/
      $s11 = "AOQAyAGIAYQA5AGQAMgAzAGEAMwBjADMAMgA1AGUAZgAwADUAYQAwAGEAMQBlADYAZAA0ADIAOABjAGYAZABhAGEAOAA4AGYAMAA4ADkANwAwADkANgAyADkAZQAxAGY" ascii /* base64 encoded string '9 2 b a 9 d 2 3 a 3 c 3 2 5 e f 0 5 a 0 a 1 e 6 d 4 2 8 c f d a a 8 8 f 0 8 9 7 0 9 6 2 9 e 1 f' */ /* score: '21.00'*/
      $s12 = "AOABhADYAMQA5AGMAOQA5AGUAYQAzADAANwA1AGYAYQBhAGEAYwA5ADQAYwBmADAAMgBlADYAYgA4AGQAYgBkAGUAOAA2ADUAZAAyADMANwA3AGIAZQAyAGUANQBhADM" ascii /* base64 encoded string '8 a 6 1 9 c 9 9 e a 3 0 7 5 f a a a c 9 4 c f 0 2 e 6 b 8 d b d e 8 6 5 d 2 3 7 7 b e 2 e 5 a 3' */ /* score: '21.00'*/
      $s13 = "ANAAzADIAZABmADAANwA4ADAANAAyADIAMAA4AGQAYgBmAGQAOQBjAGIANwBlAGUAYQBlAGQAOQA0AGMANQA5ADgAMwBiADEAOAA2AGQAZAA5AGMAYwAzAGUAMgAzADc" ascii /* base64 encoded string '4 3 2 d f 0 7 8 0 4 2 2 0 8 d b f d 9 c b 7 e e a e d 9 4 c 5 9 8 3 b 1 8 6 d d 9 c c 3 e 2 3 7' */ /* score: '21.00'*/
      $s14 = "AOQA5ADQAMAAxAGUAMQAzAGIAYgBjADEAMABjADIAZQA4ADAAZAA5ADIAYgBmAGUAYgA4AGMAZABkAGIAYgA5AGUAMAA5AGIAOAAxADUAMwBhADYAMwAxAGMAMQAzADU" ascii /* base64 encoded string '9 9 4 0 1 e 1 3 b b c 1 0 c 2 e 8 0 d 9 2 b f e b 8 c d d b b 9 e 0 9 b 8 1 5 3 a 6 3 1 c 1 3 5' */ /* score: '21.00'*/
      $s15 = "ANwBmAGEANwBkADgANgA1ADAAOQA0ADYAOAAxADYAZQBlADkANgAyAGIAYwBlADEAYgAxADAANQBhADkANwBiADAAZgA0ADEAMABmADMAMgA5ADkAZgBjADgAOQBjADQ" ascii /* base64 encoded string '7 f a 7 d 8 6 5 0 9 4 6 8 1 6 e e 9 6 2 b c e 1 b 1 0 5 a 9 7 b 0 f 4 1 0 f 3 2 9 9 f c 8 9 c 4' */ /* score: '21.00'*/
      $s16 = "AOQA1ADQAZAAwADAAOAA5ADMAOQA1ADkAMABmADAAMQAzAGUAZABkADkAMgAxADgAMgAyAGQAYwAzADEAYgAwAGQANgA0ADkAMwA1AGUAYwAzAGMAMwAyAGYANgBjADU" ascii /* base64 encoded string '9 5 4 d 0 0 8 9 3 9 5 9 0 f 0 1 3 e d d 9 2 1 8 2 2 d c 3 1 b 0 d 6 4 9 3 5 e c 3 c 3 2 f 6 c 5' */ /* score: '21.00'*/
      $s17 = "AYwBiADAAMgA0ADMAMQBmADYANQBhAGIANQBiAGYAMwA2ADQAMQA0AGQAZgA3ADAAOQAzAGEAMAA3AGQAZAAxAGEAYwA0AGQAYwA5AGUAZAA4AGIANgAxADUAYwBkAGM" ascii /* base64 encoded string 'c b 0 2 4 3 1 f 6 5 a b 5 b f 3 6 4 1 4 d f 7 0 9 3 a 0 7 d d 1 a c 4 d c 9 e d 8 b 6 1 5 c d c' */ /* score: '21.00'*/
      $s18 = "ANwBhADAANwA0AGMAYQAxADAANQA1ADMAMQBjADkANQBmADQAMQA1ADUAZABhADQAZQBiAGIAZABhADgAMABjADUAMwA4ADMAYgBjAGUANAAzADYAMgA0ADQANwBkADk" ascii /* base64 encoded string '7 a 0 7 4 c a 1 0 5 5 3 1 c 9 5 f 4 1 5 5 d a 4 e b b d a 8 0 c 5 3 8 3 b c e 4 3 6 2 4 4 7 d 9' */ /* score: '21.00'*/
      $s19 = "AZAA0ADgAOQA3ADQANgBkADEAZQBmADgANwA5AGUAOABmADMANwAxAGYANAA1ADUAZQA5AGIAZQA4AGUAMwA0ADgAMwA0AGQAMAAwADYAYQA3ADUAYgBkAGYAZQAwAGY" ascii /* base64 encoded string 'd 4 8 9 7 4 6 d 1 e f 8 7 9 e 8 f 3 7 1 f 4 5 5 e 9 b e 8 e 3 4 8 3 4 d 0 0 6 a 7 5 b d f e 0 f' */ /* score: '21.00'*/
      $s20 = "AMwBjADAANgBjAGYAYQBkADIAOAA5AGEAZAAxADAAYwAxADMAOQAyADEANwAyAGYAOQBmADAANAAxADgANgBhADUANQBmADAANgAzADYAZAA3AGYAZAAyAGEAZQBjAGQ" ascii /* base64 encoded string '3 c 0 6 c f a d 2 8 9 a d 1 0 c 1 3 9 2 1 7 2 f 9 f 0 4 1 8 6 a 5 5 f 0 6 3 6 d 7 f d 2 a e c d' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

