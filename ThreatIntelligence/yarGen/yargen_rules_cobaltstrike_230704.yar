/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-04
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb {
   meta:
      description = "mw - file 064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb"
   strings:
      $s1 = "DltG:*a" fullword ascii /* score: '4.00'*/
      $s2 = "zVsPzBp" fullword ascii /* score: '4.00'*/
      $s3 = "aPJv,2m" fullword ascii /* score: '4.00'*/
      $s4 = "(qPtq(^r]h" fullword ascii /* score: '4.00'*/
      $s5 = "VsPOw/R" fullword ascii /* score: '4.00'*/
      $s6 = ")qPtq(^r\\" fullword ascii /* score: '4.00'*/
      $s7 = "UgXD8!3F" fullword ascii /* score: '4.00'*/
      $s8 = "BZsPBx\"$" fullword ascii /* score: '4.00'*/
      $s9 = "*o!~mLBsXeW)" fullword ascii /* score: '4.00'*/
      $s10 = "(qPCw/Pau" fullword ascii /* score: '4.00'*/
      $s11 = "tZSZz8w" fullword ascii /* score: '4.00'*/
      $s12 = "\\t3skq" fullword ascii /* score: '2.00'*/
      $s13 = "\\l_D\\hXB," fullword ascii /* score: '2.00'*/
      $s14 = "\\xXE,1X" fullword ascii /* score: '2.00'*/
      $s15 = "\\dPGBs" fullword ascii /* score: '2.00'*/
      $s16 = "\\Z_D\\^,B+q" fullword ascii /* score: '2.00'*/
      $s17 = "\\y,E(u" fullword ascii /* score: '2.00'*/
      $s18 = "\\y,E(q" fullword ascii /* score: '2.00'*/
      $s19 = "$Phy P" fullword ascii /* score: '1.00'*/
      $s20 = "${q(^D" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f {
   meta:
      description = "mw - file 0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */ /* score: '26.50'*/
      $s2 = "*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* score: '4.00'*/
      $s3 = " [^_]A\\" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      all of them
}

rule sig_7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c {
   meta:
      description = "mw - file 7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                   ' */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* base64 encoded string '                                                                                   )' */ /* score: '14.00'*/
      $s3 = " [^_]A\\" fullword ascii /* score: '1.00'*/
      $s4 = "sRY6v|%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      all of them
}

rule sig_8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408 {
   meta:
      description = "mw - file 8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408"
   strings:
      $s1 = "ap6Qj}?_wj$M|g-CMD" fullword ascii /* score: '6.00'*/
      $s2 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s3 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s4 = "RRtP^Td" fullword ascii /* score: '4.00'*/
      $s5 = "ZTtw^Td" fullword ascii /* score: '4.00'*/
      $s6 = "PtwRP\\" fullword ascii /* score: '4.00'*/
      $s7 = "RTwL^Tf" fullword ascii /* score: '4.00'*/
      $s8 = "WTqOW\\" fullword ascii /* score: '4.00'*/
      $s9 = "ZR|PZRt`^Rdh^R|@^Pu" fullword ascii /* score: '4.00'*/
      $s10 = "^TtwZT|G^Pu" fullword ascii /* score: '4.00'*/
      $s11 = "RTqNRQt" fullword ascii /* score: '4.00'*/
      $s12 = "ZRtP^RdX^R|@" fullword ascii /* score: '4.00'*/
      $s13 = "ORTwL^Te" fullword ascii /* score: '4.00'*/
      $s14 = "OZTtP^R" fullword ascii /* score: '4.00'*/
      $s15 = "NjMy;CYy=Z" fullword ascii /* score: '4.00'*/
      $s16 = "RRtw^Rd" fullword ascii /* score: '4.00'*/
      $s17 = "RRLPZTt" fullword ascii /* score: '4.00'*/
      $s18 = "RtwZT|_" fullword ascii /* score: '4.00'*/
      $s19 = "OZTt8_R" fullword ascii /* score: '4.00'*/
      $s20 = "p^T|gRPLg^Pt" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea {
   meta:
      description = "mw - file a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s5 = "dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 't                                                                                    ' */ /* score: '14.00'*/
      $s6 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s7 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s8 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s9 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii /* score: '13.00'*/
      $s10 = "DigiCert Timestamp 20210" fullword ascii /* score: '4.00'*/
      $s11 = "QJxy6z'" fullword ascii /* score: '4.00'*/
      $s12 = "DigiCert, Inc.1 0" fullword ascii /* score: '4.00'*/
      $s13 = "dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* score: '4.00'*/
      $s14 = "DigiCert, Inc.1A0?" fullword ascii /* score: '4.00'*/
      $s15 = "DigiCert Trusted Root G40" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA10" fullword ascii /* score: '2.00'*/
      $s17 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" fullword ascii /* score: '2.00'*/
      $s18 = " [^_]A\\" fullword ascii /* score: '1.00'*/
      $s19 = "310106000000Z0H1" fullword ascii /* score: '1.00'*/
      $s20 = "210101000000Z" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da {
   meta:
      description = "mw - file d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da"
   strings:
      $s1 = "Project1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "whoami.exe" fullword ascii /* score: '22.00'*/
      $s3 = "DvC.wlg" fullword ascii /* score: '7.00'*/
      $s4 = " restrict" fullword ascii /* score: '6.00'*/
      $s5 = " volatile" fullword ascii /* score: '6.00'*/
      $s6 = "_ZN8DllClassC2Ev" fullword ascii /* score: '5.00'*/
      $s7 = "_ZN8DllClassD0Ev" fullword ascii /* score: '5.00'*/
      $s8 = "aFsEKC2" fullword ascii /* score: '5.00'*/
      $s9 = "wBNhOm1" fullword ascii /* score: '5.00'*/
      $s10 = "rOJqU14" fullword ascii /* score: '5.00'*/
      $s11 = "_ZN8DllClassC1Ev" fullword ascii /* score: '5.00'*/
      $s12 = "Roxf- " fullword ascii /* score: '5.00'*/
      $s13 = "_ZN8DllClassD1Ev" fullword ascii /* score: '5.00'*/
      $s14 = "_ZN8DllClassD2Ev" fullword ascii /* score: '5.00'*/
      $s15 = "_ZTV8DllClass" fullword ascii /* score: '5.00'*/
      $s16 = "8DllClass" fullword ascii /* score: '5.00'*/
      $s17 = "{(H+{ 1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "XyMZ|BJ" fullword ascii /* score: '4.00'*/
      $s19 = "L$(H9L$@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "H9T$8w" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da {
   meta:
      description = "mw - file e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da"
   strings:
      $s1 = "i:Q9s9" fullword ascii /* reversed goodware string '9s9Q:i' */ /* score: '11.00'*/
      $s2 = "iYQ~iTQbiSQbiNQtiTQei" fullword ascii /* score: '7.00'*/
      $s3 = "i:QPiOQviOQbiNQ" fullword ascii /* score: '7.00'*/
      $s4 = "QbiNQuiSQ~i" fullword ascii /* score: '7.00'*/
      $s5 = "B_ -Uzj-" fullword ascii /* score: '5.00'*/
      $s6 = "i:QtiIQ<i{QCi:Q" fullword ascii /* score: '4.00'*/
      $s7 = "i:QriCQ<i}QSi:Q" fullword ascii /* score: '4.00'*/
      $s8 = "QxiTQxiNQxi[Q}iSQki[QeiSQ~iTQ" fullword ascii /* score: '4.00'*/
      $s9 = "i:QpiHQ<iUQ|i:Q" fullword ascii /* score: '4.00'*/
      $s10 = "i:Q|iNQ<iwQEi:Q" fullword ascii /* score: '4.00'*/
      $s11 = "i:QeiHQ<inQCi:Q" fullword ascii /* score: '4.00'*/
      $s12 = "i:QtiTQ<iSQti:Q" fullword ascii /* score: '4.00'*/
      $s13 = "Q_iUQui_QMiwQxiYQciUQbiUQwiNQMilQxiIQdi[Q}iiQeiOQuiSQ~ifQ i" fullword ascii /* score: '4.00'*/
      $s14 = "QwiUQci" fullword ascii /* score: '4.00'*/
      $s15 = "i:QPi~QGi{QAisQ\"i" fullword ascii /* score: '4.00'*/
      $s16 = "iVQ<iXQti:Q" fullword ascii /* score: '4.00'*/
      $s17 = "i:QtiTQ<ixQKi:Q" fullword ascii /* score: '4.00'*/
      $s18 = "i:QtiTQ<iJQyi:Q" fullword ascii /* score: '4.00'*/
      $s19 = "i:QpiHQ<ivQSi:Q" fullword ascii /* score: '4.00'*/
      $s20 = "i:QtiIQ<iYQ}i:Q" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad {
   meta:
      description = "mw - file f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad"
   strings:
      $s1 = "ETxTEV}" fullword ascii /* score: '4.00'*/
      $s2 = "EPpLAPy" fullword ascii /* score: '4.00'*/
      $s3 = "(Vx\\IVxtAPpx" fullword ascii /* score: '4.00'*/
      $s4 = ".EPx|DV" fullword ascii /* score: '4.00'*/
      $s5 = "yYHJ}Y@Jp" fullword ascii /* score: '4.00'*/
      $s6 = "yYHr}YXJ}Y@r" fullword ascii /* score: '4.00'*/
      $s7 = "APpLEP`" fullword ascii /* score: '4.00'*/
      $s8 = "yYHe}YXU}YA" fullword ascii /* score: '4.00'*/
      $s9 = "EVxkETI" fullword ascii /* score: '4.00'*/
      $s10 = "APpCEP`" fullword ascii /* score: '4.00'*/
      $s11 = "]KqIfIqB" fullword ascii /* score: '4.00'*/
      $s12 = "HT~<DTvlEV0P" fullword ascii /* score: '4.00'*/
      $s13 = "APplEP`tEPxl" fullword ascii /* score: '4.00'*/
      $s14 = "yYHM}YY" fullword ascii /* score: '4.00'*/
      $s15 = "ETxcEV}" fullword ascii /* score: '4.00'*/
      $s16 = "EVxCEV4+" fullword ascii /* score: '4.00'*/
      $s17 = "EVpDAPy" fullword ascii /* score: '4.00'*/
      $s18 = "APptETp,ETp" fullword ascii /* score: '4.00'*/
      $s19 = "APxlETq" fullword ascii /* score: '4.00'*/
      $s20 = "ETpDEVw" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f {
   meta:
      description = "mw - file 1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
   strings:
      $s1 = "g0E -e" fullword ascii /* score: '5.00'*/
      $s2 = "g0- U[" fullword ascii /* score: '5.00'*/
      $s3 = " -P:7-}" fullword ascii /* score: '5.00'*/
      $s4 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s5 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s6 = "tFIcH<L" fullword ascii /* score: '4.00'*/
      $s7 = "tQHcJ<H" fullword ascii /* score: '4.00'*/
      $s8 = "tKIc@<H" fullword ascii /* score: '4.00'*/
      $s9 = "tLIcC<L" fullword ascii /* score: '4.00'*/
      $s10 = "\\5q'm8x)f/c;{\"j5pi" fullword ascii /* score: '2.00'*/
      $s11 = " [^_]A\\" fullword ascii /* score: '1.00'*/
      $s12 = ":#o5@>" fullword ascii /* score: '1.00'*/
      $s13 = ":7zN:A" fullword ascii /* score: '1.00'*/
      $s14 = "\"#BxB/" fullword ascii /* score: '1.00'*/
      $s15 = "a7B/y5B/Y" fullword ascii /* score: '1.00'*/
      $s16 = ")MWA\"@^O?WE]4ZLS" fullword ascii /* score: '1.00'*/
      $s17 = "p~kBP<M" fullword ascii /* score: '1.00'*/
      $s18 = ":7z5NWR}" fullword ascii /* score: '1.00'*/
      $s19 = "8MZtXH" fullword ascii /* score: '1.00'*/
      $s20 = "GCC: (GNU) 7.3-win32 20180506" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280 {
   meta:
      description = "mw - file d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
   strings:
      $s1 = "@[X] Failed to load mango-si.dll" fullword ascii /* score: '23.00'*/
      $s2 = "@muuid_exec_bin.nim.c" fullword ascii /* score: '18.00'*/
      $s3 = "616d21583424" ascii /* score: '17.00'*/ /* hex encoded string 'am!X4$' */
      $s4 = "377553212167" ascii /* score: '17.00'*/ /* hex encoded string '7uS!!g' */
      $s5 = "7d277d486039" ascii /* score: '17.00'*/ /* hex encoded string '}'}H`9' */
      $s6 = "70224f6a7570" ascii /* score: '17.00'*/ /* hex encoded string 'p"Ojup' */
      $s7 = "497a362c6625" ascii /* score: '17.00'*/ /* hex encoded string 'Iz6,f%' */
      $s8 = "48346846547c" ascii /* score: '17.00'*/ /* hex encoded string 'H4hFT|' */
      $s9 = "6d6749676277" ascii /* score: '17.00'*/ /* hex encoded string 'mgIgbw' */
      $s10 = "656b7e2d304e" ascii /* score: '17.00'*/ /* hex encoded string 'ek~-0N' */
      $s11 = "6e2d6a564368" ascii /* score: '17.00'*/ /* hex encoded string 'n-jVCh' */
      $s12 = "2f62294e2e3e" ascii /* score: '17.00'*/ /* hex encoded string '/b)N.>' */
      $s13 = "5d3c20516256" ascii /* score: '17.00'*/ /* hex encoded string ']< QbV' */
      $s14 = "417173794d3d" ascii /* score: '17.00'*/ /* hex encoded string 'AqsyM=' */
      $s15 = "512b385a2c44" ascii /* score: '17.00'*/ /* hex encoded string 'Q+8Z,D' */
      $s16 = "7250622d3727" ascii /* score: '17.00'*/ /* hex encoded string 'rPb-7'' */
      $s17 = "7a566e5d217d" ascii /* score: '17.00'*/ /* hex encoded string 'zVn]!}' */
      $s18 = "756830785342" ascii /* score: '17.00'*/ /* hex encoded string 'uh0xSB' */
      $s19 = "266e765c5c38" ascii /* score: '17.00'*/ /* hex encoded string '&nv\\8' */
      $s20 = "67376f717950" ascii /* score: '17.00'*/ /* hex encoded string 'g7oqyP' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule sig_1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f {
   meta:
      description = "mw - file 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
   strings:
      $s1 = "Configuration.dll" fullword ascii /* score: '26.00'*/
      $s2 = "Z:\\vidar-ng\\Vidar-ng\\x64\\Release\\Configuration.pdb" fullword ascii /* score: '22.00'*/
      $s3 = "C:\\Windows\\splwow64.exe" fullword ascii /* score: '21.00'*/
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s5 = "https://secure.comodo.com/CPS0L" fullword ascii /* score: '17.00'*/
      $s6 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s8 = "Dhttp://crl.comodoca.com/COMODORSAExtendedValidationCodeSigningCA.crl0" fullword ascii /* score: '13.00'*/
      $s9 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s10 = "Dhttp://crt.comodoca.com/COMODORSAExtendedValidationCodeSigningCA.crt0$" fullword ascii /* score: '13.00'*/
      $s11 = "Cplapplet" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s12 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s13 = ".COMODO RSA Extended Validation Code Signing CA" fullword ascii /* score: '9.00'*/
      $s14 = ".COMODO RSA Extended Validation Code Signing CA0" fullword ascii /* score: '9.00'*/
      $s15 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s16 = "hrmagazine.micro" fullword ascii /* score: '7.00'*/
      $s17 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s18 = "Ruyaknjoo" fullword ascii /* score: '6.00'*/
      $s19 = "MS Corporation Sofware Ltd1#0!" fullword ascii /* score: '6.00'*/
      $s20 = "MS Corporation Sofware Ltd0" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a {
   meta:
      description = "mw - file 234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
   strings:
      $s1 = "3;a3_/3" fullword ascii /* score: '5.00'*/ /* hex encoded string ':3' */
      $s2 = "'j9&- " fullword ascii /* score: '5.00'*/
      $s3 = "]n{1Qn{5QdS%R%%" fullword ascii /* score: '5.00'*/
      $s4 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s5 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s6 = "G\\.PGB~VO" fullword ascii /* score: '4.00'*/
      $s7 = "iVOj!j" fullword ascii /* score: '4.00'*/
      $s8 = "fRGE`ZGAd[1" fullword ascii /* score: '4.00'*/
      $s9 = "j.kwb-A" fullword ascii /* score: '4.00'*/
      $s10 = "srov5=%" fullword ascii /* score: '4.00'*/
      $s11 = ".HJd!A" fullword ascii /* score: '4.00'*/
      $s12 = "GCC: (GNU) 7.3-win32 20180506" fullword ascii /* score: '1.00'*/
      $s13 = "GCC: (GNU) 8.3-win32 20190406" fullword ascii /* score: '1.00'*/
      $s14 = "%s\\System32\\%s" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s15 = "-eZ*xmc" fullword ascii /* score: '1.00'*/
      $s16 = "jwb5U]i8\\St/GA" fullword ascii /* score: '1.00'*/
      $s17 = "JEx~GR" fullword ascii /* score: '1.00'*/
      $s18 = "Lm`~GR" fullword ascii /* score: '1.00'*/
      $s19 = ".VGjHV" fullword ascii /* score: '1.00'*/
      $s20 = "-In{5Q" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966 {
   meta:
      description = "mw - file 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
   strings:
      $x1 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125C:\\Windows\\System32\\ntdll.dllCentral America Standa" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '63.00'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x6 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x7 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x8 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii /* score: '47.00'*/
      $x11 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWb" ascii /* score: '41.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '40.00'*/
      $x14 = "C:\\Windows\\System32\\cmd.exe" fullword wide /* score: '38.00'*/
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x16 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x17 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii /* score: '34.00'*/
      $x18 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscans" ascii /* score: '34.00'*/
      $x19 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x20 = " P runtime: p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] a" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*)
}

rule a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb {
   meta:
      description = "mw - file a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb"
   strings:
      $s1 = "Kp{%H%" fullword ascii /* score: '5.00'*/
      $s2 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s3 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s4 = "HRoY>7R.Oi" fullword ascii /* score: '4.00'*/
      $s5 = ".HZo[>" fullword ascii /* score: '4.00'*/
      $s6 = "%s\\System32\\%s" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "I70dE$" fullword ascii /* score: '1.00'*/
      $s8 = "a\\iKV#" fullword ascii /* score: '1.00'*/
      $s9 = "G7x<!+" fullword ascii /* score: '1.00'*/
      $s10 = "!&{[f&" fullword ascii /* score: '1.00'*/
      $s11 = "k/> +/" fullword ascii /* score: '1.00'*/
      $s12 = "/=#TUk" fullword ascii /* score: '1.00'*/
      $s13 = "Eq{SA'" fullword ascii /* score: '1.00'*/
      $s14 = "bgS+Wn[" fullword ascii /* score: '1.00'*/
      $s15 = "KulA#O" fullword ascii /* score: '1.00'*/
      $s16 = "Rs/>+l" fullword ascii /* score: '1.00'*/
      $s17 = "bcS+Wn" fullword ascii /* score: '1.00'*/
      $s18 = ")y7Y(G" fullword ascii /* score: '1.00'*/
      $s19 = "m.5$CS" fullword ascii /* score: '1.00'*/
      $s20 = "Kp{gi&" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076 {
   meta:
      description = "mw - file e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = "TestPrintForm.dll" fullword ascii /* score: '23.00'*/
      $s2 = "TestPrintForm.EXE" fullword wide /* score: '22.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s5 = "testform2.prx" fullword ascii /* score: '10.00'*/
      $s6 = "testform1.prx" fullword ascii /* score: '10.00'*/
      $s7 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s8 = " /p \"%1\"" fullword ascii /* score: '9.00'*/
      $s9 = "Test dialog multiitem pages" fullword ascii /* score: '9.00'*/
      $s10 = "Test dialog singleitem page" fullword ascii /* score: '9.00'*/
      $s11 = "Dialog Print" fullword wide /* score: '9.00'*/
      $s12 = "Test dialog print" fullword wide /* score: '9.00'*/
      $s13 = "Check this to print the list content" fullword wide /* score: '9.00'*/
      $s14 = "testpage" fullword ascii /* score: '8.00'*/
      $s15 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s16 = "%d minuti, %d secondi" fullword ascii /* score: '7.00'*/
      $s17 = "TestPrintForm Versione 1.0" fullword wide /* score: '7.00'*/
      $s18 = "TestPrintForm.Document" fullword wide /* score: '7.00'*/
      $s19 = "?Passa al riquadro della finestra successivo" fullword wide /* score: '7.00'*/
      $s20 = "Subform" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03 {
   meta:
      description = "mw - file 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
   strings:
      $x1 = "C:\\Windows\\System32\\svchost.exe" fullword ascii /* score: '34.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s4 = "AB821FEA43DBF7055D783DAAD4F451FEC2B316121130EC40C497C2E397F8D51DE9909BC281FD3A96CDEA4E82FDE9DBF0C09B90302BD7D40C35190CCEE877C6C2" ascii /* score: '11.00'*/
      $s5 = "88313D6EF3AB8CD4D5676421482D33F0F1530B4800B04451810C504BAD65D7D334268FB1357A6886B14940442119F7A5D268F8814B89808CCFFD508F6F190F54" ascii /* score: '11.00'*/
      $s6 = "DB5717965DC0ECBCFD9853C960379CC507DC183F0C7DE5132B6F76DF97B1729DF4CFDA93B8D848FCB9AF2BF445A5E2EF7CE8EF69742B9BCE9D664D19A61505F2" ascii /* score: '11.00'*/
      $s7 = "3A40E5C95AEA3822B2940D20F295163E8FC4E6028972705B499E2D3866957F1C85CD8F14BCFC09B17BEF3AE216833296BD7571483216F6A9EF3F62F154FFA441" ascii /* score: '11.00'*/
      $s8 = "F10F8A5591FD40FF1BF03BD5FCBD439DDD5A943F52C57D1A44BC5BC50916AC724C1FFB1F409CBD49D5B086EC384439E5F433CF9D4BEE423C43C84D4A0B95760D" ascii /* score: '11.00'*/
      $s9 = "1C54849BE30646FA4FAF335CBE5C9AD32D3FC382807AF7E370524DA48F52464148CBF2B2E0DED783EBCCFA2589FE06A7A398C510FE401404E7911791FAAA6CC0" ascii /* score: '11.00'*/
      $s10 = "93B0BC554D32CB9E78819097E407C6B6D3F6A1A3C12806602435C60ED5C54136FC37FE1393D259EE6BEDDA4A332FD274A39B91E269581472853C30598FDF3C8D" ascii /* score: '11.00'*/
      $s11 = "8EA2BBF972214B23EFB52DB1A1877CDD26E4F6A8D6EF1EC6D154E52C8B269E40F56CFB74970914F9DAFC5BB6AEBBFE9BD0088ECBF01C062B2E10C448796C4252" ascii /* score: '11.00'*/
      $s12 = "23D4AC64E6AFE0E83EBFB6BD06EE865F7EF1FA6123D41ECFD28686B51A5EE61458587B317CE2B948BF2BCEDE990309AE00D00A59B1C5C7F3C9D84099E36E2071" ascii /* score: '11.00'*/
      $s13 = "50DB4DE92929A1B40ADFC5D322339308E10FB49376BEB581F6683E8571A0700A3CEAD3364E1B12CDCB55003B249B8D4978F95D28DEF39CE473012A2E9FE9A462" ascii /* score: '11.00'*/
      $s14 = "799A6200F5B25ABDA22807AB585B2EAC07039B1AE99C5DAA040DD4B9D46F2E0BAD53319BE06CD588824821BA3698CEB17562CE34C428D38F66891324820598CF" ascii /* score: '11.00'*/
      $s15 = "554EF23D3F3C6FD5140F425E75154C02BCFF8BE7C360FDBB8F53DDE7F54A70A05F9B7E31FFA1DA51E970459B6B7ADE059AC278F57D0EAF7532E9665F6515A012" ascii /* score: '11.00'*/
      $s16 = "FE20746AAAB6EBFE7D0BA7F57D4ABD8F0E1B783E5FEC4204CDB1540F842E4FFAFAF33075FFD305D01E0ED0C71FE214C745217763933FF2CEA442410D0C91DCB3" ascii /* score: '11.00'*/
      $s17 = "5C9F0006F879EE1B6619CF44EB44DB2EA0E9389C6977CB4B7E1778F831F345776C2EFEFF7CF1AA477C8950E1F373CD2060B97D454C2E55134238B6AF0C51E863" ascii /* score: '11.00'*/
      $s18 = "47D84E775B7D6F7E289F9205F1D3D3256FBD6320AE9F77527909BC8D1CC420EF3F36948858FAE96AEBB4292E18728D0CE83441FB7ECF2782F880110B3EE6096B" ascii /* score: '11.00'*/
      $s19 = "1FAE9190304EE7B10FFE568A5DBDA55996F852AF590CC52FA0BC871DDF924BCC827FFC99B228C0606136C70E0D5263677D647972F2C0FFA2E1BEA664D4E696E2" ascii /* score: '11.00'*/
      $s20 = "F5C81EC48C537458A508D351BF8CF03439ED8BB351EDFF1E1BA935685B3C9A3B7D5F7C36E0BDA0404D2428ED6DB6139C4C61791BAD4C72927749E2FDFC3A60F8" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d {
   meta:
      description = "mw - file d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "DeleteGroupadd_OnExecuteCommandgetCommandIdentity" fullword ascii /* score: '26.00'*/
      $s3 = "kitty-temp.exe" fullword wide /* score: '26.00'*/
      $s4 = "get_InstanceExecuteGetWindowTextLength" fullword ascii /* score: '23.00'*/
      $s5 = "SendExecuteDependencyCodeGetTypesFromInterface" fullword ascii /* score: '23.00'*/
      $s6 = "shellcode" fullword ascii /* score: '22.00'*/
      $s7 = "get_AliasesLogWarningProcessLog" fullword ascii /* score: '20.00'*/
      $s8 = "processLogget_AvatarIconGetPlugin" fullword ascii /* score: '20.00'*/
      $s9 = "ProcessLogLogGetGroup" fullword ascii /* score: '20.00'*/
      $s10 = "Reloadget_PermissionsProcessLog" fullword ascii /* score: '20.00'*/
      $s11 = "ParseUInt64ParseDoubleExecute" fullword ascii /* score: '18.00'*/
      $s12 = "<FixedUpdate>b__4_0SaveGroupExecute" fullword ascii /* score: '18.00'*/
      $s13 = "DEBUG_ONLY_THIS_PROCESS" fullword ascii /* score: '15.00'*/
      $s14 = "PROCESS_MODE_BACKGROUND_END" fullword ascii /* score: '15.00'*/
      $s15 = "CREATE_PROTECTED_PROCESS" fullword ascii /* score: '15.00'*/
      $s16 = "PROCESS_MODE_BACKGROUND_BEGIN" fullword ascii /* score: '15.00'*/
      $s17 = "DETACHED_PROCESS" fullword ascii /* score: '15.00'*/
      $s18 = "DEBUG_PROCESS" fullword ascii /* score: '15.00'*/
      $s19 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s20 = "processAccess" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843 {
   meta:
      description = "mw - file fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
   strings:
      $s1 = "Mightywill.QA.CrashReport.exe" fullword wide /* score: '22.00'*/
      $s2 = ",https://www.example.com/my_product/info.html0" fullword ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugCRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '15.00'*/
      $s5 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugMFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '15.00'*/
      $s6 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s7 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugMFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '12.00'*/
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugCRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '12.00'*/
      $s9 = "ygetji6" fullword ascii /* score: '10.00'*/
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s11 = "oBs.ijs~" fullword ascii /* score: '7.00'*/
      $s12 = "NEJCHFGNUATBMYBQWL" fullword ascii /* score: '6.50'*/
      $s13 = "Mightywill" fullword wide /* score: '6.00'*/
      $s14 = "NEJCHFGNUATBMYBQWL0" fullword ascii /* score: '5.00'*/
      $s15 = "mKN@ -):oc^" fullword ascii /* score: '5.00'*/
      $s16 = "DigiCert Timestamp 20210" fullword ascii /* score: '4.00'*/
      $s17 = "QJxy6z'" fullword ascii /* score: '4.00'*/
      $s18 = "DigiCert, Inc.1 0" fullword ascii /* score: '4.00'*/
      $s19 = "QHma6c " fullword ascii /* score: '4.00'*/
      $s20 = "DkkUah`n[lTd:8be" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43 {
   meta:
      description = "mw - file 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "f58.dll" fullword ascii /* score: '20.00'*/
      $s3 = "d5bd5d75cf6a3fba2bb72f9098fe1137d27242c58b82bbccda0f67bd7f7a91f5773fe585191387aef8685c3b6659dab6d3c3e7052cf13091f9def18d979c9c47" ascii /* score: '11.00'*/
      $s4 = "91e118de84bf0e3d5d0abdeb7a1b56b02e3a1b024525244701587f315e87e909357602690e412554996481ef43933bbd089df8d141df09e0da920fad32b0e7bb" ascii /* score: '11.00'*/
      $s5 = "f72a757f0aa5efb5c6ee35b4754fe2b8f4aeeacef6b7747e534bee988bd44f8f131e0fbe7bc7f9e7f869f93b603affe1319a6ae226f35fbd84067aa3cbd41f44" ascii /* score: '11.00'*/
      $s6 = "f49d156134d16a2848f33e26eb8e96f0d40dd4628b2c4b0f59a841df1ba6534d235bc8fdaf236453e20855ae0bbcede23ba55d6b8ce32c3ead55b8b3beb807cf" ascii /* score: '11.00'*/
      $s7 = "5ed179312db734d7fb932d7cb75347a073a78f872de81e9ef7ffafea7cf35717b77efdd2db4f51a9a06bc03de7fff7d017ed9965f79077ee981fc3b3bbc76c5a" ascii /* score: '11.00'*/
      $s8 = "8d37108d37510d37300d39388e9b983e9b98de9b985e9b989cbbf81cbbf8ecbbf86cb7f80cbefaa0f52ac0f6fb03e54627d50c27d4e3fdcc6f5b06de8b4e1e65" ascii /* score: '11.00'*/
      $s9 = "9f5d878f8007f78be1b5d2deb09e850a68707b1027e0043ab9dcbf19fc5ea900793af8b77254f05129545a72f8e20ae8a23c42dc1766652cb6f803b95015b7b3" ascii /* score: '11.00'*/
      $s10 = "2be1f61be1f62be5f63be6bb1dcdb70f9adb8fce1b8fc305cbe00e33f81e988c17444633a22311d41385d20a6632fa66337a6e328a6e310e6ff3ee63fae4b3b1" ascii /* score: '11.00'*/
      $s11 = "7352e2702f383da279a2b4bc1fcfcc4f000e6a711b78753989f344c5f38e6a727e6e7196e2f41982fda078178c5983fe4078e84f71771f9686e0ecde15dc5f81" ascii /* score: '11.00'*/
      $s12 = "7d3b51f962bc0e7d6be19909cf9278ddc2faafa5efb4fa9b0363fbff9ae3dfba5fb499d2c9fab930dbfcd81ae8efc5c2090bea13a027566fe8af0b2cd693f513" ascii /* score: '11.00'*/
      $s13 = "2a61e2341b18accc80a13ab7022079d72bee47748316b97d1566384676bb1143ce3027bf2287f02bd3bf659d3a780ac0e7cf91418c7d983d1bae558dd926ee56" ascii /* score: '11.00'*/
      $s14 = "c53a0f7aef7278b27e68fd5cfd3c7da5f92be3b72d5b0e849c9b393961ef6cd99bfc57ddf2bf52fcc53f91ad913bdce76ba6b543e30795ee2c2b0c5098bf6ccd" ascii /* score: '11.00'*/
      $s15 = "v1137c7191b60fe17d39de19cf303750b1771ae03779041796ba5944f08141a71a737ccfa06778962784af2751265380c6f334fab1d6a079e03939b03d2b819a" ascii /* score: '11.00'*/
      $s16 = "8c102e15767dc03d282e9b1dcbfc662b7585c29bf2ad828b437a6afeef58b69cc6066b199b0e44324323799c834176589f8e744646fe417f7343094b197cf122" ascii /* score: '11.00'*/
      $s17 = "48327ed8d5414e434d251f36c3cd7c61e1ecf5662ebed18e0c1527e4f920051800bf60baea412bf7fa834cce92397783bbf3e12fe2a67afd6de36f1bc2c9ae2e" ascii /* score: '11.00'*/
      $s18 = "20e62317aaf55ec15f9d9e318d77905dacb8b3c461399ac09aba2bc094fabeb10d07ae4f1584af6430fbbea3aa3d9cf917d4b21ef2fab1e22f0acc2f316cc07b" ascii /* score: '11.00'*/
      $s19 = "a8c28cee83d6b2406796eeb47fdaa02891a149844a56046d29ed88a4d666f4469e93c89ada2195f854118c926a47e69a8f7580394c24505d8a23b2a2f3efd9cf" ascii /* score: '11.00'*/
      $s20 = "d5e16fcc69b5df5aaa47ce4e243e36fbe9d7db79d145f88f4eeb5bb227662d3c91d02450118fe3ce9eaba96cbb8d3cb258673ccf71c8f53bdefbc2a72f583242" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9 {
   meta:
      description = "mw - file 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "f129.dll" fullword ascii /* score: '20.00'*/
      $s3 = "231ef223b2f0aa44801066cfa6f858f64e9803c2d6ac1773491d23655357ae8932f9c6ebd2efb8e8cc4192349538e2a89a12183555c935aafeb3a8ed3d4b74bb" ascii /* score: '11.00'*/
      $s4 = "79c42d20eb2db5a2f575893bfac336c054a1227253c776f05eb5d67dc86a0068e11474123cfeb405b2b2e0044679115a8d140efc348d26be517808a406d44c56" ascii /* score: '11.00'*/
      $s5 = "90c6b47aa785e5ffdd6e4db0aadf392a1bc1377c1ef3c955736542a110305d1acc467acc5ea7b622d07672de5ebf50d2dea44b3b1f8e76841ee2ab5d543291f3" ascii /* score: '11.00'*/
      $s6 = "6792eacb5e3a422546ecb2deab02ded82646da8a6c3a377043c62c210fd73c942a7fff776aeb12f9e4b1df8f7c2ddb5daa15aacb46d249928303ccb091b003c0" ascii /* score: '11.00'*/
      $s7 = "577de6b2de4b5c1f2dde71c433f964499f2472901cffbd5b98866dc18a05876e9e59936793b8effda9d7270c2dd237658d3afdc5c323664561918f354bfbf0db" ascii /* score: '11.00'*/
      $s8 = "9eb7479538569fa0eb6cc03d832b2318d467baba3a4b0e52dc3544a4f320b66b70ef4c8823976adc724295b931687afd80a9684af1427a9c257e20a5684af704" ascii /* score: '11.00'*/
      $s9 = "0c6ed87b173044f880fc914875235bd1bc3a909230120386fd70589233a43d415aacb8a0b735b621ead055ed08eda192b6604daff6baf6f6ef25ef213541921c" ascii /* score: '11.00'*/
      $s10 = "076bdcb0ab0323f95697717b90bdc8532a6f75cb032853c759d33f26739bc1b0c613612dab00de88e40a0845bc7ee37212f1fde3b5f602d3a12e2f804f8b2021" ascii /* score: '11.00'*/
      $s11 = "4d3d5c300e603bac3d109953a398434821d35d2cfc3d6d052fa86096923c2e9be8e2adde8cd6e48ffa8da6786097745e6b0a8fc54ed686442f08ef4323fa0807" ascii /* score: '11.00'*/
      $s12 = "4598cda332dd431a852f51ed6befaf07fd84acbd6ce765d95cfb02331aaf1d2e2f0e58b568757b2e57dd74fd2147b54cdb3c3776b7714d8b475bee4fa38c0a56" ascii /* score: '11.00'*/
      $s13 = "6b27ea906d784f42575568eb62ea4d2de6eb98d86ab2b4f63edda4d1aeb37383a3b2c7771d4707659eeb0d1d97eadb6806bff439dbd86bd6d5339494e4b9772e" ascii /* score: '11.00'*/
      $s14 = "a55e98135d35afee11f880da49fa67a13d0b610c83254d86fba7f51302762357e8be22828cf91a3de4fd7bcde3af35489ac3d5d65d94393899f7eb8f51fece25" ascii /* score: '11.00'*/
      $s15 = "7f836f66a5cb93b761e6c0506ab80147305fa7e1c5da6d7f184176c9f17dcf80436f58dd98464b62fe3640199381bfacc87b64399b0e03805da58a6ac7e621c5" ascii /* score: '11.00'*/
      $s16 = "9284db1289978f43461929274da2e02ff7dc8f98d680de81bcfd56c40cb7cc3c00ec22c8a7c3997685020a77c85c7a0f776e08ec97bb25eeb4e437900b89f7ab" ascii /* score: '11.00'*/
      $s17 = "2f43585fc5c44474d263f03e5ab49e2e756e334b5f9fc623476a84de2e7219a6b13f88588a6ba7c7e11d2dfba627ebe9486d47c2c8445f534cc2ec510f9a8689" ascii /* score: '11.00'*/
      $s18 = "e94d8dd7e50f9eefe5cc0a587d73ff1b40bf1cf102c6fc1d69653cc79e835533d4af9289aa2734422db4f8eba7c30cef464bf064a85f93206e4265152a1d4325" ascii /* score: '11.00'*/
      $s19 = "3e9af8845eb3defaf8ec748dbe3b3e32c6b651641b73481d702b4b467542eb8ff3300e7e7cefc448658b61544b518236c83e044b25a467463aeedc09c5f6c549" ascii /* score: '11.00'*/
      $s20 = "3d928e56c94264a17258ac4224452783cb75386b742be9384f418c98e67b736f710fba660a68add93ee991892d11461a48d2debd224c957d9eeb1455c09d1cd3" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618 {
   meta:
      description = "mw - file 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
   strings:
      $s1 = "IMINIMAL_PATH=1 @@COMSPEC@@ /K \"doskey git=^\"@@EXEPATH@@\\cmd\\git.exe^\" $*\"" fullword wide /* score: '23.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "git.exe" fullword wide /* score: '19.00'*/
      $s4 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "https://sectigo.com/CPS0D" fullword ascii /* score: '17.00'*/
      $s6 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s7 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii /* score: '16.00'*/
      $s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii /* score: '16.00'*/
      $s9 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s10 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii /* score: '13.00'*/
      $s12 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#" fullword ascii /* score: '13.00'*/
      $s13 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t" fullword ascii /* score: '13.00'*/
      $s14 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii /* score: '13.00'*/
      $s15 = "euHVp:\\>N" fullword ascii /* score: '10.00'*/
      $s16 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s17 = "* p4DX" fullword ascii /* score: '9.00'*/
      $s18 = "!\\[7&b![" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s19 = "The Git Development Community" fullword wide /* score: '9.00'*/
      $s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c {
   meta:
      description = "mw - file ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "HAAAAAAAA" fullword ascii /* base64 encoded string '      ' */ /* reversed goodware string 'AAAAAAAAH' */ /* score: '26.50'*/
      $s2 = "C:\\Users\\dev\\Desktop\\" fullword ascii /* score: '24.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "Dll6.dll" fullword ascii /* score: '20.00'*/
      $s5 = "\\Dll6\\x64\\Release\\Dll6.pdb" fullword ascii /* score: '19.00'*/
      $s6 = "Attempted to free %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s7 = "Attempted to realloc unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s8 = "Attempted to free unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s9 = "Attempted to realloc %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s10 = "invalid decoded scanline length" fullword ascii /* score: '16.00'*/
      $s11 = "stb.log" fullword ascii /* score: '16.00'*/
      $s12 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s13 = "Changed: %s - %08x:%08x" fullword ascii /* score: '15.00'*/
      $s14 = "s%s% :s%" fullword ascii /* reversed goodware string '%s: %s%s' */ /* score: '15.00'*/
      $s15 = "bad zlib header" fullword ascii /* score: '11.00'*/
      $s16 = "no header height" fullword ascii /* score: '11.00'*/
      $s17 = "%s/%s.cfg" fullword ascii /* score: '11.00'*/
      $s18 = "Eyedropped tile that isn't in tileset" fullword ascii /* score: '11.00'*/
      $s19 = "tnld.lld" fullword ascii /* score: '10.00'*/
      $s20 = "bad Image Descriptor" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243 {
   meta:
      description = "mw - file 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "raxaxai" fullword ascii /* score: '8.00'*/
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s5 = "ex22a Version 1.0" fullword wide /* score: '7.00'*/
      $s6 = "MAZOWIECKIE1" fullword ascii /* score: '5.00'*/
      $s7 = "Warszawa1" fullword ascii /* score: '5.00'*/
      $s8 = "ihkLbb4" fullword ascii /* score: '5.00'*/
      $s9 = "X#TlDT!<" fullword ascii /* score: '4.00'*/
      $s10 = "!TFrJ,^s;%'" fullword ascii /* score: '4.00'*/
      $s11 = "VBWe>6z<" fullword ascii /* score: '4.00'*/
      $s12 = "lFXw-S>" fullword ascii /* score: '4.00'*/
      $s13 = "vXsWj;Yi" fullword ascii /* score: '4.00'*/
      $s14 = "xneGCCI " fullword ascii /* score: '4.00'*/
      $s15 = "PAG!1*tOUT4IPhhC19H^KgO*oH&3ak9>$3ajfsn7?)2VfZ<^b#4MZvFB_7#<8jKD(d%1sijql&M2a<nbiqEO_" fullword ascii /* score: '4.00'*/
      $s16 = "rDulyU*" fullword ascii /* score: '4.00'*/
      $s17 = "NyscFy y" fullword ascii /* score: '4.00'*/
      $s18 = ".SroN>q?K" fullword ascii /* score: '4.00'*/
      $s19 = ".`cOm`" fullword ascii /* score: '4.00'*/
      $s20 = "mAIwDC2Cf" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583 {
   meta:
      description = "mw - file a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
   strings:
      $s1 = "MsgBoxTest.exe" fullword wide /* score: '22.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s3 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s4 = "CMessageBoxDialog" fullword ascii /* score: '9.00'*/
      $s5 = ".?AVCMessageBoxDialog@@" fullword ascii /* score: '9.00'*/
      $s6 = "Content of the message box" fullword wide /* score: '9.00'*/
      $s7 = "Your message box was displayed successfully or, if the result was stored in the registry, returned the former result, because th" wide /* score: '8.00'*/
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s9 = "&f:\"QO" fullword ascii /* score: '7.00'*/
      $s10 = "COmD+hc" fullword ascii /* score: '7.00'*/
      $s11 = "The message boxes have been reset. Those one with checkboxes will be displayed again, even if the user selected the \"Don't disp" wide /* score: '7.00'*/
      $s12 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s13 = "TROLOLO" fullword wide /* score: '6.50'*/
      $s14 = "IDTRYAGAIN" fullword wide /* score: '6.50'*/
      $s15 = "IDCONTINUE" fullword wide /* score: '6.50'*/
      $s16 = "IDYESTOALL" fullword wide /* score: '6.50'*/
      $s17 = "IDNOTOALL" fullword wide /* score: '6.50'*/
      $s18 = "IDSKIPALL" fullword wide /* score: '6.50'*/
      $s19 = "IDIGNOREALL" fullword wide /* score: '6.50'*/
      $s20 = "Z5* 5B" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174 {
   meta:
      description = "mw - file b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
   strings:
      $s1 = "AVGDll.dll" fullword ascii /* score: '23.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "read failed:%d" fullword ascii /* score: '10.00'*/
      $s4 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s5 = "read file success" fullword ascii /* score: '9.00'*/
      $s6 = "Qc.cfg" fullword wide /* score: '8.00'*/
      $s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s8 = "open file success" fullword ascii /* score: '6.00'*/
      $s9 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s10 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s11 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "0O1S1W1[1_1c1g1k1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s14 = ";0?0C0G0K0O0S0W0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "create file fialed:%d" fullword ascii /* score: '4.00'*/
      $s16 = "URPQQhp#" fullword ascii /* score: '4.00'*/
      $s17 = "9,9Z9c9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "l0Nt4GG2EGLcklsHmh" fullword ascii /* score: '4.00'*/
      $s19 = "5'5O5c5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "3 3'343" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802 {
   meta:
      description = "mw - file d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
   strings:
      $s1 = "abcdefghijklmnop" fullword ascii /* score: '8.00'*/
      $s2 = "abcdbcdecdefdef" ascii /* score: '8.00'*/
      $s3 = "ksysnative" fullword ascii /* score: '8.00'*/
      $s4 = "cOMG@ZA]F" fullword ascii /* score: '7.00'*/
      $s5 = "BBBBBBBBH" fullword ascii /* score: '6.50'*/
      $s6 = "%s as %s\\%s: %d" fullword ascii /* score: '6.50'*/
      $s7 = "s+- <<F" fullword ascii /* score: '5.00'*/
      $s8 = "+ 1<<F" fullword ascii /* score: '5.00'*/
      $s9 = "+ w<<H" fullword ascii /* score: '5.00'*/
      $s10 = "rijndael" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 6 times */
      $s11 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 21 times */
      $s12 = "Microsoft Base Cryptographic Provider v1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 148 times */
      $s13 = "sha256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s14 = "process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 171 times */
      $s15 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s16 = "o^^BKyKLeGZ" fullword ascii /* score: '4.00'*/
      $s17 = "{hiiiiiii" fullword ascii /* score: '4.00'*/
      $s18 = "O^^BGMOZGA@" fullword ascii /* score: '4.00'*/
      $s19 = "{hiiiiii" fullword ascii /* score: '4.00'*/
      $s20 = "%02d/%02d/%02d %02d:%02d:%02d" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281 {
   meta:
      description = "mw - file 2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "NPJava12.dll" fullword wide /* score: '23.00'*/
      $s3 = "self.exe" fullword ascii /* score: '22.00'*/
      $s4 = " testapp.exe" fullword ascii /* score: '19.00'*/
      $s5 = "FTTTGR.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "LdrGetProcedureAIsThreadAFiber" fullword ascii /* score: '12.00'*/
      $s7 = " attualmente selezionato come versione di Java predefinita per il browser." fullword wide /* score: '10.00'*/
      $s8 = " la versione di Java predefinita per il browser. Per impostare Sun Java come versione predefinita, selezione Strumenti->Opzioni " wide /* score: '10.00'*/
      $s9 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s10 = "content2,the7" fullword wide /* score: '9.00'*/
      $s11 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s12 = "cessitent une version de java diff" fullword wide /* score: '9.00'*/
      $s13 = "d$7*D$s:\\$7" fullword ascii /* score: '7.00'*/
      $s14 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s15 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s16 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s17 = "rtig vom Browser verwendete Java-Version. Um das/die Applet(s) auf dieser HTML-Seite ausf" fullword wide /* score: '7.00'*/
      $s18 = "n de Java elegida como predeterminada para el navegador." fullword wide /* score: '7.00'*/
      $s19 = "n predeterminada del navegador. Para seleccionar Sun Java como opci" fullword wide /* score: '7.00'*/
      $s20 = "cuter la ou les applet(s) de la page HTML, vous devez utiliser une nouvelle session. Cliquez sur 'Oui' pour lancer une nouvelle " wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c {
   meta:
      description = "mw - file 1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "3fGE+ r" fullword ascii /* score: '5.00'*/
      $s6 = "aeMJa-^" fullword ascii /* score: '4.00'*/
      $s7 = "PSUDfni" fullword ascii /* score: '4.00'*/
      $s8 = "|shuWx5Ik8" fullword ascii /* score: '4.00'*/
      $s9 = "-dhEeK(b^" fullword ascii /* score: '4.00'*/
      $s10 = "9pPqy{lY" fullword ascii /* score: '4.00'*/
      $s11 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s12 = ")c[X.Hzj" fullword ascii /* score: '4.00'*/
      $s13 = "6RlbZ?" fullword ascii /* score: '4.00'*/
      $s14 = "7_wovHJSJ" fullword ascii /* score: '4.00'*/
      $s15 = "dNhktmjF" fullword ascii /* score: '4.00'*/
      $s16 = "d.RtXfc\\" fullword ascii /* score: '4.00'*/
      $s17 = "cCof#HSN" fullword ascii /* score: '4.00'*/
      $s18 = "sKnbKwR*" fullword ascii /* score: '4.00'*/
      $s19 = "9zWTFVkhm" fullword ascii /* score: '4.00'*/
      $s20 = "SiHl<B`o" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530 {
   meta:
      description = "mw - file 91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "~%oit%/" fullword ascii /* score: '5.00'*/
      $s6 = " -?7fo" fullword ascii /* score: '5.00'*/
      $s7 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s8 = "CwNzCgO" fullword ascii /* score: '4.00'*/
      $s9 = "+uEoF\"a" fullword ascii /* score: '4.00'*/
      $s10 = "['dBpoY~L/^" fullword ascii /* score: '4.00'*/
      $s11 = "UreaUreaUreaUreaUreaUreaUrea" fullword ascii /* score: '4.00'*/
      $s12 = "%3>boma\\SQ)g" fullword ascii /* score: '4.00'*/
      $s13 = "m}bzFfBFz&E" fullword ascii /* score: '4.00'*/
      $s14 = "UbeVi^%Q" fullword ascii /* score: '4.00'*/
      $s15 = "EaaTIck" fullword ascii /* score: '4.00'*/
      $s16 = "YSXAr) }Na;" fullword ascii /* score: '4.00'*/
      $s17 = "QsAnmOk)PsW" fullword ascii /* score: '4.00'*/
      $s18 = "K5hA|<PZDWh+|" fullword ascii /* score: '4.00'*/
      $s19 = "wAjmK}V" fullword ascii /* score: '4.00'*/
      $s20 = "OFzGDFzGDFzGYFz" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63 {
   meta:
      description = "mw - file be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "HfFhHfF8" fullword ascii /* score: '5.00'*/
      $s6 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s7 = ":bXQI57&" fullword ascii /* score: '4.00'*/
      $s8 = "ykNHBig" fullword ascii /* score: '4.00'*/
      $s9 = "Io[RnDY{Rx" fullword ascii /* score: '4.00'*/
      $s10 = "obHvS^t" fullword ascii /* score: '4.00'*/
      $s11 = "PJLrKHG" fullword ascii /* score: '4.00'*/
      $s12 = "1#&qPBL.ew" fullword ascii /* score: '4.00'*/
      $s13 = ";&gmTz^Cd&" fullword ascii /* score: '4.00'*/
      $s14 = "ebmLZ_Qpft" fullword ascii /* score: '4.00'*/
      $s15 = "hKeM PgE" fullword ascii /* score: '4.00'*/
      $s16 = "6iXJN-dvk" fullword ascii /* score: '4.00'*/
      $s17 = "1*:NTMu>1#>[HfF" fullword ascii /* score: '4.00'*/
      $s18 = "zjPx4,7F" fullword ascii /* score: '4.00'*/
      $s19 = "~YHkU'UWi" fullword ascii /* score: '4.00'*/
      $s20 = "fJAXDv}" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule a0fc8cae1605a9f21b56bf3613627787459bfacaa7134509c2e8aba3c18753c7 {
   meta:
      description = "mw - file a0fc8cae1605a9f21b56bf3613627787459bfacaa7134509c2e8aba3c18753c7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "a0fc8cae1605a9f21b56bf3613627787459bfacaa7134509c2e8aba3c18753c7"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                           ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                           ' */ /* score: '16.50'*/
      $s4 = "5,ze7\"" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule cb6314a15f21d2de2155f9d1563970b7de43373d5fd362de66a56430f56f9f45 {
   meta:
      description = "mw - file cb6314a15f21d2de2155f9d1563970b7de43373d5fd362de66a56430f56f9f45"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "cb6314a15f21d2de2155f9d1563970b7de43373d5fd362de66a56430f56f9f45"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                             ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                             ' */ /* score: '16.50'*/
      $s4 = "`aaaaA61`" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c {
   meta:
      description = "mw - file 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
   strings:
      $s1 = "self.exe" fullword wide /* score: '22.00'*/
      $s2 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s3 = "sm.exe" fullword wide /* score: '16.00'*/
      $s4 = "ntdll.dlkernel32" fullword wide /* score: '12.00'*/
      $s5 = "pmmplk.bb.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "LdrGetProcedureA0" fullword ascii /* score: '10.00'*/
      $s7 = "content2,the7" fullword wide /* score: '9.00'*/
      $s8 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s9 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s10 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s11 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s12 = "(+,P:\"" fullword ascii /* score: '7.00'*/
      $s13 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s14 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s15 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
      $s16 = "q\\K -S6^" fullword ascii /* score: '5.00'*/
      $s17 = "\"Pqg-o!." fullword ascii /* score: '5.00'*/
      $s18 = "F13Daenables" fullword ascii /* score: '4.00'*/
      $s19 = "D$49D$4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "betaorNUMFL" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83 {
   meta:
      description = "mw - file 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s8 = "content2,the7" fullword wide /* score: '9.00'*/
      $s9 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s10 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s11 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s12 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s15 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s16 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s17 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce {
   meta:
      description = "mw - file 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s8 = "content2,the7" fullword wide /* score: '9.00'*/
      $s9 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s10 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s11 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s12 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s15 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s16 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s17 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2 {
   meta:
      description = "mw - file 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s8 = "content2,the7" fullword wide /* score: '9.00'*/
      $s9 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s10 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s11 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s12 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s15 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s16 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s17 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39 {
   meta:
      description = "mw - file 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s8 = "content2,the7" fullword wide /* score: '9.00'*/
      $s9 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s10 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s11 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s12 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s15 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s16 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s17 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f {
   meta:
      description = "mw - file 21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s15 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s16 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s17 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s18 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s19 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s20 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476 {
   meta:
      description = "mw - file 7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s15 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s16 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s17 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s18 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s19 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s20 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842 {
   meta:
      description = "mw - file ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s15 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s16 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s17 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s18 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s19 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s20 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8 {
   meta:
      description = "mw - file 2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8"
   strings:
      $s1 = "LMMMMMMMMMMMMMMMMMMMM" fullword ascii /* reversed goodware string 'MMMMMMMMMMMMMMMMMMMML' */ /* score: '16.50'*/
      $s2 = "       <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s3 = "             <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s4 = "        processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "                       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "                       publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s7 = "        version=\"1.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s8 = "                       version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s9 = "MMMMMMMMMMMMMMMMMMMMB" fullword ascii /* score: '6.50'*/
      $s10 = "AMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s11 = "MMMMMMMMMMMMMMMMMMMMP" fullword ascii /* score: '6.50'*/
      $s12 = "MMMMMMMMMMMMMMMMMMMMZ" fullword ascii /* score: '6.50'*/
      $s13 = "MMMMMMMMMMMMMMMMMMMMT" fullword ascii /* score: '6.50'*/
      $s14 = "ZMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s15 = "FMMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s16 = "VIMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s17 = "MMMMMMMMMMMMMMMMMMMMV" fullword ascii /* score: '6.50'*/
      $s18 = "XLMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s19 = "MMMMMMMMMMMMMMMMMMMMBR" fullword ascii /* score: '6.50'*/
      $s20 = "PMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f {
   meta:
      description = "mw - file d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "ComputerizedEmployeeRecord.LoginForm1.resources" fullword ascii /* score: '25.00'*/
      $s3 = "40yKvYu.exe" fullword wide /* score: '22.00'*/
      $s4 = "get_LoginForm1" fullword ascii /* score: '20.00'*/
      $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s6 = "LoginForm1" fullword wide /* score: '16.00'*/
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s8 = "set_LoginForm1" fullword ascii /* score: '15.00'*/
      $s9 = "m_LoginForm1" fullword ascii /* score: '15.00'*/
      $s10 = "get_LogoPictureBox" fullword ascii /* score: '14.00'*/
      $s11 = "get_OpenFileDialog1" fullword ascii /* score: '14.00'*/
      $s12 = "server=localhost;uid=sa;pwd=hamplustech; database=Computerized_Employee_Record_System" fullword wide /* score: '14.00'*/
      $s13 = "get_AboutSystemToolStripMenuItem" fullword ascii /* score: '12.00'*/
      $s14 = "_PasswordTextBox" fullword ascii /* score: '12.00'*/
      $s15 = "PasswordTextBox" fullword wide /* score: '12.00'*/
      $s16 = "get_UsernameLabel" fullword ascii /* score: '12.00'*/
      $s17 = "_PasswordLabel" fullword ascii /* score: '12.00'*/
      $s18 = "get_UsernameTextBox" fullword ascii /* score: '12.00'*/
      $s19 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s20 = "get_btnUpload" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8 {
   meta:
      description = "mw - file 4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "@.data3" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s15 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s16 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s17 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s18 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s19 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s20 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326 {
   meta:
      description = "mw - file cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "@.data3" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s15 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s16 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s17 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s18 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s19 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s20 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63 {
   meta:
      description = "mw - file cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63"
   strings:
      $s1 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" fullword ascii /* score: '12.00'*/
      $s2 = "103.234.72.237" fullword ascii /* score: '6.00'*/
      $s3 = "GCC: (x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0" fullword ascii /* score: '4.00'*/
      $s4 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "111111," fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = ")))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "\\@_Cr\"" fullword ascii /* score: '2.00'*/
      $s8 = "11111111111111111" ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "111111111111111" ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "MZuWVS" fullword ascii /* score: '1.00'*/
      $s11 = "@#N{Q4fj" fullword ascii /* score: '1.00'*/
      $s12 = "0X{|\\Y" fullword ascii /* score: '1.00'*/
      $s13 = "`\\7?dQh" fullword ascii /* score: '1.00'*/
      $s14 = "E{081X" fullword ascii /* score: '1.00'*/
      $s15 = "'%ES|\\" fullword ascii /* score: '1.00'*/
      $s16 = "HZ~Bq<" fullword ascii /* score: '1.00'*/
      $s17 = "=z6JX&" fullword ascii /* score: '1.00'*/
      $s18 = "111111,,,,,,,,,,,,,,,,,,,,,,,,,,,,," fullword ascii /* score: '1.00'*/
      $s19 = "9@\"ZaPF" fullword ascii /* score: '1.00'*/
      $s20 = "))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule sig_44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4 {
   meta:
      description = "mw - file 44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4"
   strings:
      $x1 = "HanzoInjection.exe" fullword ascii /* score: '32.00'*/
      $s2 = "payload.bin" fullword ascii /* score: '22.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii /* score: '20.00'*/
      $s4 = "1.bat=" fullword ascii /* score: '8.00'*/
      $s5 = "106.52.38.217" fullword ascii /* score: '6.00'*/
      $s6 = "hwiniThLw&" fullword ascii /* score: '4.00'*/
      $s7 = "RRRSRPh" fullword ascii /* score: '4.00'*/
      $s8 = "WWWWWh:Vy" fullword ascii /* score: '4.00'*/
      $s9 = "cvFfL9" fullword ascii /* score: '2.00'*/
      $s10 = ";;gR-;" fullword ascii /* score: '1.00'*/
      $s11 = "kU~K^/S" fullword ascii /* score: '1.00'*/
      $s12 = "BiW@wh" fullword ascii /* score: '1.00'*/
      $s13 = "[i<\"2<N" fullword ascii /* score: '1.00'*/
      $s14 = "{xRmP`" fullword ascii /* score: '1.00'*/
      $s15 = "Yb'6Iu" fullword ascii /* score: '1.00'*/
      $s16 = "ef3z6/" fullword ascii /* score: '1.00'*/
      $s17 = "aq>oMv" fullword ascii /* score: '1.00'*/
      $s18 = "b[1uNy" fullword ascii /* score: '1.00'*/
      $s19 = "]bJ/'[A4" fullword ascii /* score: '1.00'*/
      $s20 = ":wJ!Y{" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule sig_497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99 {
   meta:
      description = "mw - file 497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99"
   strings:
      $s1 = "snedea" fullword ascii /* score: '5.00'*/
      $s2 = "\\e.Xwb" fullword ascii /* score: '5.00'*/
      $s3 = "# $Z$4" fullword ascii /* score: '5.00'*/
      $s4 = "indyda" fullword ascii /* score: '5.00'*/
      $s5 = "HgnTL&D" fullword ascii /* score: '4.00'*/
      $s6 = "gntoR1\"j" fullword ascii /* score: '4.00'*/
      $s7 = "\"Hgac4l`" fullword ascii /* score: '4.00'*/
      $s8 = "HgnTL?" fullword ascii /* score: '4.00'*/
      $s9 = "Na|~Gows\\}jdUsaijYPJcW[GxEFPqKM]" fullword ascii /* score: '4.00'*/
      $s10 = "Igac1b(`" fullword ascii /* score: '4.00'*/
      $s11 = "wHgan<Cq" fullword ascii /* score: '4.00'*/
      $s12 = "{dqYHgac" fullword ascii /* score: '4.00'*/
      $s13 = "_HgaXHwa" fullword ascii /* score: '4.00'*/
      $s14 = "QIwqPIw" fullword ascii /* score: '4.00'*/
      $s15 = "EQIwMQIwYQIw-QIw" fullword ascii /* score: '4.00'*/
      $s16 = "HgdWHga" fullword ascii /* score: '4.00'*/
      $s17 = "Hgng1ea" fullword ascii /* score: '4.00'*/
      $s18 = "bHgazKb" fullword ascii /* score: '4.00'*/
      $s19 = "eJHf`b<" fullword ascii /* score: '4.00'*/
      $s20 = "pzfa%LPa" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2 {
   meta:
      description = "mw - file 669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2"
   strings:
      $s1 = ",WUvrWjv" fullword ascii /* score: '4.00'*/
      $s2 = "SVcWC\\" fullword ascii /* score: '4.00'*/
      $s3 = "%SRcWC\\" fullword ascii /* score: '4.00'*/
      $s4 = "&SRcW`\\" fullword ascii /* score: '4.00'*/
      $s5 = "SVcWl\\" fullword ascii /* score: '4.00'*/
      $s6 = "ywLA9cd}-" fullword ascii /* score: '4.00'*/
      $s7 = "gv/SRlWH\\" fullword ascii /* score: '4.00'*/
      $s8 = "ZbQY&/t" fullword ascii /* score: '4.00'*/
      $s9 = "YaWTvEW" fullword ascii /* score: '4.00'*/
      $s10 = "SWlWj\\" fullword ascii /* score: '4.00'*/
      $s11 = "&SRlWH\\" fullword ascii /* score: '4.00'*/
      $s12 = "SVcWk\\" fullword ascii /* score: '4.00'*/
      $s13 = "uKRmb,_" fullword ascii /* score: '4.00'*/
      $s14 = "YaWTv##" fullword ascii /* score: '4.00'*/
      $s15 = "^%Wauw8mb" fullword ascii /* score: '4.00'*/
      $s16 = "SVcWE\\" fullword ascii /* score: '4.00'*/
      $s17 = "0= />6-&,+:=\" 74xI|CvBqJd_fQjTkX@eHgNnEn\\sRuRx_|" fullword ascii /* score: '4.00'*/
      $s18 = "+8%S}}" fullword ascii /* score: '4.00'*/
      $s19 = "SVcWe\\" fullword ascii /* score: '4.00'*/
      $s20 = "SVcW]\\" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555 {
   meta:
      description = "mw - file 7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555"
   strings:
      $s1 = "pc)J:\\" fullword ascii /* score: '7.00'*/
      $s2 = "z+ o{M\"" fullword ascii /* score: '5.00'*/
      $s3 = "cihc)~S" fullword ascii /* score: '4.00'*/
      $s4 = "8vVWQ=!YZ0(KG'3EL*:o}" fullword ascii /* score: '4.00'*/
      $s5 = "u(.fuH)" fullword ascii /* score: '4.00'*/
      $s6 = ".uuI)]rZ(" fullword ascii /* score: '4.00'*/
      $s7 = "SYhc)vM" fullword ascii /* score: '4.00'*/
      $s8 = "SIbc)J;" fullword ascii /* score: '4.00'*/
      $s9 = "SKwc)J;" fullword ascii /* score: '4.00'*/
      $s10 = "_AUqRH[zESIgHZGlkem]flcVqwqK|~" fullword ascii /* score: '4.00'*/
      $s11 = "Zsrc)xrc)z" fullword ascii /* score: '4.00'*/
      $s12 = "UKrtn>rc" fullword ascii /* score: '4.00'*/
      $s13 = "rilD&*aQW" fullword ascii /* score: '4.00'*/
      $s14 = "niih?$" fullword ascii /* score: '4.00'*/
      $s15 = "sc)vM%z;" fullword ascii /* score: '3.50'*/
      $s16 = "\\[8U7}" fullword ascii /* score: '2.00'*/
      $s17 = "\\[8a7}" fullword ascii /* score: '2.00'*/
      $s18 = "\\[8Q7}" fullword ascii /* score: '2.00'*/
      $s19 = "H?Xrc)" fullword ascii /* score: '1.00'*/
      $s20 = "Jw/vM_" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35 {
   meta:
      description = "mw - file 86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35"
   strings:
      $s1 = "o<0c-+ " fullword ascii /* score: '5.00'*/
      $s2 = "s@* Bc" fullword ascii /* score: '5.00'*/
      $s3 = "xB)c1+ " fullword ascii /* score: '5.00'*/
      $s4 = "xB)c-* " fullword ascii /* score: '5.00'*/
      $s5 = "ghlv5|; " fullword ascii /* score: '4.00'*/
      $s6 = "elvtioQ" fullword ascii /* score: '4.00'*/
      $s7 = "8#KEy$" fullword ascii /* score: '4.00'*/
      $s8 = "ypgb?0L:k$" fullword ascii /* score: '4.00'*/
      $s9 = "*osctx!" fullword ascii /* score: '4.00'*/
      $s10 = "Opiwcq? " fullword ascii /* score: '4.00'*/
      $s11 = "O$tLnqt,7}H)" fullword ascii /* score: '4.00'*/
      $s12 = "es+hwtLU!" fullword ascii /* score: '4.00'*/
      $s13 = "hvcmi " fullword ascii /* score: '3.00'*/
      $s14 = "piwtI7" fullword ascii /* score: '2.00'*/
      $s15 = "J(c 9 " fullword ascii /* score: '1.00'*/
      $s16 = "J#a{b)" fullword ascii /* score: '1.00'*/
      $s17 = ")7/=>2" fullword ascii /* score: '1.00'*/
      $s18 = "t? tioQ" fullword ascii /* score: '1.00'*/
      $s19 = "ew#a{B" fullword ascii /* score: '1.00'*/
      $s20 = "|? c.Q" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f {
   meta:
      description = "mw - file 87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f"
   strings:
      $s1 = "zFSPyFS" fullword ascii /* score: '9.00'*/
      $s2 = "zeE.gdE" fullword ascii /* score: '7.00'*/
      $s3 = "HANPIANP" fullword ascii /* score: '6.50'*/
      $s4 = "7: iT* " fullword ascii /* score: '5.00'*/
      $s5 = "vcczvcc3" fullword ascii /* score: '5.00'*/
      $s6 = "nboznbo2" fullword ascii /* score: '5.00'*/
      $s7 = "racxzac9" fullword ascii /* score: '5.00'*/
      $s8 = "BTpqCTpq" fullword ascii /* score: '4.00'*/
      $s9 = "UKwoqcw#" fullword ascii /* score: '4.00'*/
      $s10 = "zPHq?c" fullword ascii /* score: '4.00'*/
      $s11 = "PZ}BtrlBtb" fullword ascii /* score: '4.00'*/
      $s12 = "xlKP<H{" fullword ascii /* score: '4.00'*/
      $s13 = "affwE~1?" fullword ascii /* score: '4.00'*/
      $s14 = "/ANP.ANPxANPxANP" fullword ascii /* score: '4.00'*/
      $s15 = "5JTZQntZ" fullword ascii /* score: '4.00'*/
      $s16 = "diNPeiNP" fullword ascii /* score: '4.00'*/
      $s17 = "dMiZ4]iZ" fullword ascii /* score: '4.00'*/
      $s18 = "kuqRauqR" fullword ascii /* score: '4.00'*/
      $s19 = "`ANPaANP" fullword ascii /* score: '4.00'*/
      $s20 = "hoqiq\\" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x48fc and filesize < 800KB and
      8 of them
}

rule abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051 {
   meta:
      description = "mw - file abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051"
   strings:
      $s1 = "PJiI'OHE" fullword ascii /* score: '4.00'*/
      $s2 = "yxPHJ{@r" fullword ascii /* score: '4.00'*/
      $s3 = "op~bf~uo}lhxtbcuKHRVBFY[YTDLPZOA'" fullword ascii /* score: '4.00'*/
      $s4 = "oIkC4sc4" fullword ascii /* score: '4.00'*/
      $s5 = "tKkYzKk" fullword ascii /* score: '4.00'*/
      $s6 = "ujQxP{?" fullword ascii /* score: '4.00'*/
      $s7 = ".Jkc/Jk" fullword ascii /* score: '4.00'*/
      $s8 = "xCKk$CKk" fullword ascii /* score: '4.00'*/
      $s9 = "vxPqo;|" fullword ascii /* score: '4.00'*/
      $s10 = "vss  v" fullword ascii /* score: '3.00'*/
      $s11 = "UZ;yP{" fullword ascii /* score: '1.00'*/
      $s12 = "lKz>_Zk" fullword ascii /* score: '1.00'*/
      $s13 = "'}r0yP" fullword ascii /* score: '1.00'*/
      $s14 = "Nq,s@q1s@y4w" fullword ascii /* score: '1.00'*/
      $s15 = "MFTxPq" fullword ascii /* score: '1.00'*/
      $s16 = "5YuU;Rx\\T" fullword ascii /* score: '1.00'*/
      $s17 = "6LxFtOL" fullword ascii /* score: '1.00'*/
      $s18 = "Ys&$0JW%" fullword ascii /* score: '1.00'*/
      $s19 = "i%4%7C" fullword ascii /* score: '1.00'*/
      $s20 = "U*:yPy" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f_4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e633_0 {
   meta:
      description = "mw - from files 21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f, 4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8, 7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476, ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842, cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
      hash2 = "4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
      hash3 = "7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
      hash4 = "ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
      hash5 = "cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s7 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s11 = "pYjp3Y`" fullword ascii /* score: '4.00'*/
      $s12 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s13 = "jfMXi^_d" fullword ascii /* score: '4.00'*/
      $s14 = "VisStruct" fullword ascii /* score: '4.00'*/
      $s15 = "VrNxNrN`FbNX~k" fullword ascii /* score: '4.00'*/
      $s16 = "+.HuC-q" fullword ascii /* score: '4.00'*/
      $s17 = "YpGcY&G" fullword ascii /* score: '4.00'*/
      $s18 = "KXjC,Yr" fullword ascii /* score: '4.00'*/
      $s19 = "irH#ipHshbHshb" fullword ascii /* score: '4.00'*/
      $s20 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83_923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4_1 {
   meta:
      description = "mw - from files 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash2 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash3 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      hash4 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
   strings:
      $s1 = "wv.exe" fullword wide /* score: '16.00'*/
      $s2 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s4 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s5 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s6 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s7 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s8 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s9 = "=OuF /d" fullword ascii /* score: '5.00'*/
      $s10 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
      $s11 = "aPMFm3<" fullword ascii /* score: '4.00'*/
      $s12 = ";HHfz+4o" fullword ascii /* score: '4.00'*/
      $s13 = "aXKnw-:" fullword ascii /* score: '4.00'*/
      $s14 = "1?1E1c1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "Bbvj'W2BA" fullword ascii /* score: '4.00'*/
      $s16 = ",S.WXw" fullword ascii /* score: '4.00'*/
      $s17 = "fjxcgg0c" fullword ascii /* score: '4.00'*/
      $s18 = ">maOs\"K[" fullword ascii /* score: '4.00'*/
      $s19 = "'5'`krWL$qUj" fullword ascii /* score: '4.00'*/
      $s20 = "!AtbFDXt" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243_a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d_2 {
   meta:
      description = "mw - from files 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash2 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      hash3 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s2 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s3 = " A^A]A\\" fullword ascii /* score: '1.00'*/
      $s4 = "D$ H9D$(tSH" fullword ascii /* score: '1.00'*/
      $s5 = " A]A\\_" fullword ascii /* score: '1.00'*/
      $s6 = "f99t%H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "D$(H9D$ s$H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "D$XD+D$PD" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "@8x(u<H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s10 = "fD9\"t!H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s11 = "T$HD;T$@C" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s12 = "LT$@;D$L~" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s13 = "f99t*H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s14 = "T$PD+T$XD" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243_a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d_3 {
   meta:
      description = "mw - from files 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash2 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
   strings:
      $s1 = "(LcD$@L" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "w(D9t$(t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "System" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.18'*/ /* Goodware String - occured 1819 times */
      $s4 = "(LcL$HI" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "D$HLcL$HHcT$8L" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "ForceRemove" fullword wide /* PEStudio Blacklist: strings */ /* score: '2.38'*/ /* Goodware String - occured 2623 times */
      $s7 = "NoRemove" fullword wide /* PEStudio Blacklist: strings */ /* score: '2.32'*/ /* Goodware String - occured 2676 times */
      $s8 = "fD9#thH" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43_5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f44075_4 {
   meta:
      description = "mw - from files 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash2 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
   strings:
      $s1 = ".?AVCommonError@@" fullword ascii /* score: '10.00'*/
      $s2 = "inBuffer::get_8: noenough " fullword ascii /* score: '9.00'*/
      $s3 = "unpack error not enough " fullword ascii /* score: '9.00'*/
      $s4 = "memory alloc error @9" fullword ascii /* score: '7.00'*/
      $s5 = "alloc error @10" fullword ascii /* score: '7.00'*/
      $s6 = "alloc error @12" fullword ascii /* score: '7.00'*/
      $s7 = "vector too long" fullword ascii /* score: '6.00'*/
      $s8 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " fullword ascii /* score: '6.00'*/
      $s9 = "unknown compression method" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 498 times */
      $s10 = "D$@9D$Dv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "inBuffer unpack:  buffer size to small" fullword ascii /* score: '4.00'*/
      $s12 = ".rdata$voltmd" fullword ascii /* score: '4.00'*/
      $s13 = "H+D$8H;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "HkD$( H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "WHkD$8 H" fullword ascii /* score: '4.00'*/
      $s16 = "D$xHkL$( H" fullword ascii /* score: '4.00'*/
      $s17 = "k4+kP+" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "D$`9D$ v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "D$PH9D$ v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "D$09D$,v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802_ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec9465_5 {
   meta:
      description = "mw - from files d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
      hash2 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "bin\\amd64\\MSPDB110.DLL" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\11.0\\Setup\\VC" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "}}}}cc" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "./.,.,." fullword ascii /* score: '1.00'*/
      $s5 = "./.,./." fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4_6 {
   meta:
      description = "mw - from files 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash2 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash3 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash4 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash5 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash6 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "D$XD9x" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "u3HcH<H" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "vC8_(t" fullword ascii /* score: '1.00'*/
      $s4 = "ue!T$(H!T$ " fullword ascii /* score: '1.00'*/
      $s5 = " A_A^A\\" fullword ascii /* score: '1.00'*/
      $s6 = "uF8Z(t" fullword ascii /* score: '1.00'*/
      $s7 = "H97u+A" fullword ascii /* score: '1.00'*/
      $s8 = " H3E H3E" fullword ascii /* score: '1.00'*/
      $s9 = "vB8_(t" fullword ascii /* score: '1.00'*/
      $s10 = " A_A^_" fullword ascii /* score: '1.00'*/
      $s11 = "u\"8Z(t" fullword ascii /* score: '1.00'*/
      $s12 = "L$ |+L;" fullword ascii /* score: '1.00'*/
      $s13 = "L$&8\\$&t,8Y" fullword ascii /* score: '1.00'*/
      $s14 = "D!l$xA" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4_7 {
   meta:
      description = "mw - from files 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583, b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash2 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash3 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash4 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash5 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash6 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash7 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      hash8 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      hash9 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash10 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s3 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s4 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s5 = " delete[]" fullword ascii /* score: '4.00'*/
      $s6 = " delete" fullword ascii /* score: '3.00'*/
      $s7 = " new[]" fullword ascii /* score: '1.00'*/
      $s8 = " Base Class Array'" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243_e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920_8 {
   meta:
      description = "mw - from files 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash2 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = "MAZOWIECKIE1" fullword ascii /* score: '5.00'*/
      $s2 = "Warszawa1" fullword ascii /* score: '5.00'*/
      $s3 = "Y`CUzD]" fullword ascii /* score: '1.00'*/
      $s4 = "201202000000Z" fullword ascii /* score: '1.00'*/
      $s5 = "00001888681" ascii /* score: '1.00'*/
      $s6 = "211129235959Z0" fullword ascii /* score: '1.00'*/
      $s7 = "12041812" ascii /* score: '1.00'*/
      $s8 = "PL-00001888680" fullword ascii /* score: '1.00'*/
      $s9 = "27041812" ascii /* score: '1.00'*/
      $s10 = "211129235959" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4_9 {
   meta:
      description = "mw - from files 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash2 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash3 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash4 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash5 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash6 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      hash7 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s3 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s4 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s5 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s6 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "api-ms-" fullword wide /* score: '1.00'*/
      $s8 = "ext-ms-" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281_32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e53223074_10 {
   meta:
      description = "mw - from files 2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281, 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c, 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281"
      hash2 = "32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      hash3 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash4 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash5 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      hash6 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
   strings:
      $s1 = "content2,the7" fullword wide /* score: '9.00'*/
      $s2 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s3 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s4 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s5 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s6 = "frommountainwasfF537" fullword wide /* score: '5.00'*/
      $s7 = "F13Daenables" fullword ascii /* score: '4.00'*/
      $s8 = "betaorNUMFL" fullword wide /* score: '4.00'*/
      $s9 = "mNoalong" fullword wide /* score: '4.00'*/
      $s10 = "forensicnumber,1BranchactivityasksLinux" fullword wide /* score: '4.00'*/
      $s11 = "d38subsequentu0thumbnailsapplet" fullword wide /* score: '4.00'*/
      $s12 = "loadblayoutChromeandwillie" fullword wide /* score: '4.00'*/
      $s13 = "wnUlifeTheofficialt" fullword wide /* score: '4.00'*/
      $s14 = "bubbaYHjGooglebeforeschoolRsecurity" fullword wide /* score: '4.00'*/
      $s15 = "theirxqcrashes.4444inlalso" fullword wide /* score: '4.00'*/
      $s16 = "m3bookmarks,kfIqb" fullword wide /* score: '4.00'*/
      $s17 = "of309Allavdemonstratorcurrently" fullword wide /* score: '4.00'*/
      $s18 = "GFattackfree" fullword wide /* score: '4.00'*/
      $s19 = "the5Partial" fullword wide /* score: '4.00'*/
      $s20 = "HreleaseUniversitybuilt-inbutqthatVDI" fullword wide /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f_a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e_11 {
   meta:
      description = "mw - from files 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea, d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280, fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash2 = "a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
      hash3 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      hash4 = "fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s2 = "DigiCert Timestamp 20210" fullword ascii /* score: '4.00'*/
      $s3 = "QJxy6z'" fullword ascii /* score: '4.00'*/
      $s4 = "DigiCert, Inc.1 0" fullword ascii /* score: '4.00'*/
      $s5 = "310106000000Z0H1" fullword ascii /* score: '1.00'*/
      $s6 = "210101000000Z" fullword ascii /* score: '1.00'*/
      $s7 = "16010712" ascii /* score: '1.00'*/
      $s8 = "dwc_#Ri" fullword ascii /* score: '1.00'*/
      $s9 = "31010712" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d_d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763_12 {
   meta:
      description = "mw - from files d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
      hash2 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s5 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s6 = "b77a5c561934e089" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03_2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7d_13 {
   meta:
      description = "mw - from files 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash2 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash3 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
   strings:
      $s1 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s2 = "u4I9}(" fullword ascii /* score: '1.00'*/
      $s3 = "H;xXu5" fullword ascii /* score: '1.00'*/
      $s4 = "D$HL9gXt" fullword ascii /* score: '1.00'*/
      $s5 = "D8L$0uP" fullword ascii /* score: '1.00'*/
      $s6 = "L!d$(L!d$@D" fullword ascii /* score: '1.00'*/
      $s7 = ";I9}(tiH" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c_7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c9_14 {
   meta:
      description = "mw - from files 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c, 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      hash2 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash3 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash4 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      hash5 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
   strings:
      $s1 = "self.exe" fullword wide /* score: '22.00'*/
      $s2 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s3 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s4 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s5 = ".m5Fih" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f_2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7d_15 {
   meta:
      description = "mw - from files 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash2 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash3 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
   strings:
      $s1 = "<Ct-<D" fullword ascii /* score: '1.00'*/
      $s2 = "D<P0@:" fullword ascii /* score: '1.00'*/
      $s3 = "<StW@:" fullword ascii /* score: '1.00'*/
      $s4 = "<g~{<itd<ntY<ot7<pt" fullword ascii /* score: '1.00'*/
      $s5 = "<htl<jt\\<lt4<tt$<wt" fullword ascii /* score: '1.00'*/
      $s6 = "<utT@:" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618_d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9ad_16 {
   meta:
      description = "mw - from files 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash2 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
   strings:
      $s1 = "  </compatibility>" fullword ascii /* score: '7.00'*/
      $s2 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s3 = "      <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s4 = "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s5 = "a2440225f93a" ascii /* score: '1.00'*/
      $s6 = "83d0f6d0da78" ascii /* score: '1.00'*/
      $s7 = "48fd50a15a9a" ascii /* score: '1.00'*/
      $s8 = "d69d4a4a6e38" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c_91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b1_17 {
   meta:
      description = "mw - from files 1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c, 91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530, be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-04"
      hash1 = "1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
      hash2 = "91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
      hash3 = "be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s3 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s5 = "/!,1{qm" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

