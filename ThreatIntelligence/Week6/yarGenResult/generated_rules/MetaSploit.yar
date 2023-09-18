/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_25ea2b15ea0a7a7559d1996dcc1b0c7dbb221f60a38a18ae8e3a5820df4d17bf {
   meta:
      description = "mw - file 25ea2b15ea0a7a7559d1996dcc1b0c7dbb221f60a38a18ae8e3a5820df4d17bf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "25ea2b15ea0a7a7559d1996dcc1b0c7dbb221f60a38a18ae8e3a5820df4d17bf"
   strings:
      $s1 = "C:\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb" fullword ascii /* score: '21.00'*/
      $s2 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>" fullword ascii /* score: '17.00'*/
      $s3 = "    -T content-type Content-type header for POSTing, eg." fullword ascii /* score: '15.00'*/
      $s4 = "    -h              Display usage information (this message)" fullword ascii /* score: '12.00'*/
      $s5 = "    -i              Use HEAD instead of GET" fullword ascii /* score: '12.00'*/
      $s6 = "    -p postfile     File containing data to POST. Remember also to set -T" fullword ascii /* score: '12.00'*/
      $s7 = "    -k              Use HTTP KeepAlive feature" fullword ascii /* score: '10.00'*/
      $s8 = "    -r              Don't exit on socket receive errors." fullword ascii /* score: '10.00'*/
      $s9 = " This is ApacheBench, Version %s <i>&lt;%s&gt;</i><br>" fullword ascii /* score: '10.00'*/
      $s10 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>" fullword ascii /* score: '10.00'*/
      $s11 = "    -X proxy:port   Proxyserver and port number to use" fullword ascii /* score: '9.00'*/
      $s12 = "  %d%%  %5I64d" fullword ascii /* score: '8.00'*/
      $s13 = "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'" fullword ascii /* score: '8.00'*/
      $s14 = "    -n requests     Number of requests to perform" fullword ascii /* score: '7.00'*/
      $s15 = "    -z attributes   String to insert as td or th attributes" fullword ascii /* score: '7.00'*/
      $s16 = "    -b windowsize   Size of TCP send/receive buffer, in bytes" fullword ascii /* score: '7.00'*/
      $s17 = "    -x attributes   String to insert as table attributes" fullword ascii /* score: '7.00'*/
      $s18 = "    -t timelimit    Seconds to max. wait for responses" fullword ascii /* score: '7.00'*/
      $s19 = "                    are a colon separated username and password." fullword ascii /* score: '7.00'*/
      $s20 = "    -y attributes   String to insert as tr attributes" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1 {
   meta:
      description = "mw - file f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
   strings:
      $s1 = "CSShell.dll" fullword ascii /* score: '28.00'*/
      $s2 = "11Protect.dll" fullword ascii /* score: '23.00'*/
      $s3 = "F:\\Projects\\gogs\\Company\\CSProtect\\Release\\11Protect.pdb" fullword ascii /* score: '22.00'*/
      $s4 = "cstrike.exe" fullword ascii /* score: '22.00'*/
      $s5 = "%d%.2d%.2d%.2d%.2d%.2d_%d.log" fullword ascii /* score: '20.00'*/
      $s6 = "sw.dll" fullword ascii /* score: '17.00'*/
      $s7 = "hw.dll" fullword ascii /* score: '17.00'*/
      $s8 = ".?AVCProcessScanner@@" fullword ascii /* score: '16.00'*/
      $s9 = "{\"Module\":\"%s\",\"Offset\":%u,\"Address\":%u,\"Hash\":\"%s\"}" fullword ascii /* score: '15.50'*/
      $s10 = "process_include" fullword ascii /* score: '15.00'*/
      $s11 = "\"cstrike.exe" fullword ascii /* score: '15.00'*/
      $s12 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s13 = "ambiguous host or service" fullword ascii /* score: '14.00'*/
      $s14 = "cms_get0_econtent_type" fullword ascii /* score: '14.00'*/
      $s15 = "ssl command section not found" fullword ascii /* score: '14.00'*/
      $s16 = "assertion failed: (AES_ENCRYPT == enc) || (AES_DECRYPT == enc)" fullword ascii /* score: '14.00'*/
      $s17 = "malformed host or service" fullword ascii /* score: '14.00'*/
      $s18 = "ssl command section empty" fullword ascii /* score: '14.00'*/
      $s19 = "no hostname or service specified" fullword ascii /* score: '14.00'*/
      $s20 = "h.dllhel32hkern" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db {
   meta:
      description = "mw - file a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db"
   strings:
      $s1 = "VMProtectSDK32.dll" fullword ascii /* score: '23.00'*/
      $s2 = "VSSSSSSP" fullword ascii /* reversed goodware string 'PSSSSSSV' */ /* score: '16.50'*/
      $s3 = "ifEsvJV57" fullword ascii /* base64 encoded string '|K/%^{' */ /* score: '15.00'*/
      $s4 = "BIzBXdT91WWW" fullword ascii /* base64 encoded string '#0Wu?uYe' */ /* score: '14.00'*/
      $s5 = "?DecreaseBpp: target BPP greater than source BPP" fullword ascii /* score: '14.00'*/
      $s6 = "GNUUmOC19WWW" fullword ascii /* base64 encoded string '5E&8-}Ye' */ /* score: '14.00'*/
      $s7 = "    Component %d: %dhx%dv q=%d" fullword ascii /* score: '13.50'*/
      $s8 = "RQSPWV" fullword ascii /* reversed goodware string 'VWPSQR' */ /* score: '13.50'*/
      $s9 = "WWWWSW" fullword ascii /* reversed goodware string 'WSWWWW' */ /* score: '13.50'*/
      $s10 = "null image!!!" fullword ascii /* score: '13.00'*/
      $s11 = "vgetmantps" fullword ascii /* score: '13.00'*/
      $s12 = "vgetexppd" fullword ascii /* score: '13.00'*/
      $s13 = "vgetmantpd" fullword ascii /* score: '13.00'*/
      $s14 = "vgetmantss" fullword ascii /* score: '13.00'*/
      $s15 = "h.dllhel32hkern" fullword ascii /* score: '13.00'*/
      $s16 = "vgetexpps" fullword ascii /* score: '13.00'*/
      $s17 = "vgetexpsd" fullword ascii /* score: '13.00'*/
      $s18 = "vgetmantsd" fullword ascii /* score: '13.00'*/
      $s19 = "vpternlogq" fullword ascii /* score: '13.00'*/
      $s20 = "vpternlogd" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      8 of them
}

rule sig_6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30 {
   meta:
      description = "mw - file 6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "[+] ShellExec success" fullword ascii /* score: '25.00'*/
      $s6 = "[+] before ShellExec" fullword ascii /* score: '25.00'*/
      $s7 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s8 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii /* score: '22.00'*/
      $s10 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s11 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s12 = "[-] CoGetObject FAILURE" fullword ascii /* score: '18.00'*/
      $s13 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s14 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s15 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s16 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s17 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s18 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s19 = "Executing file: " fullword ascii /* score: '16.00'*/
      $s20 = "[Firefox StoredLogins Cleared!]" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0 {
   meta:
      description = "mw - file 817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "[+] ShellExec success" fullword ascii /* score: '25.00'*/
      $s6 = "[+] before ShellExec" fullword ascii /* score: '25.00'*/
      $s7 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s8 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii /* score: '22.00'*/
      $s10 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s11 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s12 = "[-] CoGetObject FAILURE" fullword ascii /* score: '18.00'*/
      $s13 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s14 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s15 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s16 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s17 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s18 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s19 = "Executing file: " fullword ascii /* score: '16.00'*/
      $s20 = "[Firefox StoredLogins Cleared!]" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a {
   meta:
      description = "mw - file e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "[+] ShellExec success" fullword ascii /* score: '25.00'*/
      $s6 = "[+] before ShellExec" fullword ascii /* score: '25.00'*/
      $s7 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s8 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii /* score: '22.00'*/
      $s10 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s11 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s12 = "[-] CoGetObject FAILURE" fullword ascii /* score: '18.00'*/
      $s13 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s14 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s15 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s16 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s17 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s18 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s19 = "Executing file: " fullword ascii /* score: '16.00'*/
      $s20 = "[Firefox StoredLogins Cleared!]" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule c27132aa1c08b6c8b73d58af7c602d551e4a0ca5d537fb687f7b9849885c5518 {
   meta:
      description = "mw - file c27132aa1c08b6c8b73d58af7c602d551e4a0ca5d537fb687f7b9849885c5518"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "c27132aa1c08b6c8b73d58af7c602d551e4a0ca5d537fb687f7b9849885c5518"
   strings:
      $s1 = "C:\\DistributedAutoLink\\Temp\\CompileOutputDir\\ScanFrm.pdb" fullword ascii /* score: '28.00'*/
      $s2 = "MZKERNEL32.DLL" fullword ascii /* score: '23.00'*/
      $s3 = "ScanFrm.exe" fullword wide /* score: '23.00'*/
      $s4 = "*-.-*ScanFrm.exe.exe" fullword ascii /* score: '20.00'*/
      $s5 = "%s\\RSXML.DLL" fullword ascii /* score: '20.00'*/
      $s6 = "%d processor(s), type %d." fullword ascii /* score: '18.00'*/
      $s7 = "GetDLLObject" fullword ascii /* score: '14.00'*/
      $s8 = "h.dllhel32hkern" fullword ascii /* score: '13.00'*/
      $s9 = "rsscomps.xml" fullword ascii /* score: '13.00'*/
      $s10 = "Thread Id occurred error: %d." fullword ascii /* score: '13.00'*/
      $s11 = "RsCreateObjLoader" fullword ascii /* score: '13.00'*/
      $s12 = "OS Version: %d.%d, Build: %d." fullword ascii /* score: '12.50'*/
      $s13 = "Error occurred at %d/%d/%d %d:%d:%d.%d." fullword ascii /* score: '12.50'*/
      $s14 = "a DLL Initialization Failed" fullword ascii /* score: '12.00'*/
      $s15 = "Beijing Rising Information Technology Co., Ltd." fullword wide /* score: '11.00'*/
      $s16 = "Copyright(C) 2008-2009 Beijing Rising Information Technology Co., Ltd. All Rights Reserved." fullword wide /* score: '11.00'*/
      $s17 = "%u Bytes user address space." fullword ascii /* score: '10.00'*/
      $s18 = "%u Bytes user address space free." fullword ascii /* score: '10.00'*/
      $s19 = "a Float Denormal Operand" fullword ascii /* score: '9.00'*/
      $s20 = "horyAhrecthwsDihindohGetW" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule b89e155282772215d6d481677cb04a62834bcd83b4999a441b825ac33655954d {
   meta:
      description = "mw - file b89e155282772215d6d481677cb04a62834bcd83b4999a441b825ac33655954d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "b89e155282772215d6d481677cb04a62834bcd83b4999a441b825ac33655954d"
   strings:
      $s1 = "wxvxpbwl.exe" fullword ascii /* score: '22.00'*/
      $s2 = "h.dllhel32hkernT" fullword ascii /* score: '13.00'*/
      $s3 = "BPOST /cgi-bt" fullword ascii /* score: '13.00'*/
      $s4 = "h32.dhuserT" fullword ascii /* score: '10.00'*/
      $s5 = "c:\\B Fil" fullword ascii /* score: '10.00'*/
      $s6 = "GetSystPADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDIN" ascii /* score: '9.00'*/
      $s7 = "GetSystPADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDIN" ascii /* score: '9.00'*/
      $s8 = "GXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s9 = "me error" fullword ascii /* score: '6.00'*/
      $s10 = "WriteBiatkodxvt" fullword ascii /* score: '4.00'*/
      $s11 = "E .rLn" fullword ascii /* score: '4.00'*/
      $s12 = "1By>ToWideChar" fullword ascii /* score: '4.00'*/
      $s13 = "ageBox" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "eSOFTWAREq" fullword ascii /* score: '4.00'*/
      $s15 = "LDPh(Qu" fullword ascii /* score: '4.00'*/
      $s16 = "Numb6Of" fullword ascii /* score: '4.00'*/
      $s17 = "USER ." fullword ascii /* score: '4.00'*/
      $s18 = "gh spac#f{lowi8)" fullword ascii /* score: '4.00'*/
      $s19 = "3x<%S_" fullword ascii /* score: '4.00'*/
      $s20 = "O!argu(s_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule sig_3aecf7122ee8971bddbdfdc2014e48dc65b0669f178aee0ba85b096b00738ad8 {
   meta:
      description = "mw - file 3aecf7122ee8971bddbdfdc2014e48dc65b0669f178aee0ba85b096b00738ad8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "3aecf7122ee8971bddbdfdc2014e48dc65b0669f178aee0ba85b096b00738ad8"
   strings:
      $s1 = "// Originally reported here: http://blog.fireeye.com/research/2012/08/zero-day-season-is-not-over-yet.html" fullword ascii /* score: '30.00'*/
      $s2 = "// Oracle's Security Alert: http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html" fullword ascii /* score: '21.00'*/
      $s3 = "import metasploit.Payload;" fullword ascii /* score: '21.00'*/
      $s4 = "// CVE-2012-4681 Exploit - See java_jre17_exec.rb" fullword ascii /* score: '20.00'*/
      $s5 = "// PoC by Joshua J. Drake: https://twitter.com/jduck1337/status/239875285913317376" fullword ascii /* score: '17.00'*/
      $s6 = "        localExpression.execute();" fullword ascii /* score: '16.00'*/
      $s7 = "        localStatement.execute();" fullword ascii /* score: '16.00'*/
      $s8 = "Payload.main(null);               " fullword ascii /* score: '11.00'*/
      $s9 = "import java.awt.Graphics;" fullword ascii /* score: '10.00'*/
      $s10 = "import java.net.URL;" fullword ascii /* score: '10.00'*/
      $s11 = "import java.beans.Statement;" fullword ascii /* score: '7.00'*/
      $s12 = "import java.beans.Expression;" fullword ascii /* score: '7.00'*/
      $s13 = "public class Exploit extends Applet" fullword ascii /* score: '7.00'*/
      $s14 = "import java.security.*;" fullword ascii /* score: '7.00'*/
      $s15 = "import java.applet.Applet;" fullword ascii /* score: '7.00'*/
      $s16 = "import java.lang.reflect.Field;" fullword ascii /* score: '7.00'*/
      $s17 = "        Expression localExpression = new Expression(GetClass(\"sun.awt.SunToolkit\"), \"getField\", arrayOfObject);" fullword ascii /* score: '6.00'*/
      $s18 = "    public Exploit()" fullword ascii /* score: '6.00'*/
      $s19 = "        }" fullword ascii /* reversed goodware string '}        ' */ /* score: '6.00'*/
      $s20 = "        {" fullword ascii /* reversed goodware string '{        ' */ /* score: '6.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 7KB and
      8 of them
}

rule ea7c0293025ff408bec874f686497bd9daa85214ba604aa6c27d64dbf5b31f8d {
   meta:
      description = "mw - file ea7c0293025ff408bec874f686497bd9daa85214ba604aa6c27d64dbf5b31f8d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "ea7c0293025ff408bec874f686497bd9daa85214ba604aa6c27d64dbf5b31f8d"
   strings:
      $x1 = "# This module requires Metasploit: https://metasploit.com/download" fullword ascii /* score: '36.00'*/
      $x2 = "# Current source: https://github.com/rapid7/metasploit-framework" fullword ascii /* score: '33.00'*/
      $s3 = "  system(\"jarsigner -storepass importkey signed_jar/jarsigner-signed.jar importkey\")" fullword ascii /* score: '20.00'*/
      $s4 = "  system(\"java -cp . ImportKey signed_jar/key.der signed_jar/cert.der\")" fullword ascii /* score: '17.00'*/
      $s5 = "  system(\"openssl pkcs8 -topk8 -nocrypt -in signed_jar/key.pem -inform PEM -out signed_jar/key.der -outform DER\")" fullword ascii /* score: '17.00'*/
      $s6 = "import metasploit.*;" fullword ascii /* score: '16.00'*/
      $s7 = "  include Msf::Exploit::Remote::HttpServer::HTML" fullword ascii /* score: '14.00'*/
      $s8 = "  system(\"openssl x509 -in signed_jar/cert.pem -inform PEM -out signed_jar/cert.der -outform DER\")" fullword ascii /* score: '14.00'*/
      $s9 = "      'Name'          => 'Java Signed Applet Social Engineering Code Execution'," fullword ascii /* score: '13.00'*/
      $s10 = "class MetasploitModule < Msf::Exploit::Remote" fullword ascii /* score: '12.00'*/
      $s11 = "  File.open(\"signed_jar/key.pem\",  \"wb\")     { |f| f.write(@key.to_s  + @key.public_key.to_s) }" fullword ascii /* score: '12.00'*/
      $s12 = "        Either way, once the user clicks \"run\", the applet executes" fullword ascii /* score: '12.00'*/
      $s13 = "http://www.agentbob.info/agentbob/79-AB.html" fullword ascii /* score: '12.00'*/
      $s14 = "      print_error(\"Failed to generate the payload.\")" fullword ascii /* score: '11.00'*/
      $s15 = "    #File.open(\"payload.jar\", \"wb\") { |f| f.write(jar.to_s) }" fullword ascii /* score: '11.00'*/
      $s16 = "  system(\"rm -rf signed_jar/*\")" fullword ascii /* score: '11.00'*/
      $s17 = "    data_dir = File.join(Msf::Config.data_directory, \"exploits\", self.shortname)" fullword ascii /* score: '10.00'*/
      $s18 = "  system(\"mv ~/keystore.ImportKey ~/.keystore\")" fullword ascii /* score: '10.00'*/
      $s19 = "      'DefaultTarget'  => 1," fullword ascii /* score: '9.00'*/
      $s20 = "  File.open(\"signed_jar/cert.pem\", \"wb\")     { |f| f.write(@cert.to_s + @key.to_s) }" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2323 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30_817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa8426_0 {
   meta:
      description = "mw - from files 6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30, 817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0, e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30"
      hash2 = "817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0"
      hash3 = "e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide /* score: '26.00'*/
      $s5 = "[+] ShellExec success" fullword ascii /* score: '25.00'*/
      $s6 = "[+] before ShellExec" fullword ascii /* score: '25.00'*/
      $s7 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s8 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii /* score: '22.00'*/
      $s10 = "rmclient.exe" fullword wide /* score: '22.00'*/
      $s11 = "Keylogger initialization failure: error " fullword ascii /* score: '20.00'*/
      $s12 = "[-] CoGetObject FAILURE" fullword ascii /* score: '18.00'*/
      $s13 = "Offline Keylogger Started" fullword ascii /* score: '17.00'*/
      $s14 = "Online Keylogger Started" fullword ascii /* score: '17.00'*/
      $s15 = "Offline Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s16 = "Online Keylogger Stopped" fullword ascii /* score: '17.00'*/
      $s17 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide /* score: '17.00'*/
      $s18 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s19 = "Executing file: " fullword ascii /* score: '16.00'*/
      $s20 = "[Firefox StoredLogins Cleared!]" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db_f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4af_1 {
   meta:
      description = "mw - from files a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db, f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db"
      hash2 = "f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
   strings:
      $s1 = "4$%y:\\Y" fullword ascii /* score: '9.50'*/
      $s2 = "hdleAheHanhodulhGetM" fullword ascii /* score: '9.00'*/
      $s3 = "$\\jehmTimhystehGetS" fullword ascii /* score: '9.00'*/
      $s4 = "h32.dhuser" fullword ascii /* score: '7.00'*/
      $s5 = "3jlhl.dlhntdl" fullword ascii /* score: '7.00'*/
      $s6 = "jlhl.dlhntdl" fullword ascii /* score: '7.00'*/
      $s7 = "hreadhonThhmatihnforheryIhNtQu" fullword ascii /* score: '7.00'*/
      $s8 = "[+M -q5" fullword ascii /* score: '5.00'*/
      $s9 = "SeDebugPrivilege" fullword ascii /* PEStudio Blacklist: priv */ /* score: '4.86'*/ /* Goodware String - occured 141 times */
      $s10 = "SYSTEM" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 509 times */
      $s11 = "<$\\jrhtchehispahionDhceptherExhKiUs" fullword ascii /* score: '4.00'*/
      $s12 = "YQhPbR6Y" fullword ascii /* score: '4.00'*/
      $s13 = "yOAahTo" fullword ascii /* score: '4.00'*/
      $s14 = "jZhD|@ j" fullword ascii /* score: '4.00'*/
      $s15 = "hrocehatePhrminhZwTe" fullword ascii /* score: '4.00'*/
      $s16 = "hTimehFilehmeTohemTihSyst" fullword ascii /* score: '4.00'*/
      $s17 = "$zBjFX-zBjFU" fullword ascii /* score: '4.00'*/
      $s18 = "hrotehualPhVirt" fullword ascii /* score: '4.00'*/
      $s19 = "$xIjcX-xIjc" fullword ascii /* score: '4.00'*/
      $s20 = "$0NxrX-0Nxr" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30_817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa8426_2 {
   meta:
      description = "mw - from files 6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30, 817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0, a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db, e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a, f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "6af8bc2a8832b510703163e0697b9f598416d190ae21f94ac1897f1c4b2eaa30"
      hash2 = "817323d6d0b4a8ff414163a8bb9b7e1107205e5eb3f33a1ded9bfa84269c23c0"
      hash3 = "a123b755bf911738befebe88e1f4e9f5b5b863c4ad46813de79bf9ed1cb010db"
      hash4 = "e80146515a83c83640e0356c31e79affeeeba923c9def193d8b55bbb866b2d4a"
      hash5 = "f8869b5afa824baefb63d9d355fcb059f00b7310eda863dd344811b4afbf41e1"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s3 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s4 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s5 = " delete[]" fullword ascii /* score: '4.00'*/
      $s6 = " delete" fullword ascii /* score: '3.00'*/
      $s7 = " new[]" fullword ascii /* score: '1.00'*/
      $s8 = " Base Class Array'" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

