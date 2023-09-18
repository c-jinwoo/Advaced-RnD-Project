/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a {
   meta:
      description = "mw - file 080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a"
   strings:
      $s1 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s2 = "Lhttp://pki-crl.symauth.com/ca_d409a5cb737dc0768fd08ed5256f3633/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s3 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii /* score: '15.00'*/
      $s4 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii /* score: '15.00'*/
      $s5 = "http://pki-ocsp.symauth.com0" fullword ascii /* score: '13.00'*/
      $s6 = "Oreans Technologies0" fullword ascii /* score: '9.00'*/
      $s7 = "# -5l[\"." fullword ascii /* score: '9.00'*/
      $s8 = "skipact" fullword ascii /* score: '8.00'*/
      $s9 = ">U|%S%" fullword ascii /* score: '8.00'*/
      $s10 = "bugycseck" fullword ascii /* score: '8.00'*/
      $s11 = "F:\"`F*t" fullword ascii /* score: '7.00'*/
      $s12 = "@|c:\\mirn" fullword ascii /* score: '7.00'*/
      $s13 = "xrW:\"A" fullword ascii /* score: '7.00'*/
      $s14 = ".imports" fullword ascii /* score: '7.00'*/
      $s15 = "XSQRVWUH" fullword ascii /* score: '6.50'*/
      $s16 = ") -g/'" fullword ascii /* score: '5.00'*/
      $s17 = ",/+ b``" fullword ascii /* score: '5.00'*/
      $s18 = "J -;*t" fullword ascii /* score: '5.00'*/
      $s19 = "_Z /SV" fullword ascii /* score: '5.00'*/
      $s20 = "S=%+ 1" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule sig_1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50 {
   meta:
      description = "mw - file 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = "ImportTxtFile.exe" fullword ascii /* score: '25.00'*/
      $s2 = "ImportTxtFile.EXE" fullword wide /* score: '25.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "FieldDefs.txt" fullword ascii /* score: '14.00'*/
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s6 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s7 = "ImportTxtFile Version 1.0" fullword wide /* score: '10.00'*/
      $s8 = ".?AVCFECFileDialog@@" fullword ascii /* score: '9.00'*/
      $s9 = "CFECFileDialog" fullword ascii /* score: '9.00'*/
      $s10 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s11 = ".?AVCFileContents@@" fullword ascii /* score: '9.00'*/
      $s12 = "Define each field by clicking on column header." fullword wide /* score: '9.00'*/
      $s13 = "Import Text File" fullword wide /* score: '7.00'*/
      $s14 = "CPropSheetImportTxtFile" fullword ascii /* score: '7.00'*/
      $s15 = ".?AVCPageImportTxtFile@@" fullword ascii /* score: '7.00'*/
      $s16 = ".?AVCPropSheetImportTxtFile@@" fullword ascii /* score: '7.00'*/
      $s17 = ".?AVCImportTxtFileApp@@" fullword ascii /* score: '7.00'*/
      $s18 = "CPageImportTxtFile" fullword ascii /* score: '7.00'*/
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s20 = "You need to set up the FieldDefs.txt file in the application subdirectory" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0 {
   meta:
      description = "mw - file 24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
   strings:
      $x1 = "C:\\Users\\orawat\\code\\vs\\ssi_msf\\Release\\ssi_msf.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e303b2057696e646f7773204e5420362e323b20" ascii /* score: '24.00'*/ /* hex encoded string 'User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; Touch; MASPJS)' */
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "2f5a25930a406bd092cf1264e8a73f1ec96f0a9dbb7fbd3e97c44e45633185529035bd6ab39e479a1be6478d7f20af65feaea6a6e917b4bf9d4684c5faaf8cc1" ascii /* score: '11.00'*/
      $s6 = "15000053506857899fc6ffd5eb705b31d252680002408452525253525068eb552e3bffd589c683c35031ff57576aff5356682d06187bffd585c00f84c3010000" ascii /* score: '11.00'*/
      $s7 = "31ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff576a0751565068b757e00bffd5bf002f000039c774b731ffe991010000e9c9010000e88b" ascii /* score: '11.00'*/
      $s8 = "2f5a25930a406bd092cf1264e8a73f1ec96f0a9dbb7fbd3e97c44e45633185529035bd6ab39e479a1be6478d7f20af65feaea6a6e917b4bf9d4684c5faaf8cc1" ascii /* score: '11.00'*/
      $s9 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s10 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s11 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s12 = "303b2057696e646f7773204e5420362e323b20574f5736343b2054726964656e742f362e303b20546f7563683b204d4153504a53290d0a006e6e4e1d5ee0edcc" ascii /* score: '8.00'*/
      $s13 = "3c829cbb74617bb1e144668f7e8baa8e6ce900557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e" ascii /* score: '8.00'*/
      $s14 = "54140068f0b5a256ffd56a4068001000006800004000576858a453e5ffd593b90000000001d9515389e7576800200000535668129689e2ffd585c074c68b0701" ascii /* score: '8.00'*/
      $s15 = "5b5b61595a51ffe0585f5a8b12eb865d686e6574006877696e6954684c772607ffd531ff5757575757683a5679a7ffd5e9840000005b31c951516a0351516843" ascii /* score: '8.00'*/
      $s16 = "557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e303b2057696e646f7773204e5420362e323b20" ascii /* score: '8.00'*/
      $s17 = "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01" ascii /* score: '8.00'*/
      $s18 = "f6e6661724a25c5f550c08dc88f27c3ead794822eb397b9f9f745b47de8c72385cc895707f703af3ec0dcf85847f799c46b95091bf09d5b71c729ea49f7dac5e" ascii /* score: '8.00'*/
      $s19 = "d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d089442424" ascii /* score: '8.00'*/
      $s20 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7 {
   meta:
      description = "mw - file 62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7"
   strings:
      $s1 = "beacon.x64.dll" fullword ascii /* score: '20.00'*/
      $s2 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s3 = "system32H" fullword ascii /* score: '12.00'*/
      $s4 = "abcdefghijklmnop" fullword ascii /* score: '8.00'*/
      $s5 = "abcdbcdecdefdef" ascii /* score: '8.00'*/
      $s6 = "asysnative" fullword ascii /* score: '8.00'*/
      $s7 = "BBBBBBBBH" fullword ascii /* score: '6.50'*/
      $s8 = "%s as %s\\%s: %d" fullword ascii /* score: '6.50'*/
      $s9 = "8;8(t+ _" fullword ascii /* score: '5.00'*/
      $s10 = "rijndael" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 6 times */
      $s11 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 21 times */
      $s12 = "Microsoft Base Cryptographic Provider v1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 148 times */
      $s13 = "sha256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s14 = "process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 171 times */
      $s15 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s16 = "888>888>{WWSQ]888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" ascii /* score: '4.00'*/
      $s17 = "C\\f9DL@t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "RQYKPMT]" fullword ascii /* score: '4.00'*/
      $s19 = "yHHT]o]ZsQL" fullword ascii /* score: '4.00'*/
      $s20 = "888>888>{WWSQ]888?8889888;888<88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a {
   meta:
      description = "mw - file 66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a"
   strings:
      $x1 = "D:\\githubCoder\\MemoryModule\\MemoryModule-master\\example\\DllLoader\\Release\\DllLoader.pdb" fullword ascii /* score: '33.00'*/
      $x2 = "http://ni.anhuiry.com/json/Reflective.dll" fullword ascii /* score: '31.00'*/
      $s3 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s4 = "..\\SampleDLL\\SampleDLL.dll" fullword ascii /* score: '15.00'*/
      $s5 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s6 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s7 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s8 = ".?AVCKernel32@@" fullword ascii /* score: '9.00'*/
      $s9 = ".?AV?$CStc@VCKernel32@@@NSstc@@" fullword ascii /* score: '9.00'*/
      $s10 = ".?AVCShell32@@" fullword ascii /* score: '9.00'*/
      $s11 = ".?AV?$CStc@VCShell32@@@NSstc@@" fullword ascii /* score: '9.00'*/
      $s12 = "Can't open DLL file \"%s\"." fullword ascii /* score: '8.00'*/
      $s13 = "Test custom free function after MemoryLoadLibraryEx" fullword ascii /* score: '8.00'*/
      $s14 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s15 = ".?AVCUser32@@" fullword ascii /* score: '7.00'*/
      $s16 = ".?AVCComctl32@@" fullword ascii /* score: '7.00'*/
      $s17 = ".?AV?$CStc@VCUser32@@@NSstc@@" fullword ascii /* score: '7.00'*/
      $s18 = ".?AVCWinhttp@@" fullword ascii /* score: '7.00'*/
      $s19 = "Test MemoryLoadLibraryEx after initially failing allocation function" fullword ascii /* score: '7.00'*/
      $s20 = "Test cleanup after MemoryLoadLibraryEx with failing allocation function" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_748ec8ae548055ea31dc07d6f854513bd6f6bcbb810087f5c32214ba98405967 {
   meta:
      description = "mw - file 748ec8ae548055ea31dc07d6f854513bd6f6bcbb810087f5c32214ba98405967"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "748ec8ae548055ea31dc07d6f854513bd6f6bcbb810087f5c32214ba98405967"
   strings:
      $s1 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s2 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s3 = "?$?3?f?{?" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s5 = ":#:+:0:6:>:C:I:Q:V:\\:d:i:o:w:|:" fullword ascii /* score: '7.00'*/
      $s6 = ":#:4:::F:V:\\:k:r:" fullword ascii /* score: '7.00'*/
      $s7 = "TGPQKML" fullword ascii /* score: '6.50'*/
      $s8 = "FWWWUWW" fullword ascii /* score: '6.50'*/
      $s9 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s10 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s11 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s12 = " Microsoft Code Verification Root0" fullword ascii /* score: '5.00'*/
      $s13 = "- %:::" fullword ascii /* score: '5.00'*/
      $s14 = "42+''##" fullword ascii /* score: '5.00'*/ /* hex encoded string 'B' */
      $s15 = "$9I$+ " fullword ascii /* score: '5.00'*/
      $s16 = "fvwrru" fullword ascii /* score: '5.00'*/
      $s17 = "uvvbll" fullword ascii /* score: '5.00'*/
      $s18 = " delete[]" fullword ascii /* score: '4.00'*/
      $s19 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s20 = "_T.aVmd8k*;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5dadf1f {
   meta:
      description = "mw - file d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5dadf1f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5dadf1f"
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii /* score: '45.00'*/
      $x2 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\80c2da985e321caadd256a0fc3fbab3a905331ed2b3c8fa039d3f769c1af1176.exe" fullword ascii /* score: '43.00'*/
      $s3 = "%d is an x64 process (can't inject x86 content)" fullword ascii /* score: '25.00'*/
      $s4 = "%d is an x86 process (can't inject x64 content)" fullword ascii /* score: '25.00'*/
      $s5 = "beacon.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Could not open process token: %d (%u)" fullword ascii /* score: '21.00'*/
      $s7 = "could not open process %d: %d" fullword ascii /* score: '20.50'*/
      $s8 = "beacon.x64.dll" fullword ascii /* score: '20.00'*/
      $s9 = "Failed to impersonate logged on user %d (%u)" fullword ascii /* score: '20.00'*/
      $s10 = "Could not open process: %d (%u)" fullword ascii /* score: '18.00'*/
      $s11 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii /* score: '18.00'*/
      $s12 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" fullword ascii /* score: '18.00'*/
      $s13 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii /* score: '17.00'*/
      $s14 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." fullword ascii /* score: '16.00'*/
      $s15 = "could not spawn %s (token): %d" fullword ascii /* score: '16.00'*/
      $s16 = "could not create remote thread in %d: %d" fullword ascii /* score: '15.50'*/
      $s17 = "could not spawn %s: %d" fullword ascii /* score: '15.50'*/
      $s18 = "Failed to impersonate token from %d (%u)" fullword ascii /* score: '15.00'*/
      $s19 = "Command length (%d) too long" fullword ascii /* score: '15.00'*/
      $s20 = "could not adjust permissions in process: %d" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a {
   meta:
      description = "mw - file 18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
   strings:
      $s1 = "    qHide.Exec(qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\")" fullword ascii /* score: '30.00'*/
      $s2 = "8/fonts/file12.bin\",\"http://insiderushings.com:8088/plugins/file4.bin\",\"http://webservicesamazin.com:8088/js/file10.bin\",\"" ascii /* score: '20.00'*/
      $s3 = "onlinefastsolutions.com:8088/images/file1.bin\",\"http://paymentadvisry.com:8088/css/file2.bin\",\"http://jeromfastsolutions.com" ascii /* score: '20.00'*/
      $s4 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii /* score: '20.00'*/
      $s5 = "        .savetofile qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\", 2 " fullword ascii /* score: '18.00'*/
      $s6 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii /* score: '17.00'*/
      $s7 = "nts/file13.bin\",\"http://jeromfastsolutions.com:8088/styles/file12.bin\",\"http://paymentadvisry.com:8088/fonts/file1.bin\",\"h" ascii /* score: '17.00'*/
      $s8 = "    qDialogWorkbookProtect.setRequestHeader \"User-Agent\", \"qIntlAddIn\"" fullword ascii /* score: '17.00'*/
      $s9 = "/jeromfastsolutions.com:8088/bundle/file8.bin\")" fullword ascii /* score: '14.00'*/
      $s10 = "    qDialogWorkbookProtect.Open \"GET\", qPivotTableVersion10, False" fullword ascii /* score: '12.00'*/
      $s11 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >" fullword ascii /* score: '10.00'*/
      $s12 = "    Set qHide = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '7.00'*/
      $s13 = "riving to win his own life and the return of his company. Nay, but even so he saved not his company, though he desired it sore. " ascii /* score: '7.00'*/
      $s14 = "    Set qDialogWorkbookProtect = createobject(\"MSXML2.ServerXMLHTTP.6.0\")" fullword ascii /* score: '7.00'*/
      $s15 = "    'Tell me, Muse, of that man, so ready at need, who wandered far and wide, after he had sacked the sacred citadel of Troy, an" ascii /* score: '5.00'*/
      $s16 = "rom them their day of returning. Of these things, goddess, daughter of Zeus, whencesoever thou hast heard thereof, declare thou " ascii /* score: '4.00'*/
      $s17 = "SHOWINTASKBAR=\"no\">" fullword ascii /* score: '4.00'*/
      $s18 = "For through the blindness of their own hearts they perished, fools, who devoured the oxen of Helios Hyperion: but the god took f" ascii /* score: '4.00'*/
      $s19 = "    qDialogWorkbookProtect.Send" fullword ascii /* score: '4.00'*/
      $s20 = "MINIMIZEBUTTON=\"no\"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule sig_1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89 {
   meta:
      description = "mw - file 1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s2 = "C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '29.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s4 = "ies.com/wp-content/themes/adamje@" fullword ascii /* score: '22.00'*/
      $s5 = "#4.2#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applications" fullword wide /* score: '21.00'*/
      $s6 = "https://ahd|d5%lYm|d5%lYspor|d5%lYt.com/boots|P." fullword ascii /* score: '17.00'*/
      $s7 = " (664 - @649#))" fullword ascii /* score: '17.00'*/ /* hex encoded string 'fFI' */
      $s8 = "#1.9#0#C:\\Program Files (x86)\\Microsoft Office\\Office16\\EXCEL.EXE#Microsoft Excel 16.0 Object Library" fullword wide /* score: '17.00'*/
      $s9 = "VVVAAAAAAA" fullword wide /* base64 encoded string 'UU@    ' */ /* score: '16.50'*/
      $s10 = "EL.EXE" fullword ascii /* score: '16.00'*/
      $s11 = "contemptibleneskh" fullword ascii /* score: '15.00'*/
      $s12 = "logo_ias_agent_pages" fullword wide /* score: '14.00'*/
      $s13 = "VVVVVL" fullword wide /* reversed goodware string 'LVVVVV' */ /* score: '13.50'*/
      $s14 = "ircumste" fullword ascii /* score: '13.00'*/
      $s15 = "C:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii /* score: '13.00'*/
      $s16 = "baguetphilologi" fullword ascii /* score: '13.00'*/
      $s17 = "ednugget" fullword ascii /* score: '13.00'*/
      $s18 = "imposthumationha" fullword ascii /* score: '13.00'*/
      $s19 = "imposthu" fullword ascii /* score: '13.00'*/
      $s20 = "ntocrat" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7_d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5_0 {
   meta:
      description = "mw - from files 62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7, d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5dadf1f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "62b5bfb4c03f175ba2b202de208a716db904be695633d770aa696f38f610a2b7"
      hash2 = "d1ade8821b0a79bd5c7233851c99874ac1ac1c10c5f7a9c29f431dfcf5dadf1f"
   strings:
      $s1 = "beacon.x64.dll" fullword ascii /* score: '20.00'*/
      $s2 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s3 = "system32H" fullword ascii /* score: '12.00'*/
      $s4 = "abcdefghijklmnop" fullword ascii /* score: '8.00'*/
      $s5 = "abcdbcdecdefdef" ascii /* score: '8.00'*/
      $s6 = "BBBBBBBBH" fullword ascii /* score: '6.50'*/
      $s7 = "%s as %s\\%s: %d" fullword ascii /* score: '6.50'*/
      $s8 = "rijndael" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 6 times */
      $s9 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 21 times */
      $s10 = "Microsoft Base Cryptographic Provider v1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 148 times */
      $s11 = "sha256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s12 = "process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 171 times */
      $s13 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s14 = "C\\f9DL@t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "fD9k8u" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "uQHc}0I" fullword ascii /* score: '4.00'*/
      $s17 = "123456789abcdefg" fullword ascii /* score: '4.00'*/
      $s18 = "t]+uoA;6rUA" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "!t$(H!t$ M" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "he appropriate bitmask.  For example:  " fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0_66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e6_1 {
   meta:
      description = "mw - from files 24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0, 66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
      hash2 = "66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a"
   strings:
      $s1 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s2 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s3 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s4 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "api-ms-" fullword wide /* score: '1.00'*/
      $s6 = "ext-ms-" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50_24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca_2 {
   meta:
      description = "mw - from files 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50, 24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0, 66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a, 748ec8ae548055ea31dc07d6f854513bd6f6bcbb810087f5c32214ba98405967"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      hash2 = "24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
      hash3 = "66cc4886c99469c92043bcc7dca6c8ef66f3597f8478da8391fe38d3e64ac84a"
      hash4 = "748ec8ae548055ea31dc07d6f854513bd6f6bcbb810087f5c32214ba98405967"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s3 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s4 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s5 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s6 = " delete[]" fullword ascii /* score: '4.00'*/
      $s7 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s8 = " delete" fullword ascii /* score: '3.00'*/
      $s9 = "      </requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s10 = "      <requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s11 = " new[]" fullword ascii /* score: '1.00'*/
      $s12 = " Base Class Array'" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

