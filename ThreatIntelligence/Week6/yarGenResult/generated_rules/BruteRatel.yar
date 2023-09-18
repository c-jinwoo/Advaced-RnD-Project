/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6 {
   meta:
      description = "mw - file 18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s6 = "gpF.ARH" fullword ascii /* score: '7.00'*/
      $s7 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s8 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s9 = "a4Z.AQH" fullword ascii /* score: '7.00'*/
      $s10 = "9EddS.tATI" fullword ascii /* score: '7.00'*/
      $s11 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s12 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s13 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s14 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s15 = "\\a:hjtSsASI" fullword ascii /* score: '5.00'*/
      $s16 = "# {[AUI" fullword ascii /* score: '5.00'*/
      $s17 = "Z- AVI" fullword ascii /* score: '5.00'*/
      $s18 = "&iAMRATI" fullword ascii /* score: '4.00'*/
      $s19 = "coVLAPH" fullword ascii /* score: '4.00'*/
      $s20 = "nLmU+x8LASI" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a {
   meta:
      description = "mw - file 9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s6 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s7 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s8 = "POJ.APH" fullword ascii /* score: '7.00'*/
      $s9 = "Vn2b.API" fullword ascii /* score: '7.00'*/
      $s10 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s11 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s12 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s13 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s14 = ",+ ^API" fullword ascii /* score: '5.00'*/
      $s15 = "%_%TAQI" fullword ascii /* score: '5.00'*/
      $s16 = "\\y0iZDJAVI" fullword ascii /* score: '5.00'*/
      $s17 = "G* 1AVH" fullword ascii /* score: '5.00'*/
      $s18 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s19 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s20 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00 {
   meta:
      description = "mw - file a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s6 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s7 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s8 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s9 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s10 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s11 = "TIHASH" fullword ascii /* score: '6.50'*/
      $s12 = "KHQNATI" fullword ascii /* score: '6.50'*/
      $s13 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s14 = "X%n%WI" fullword ascii /* score: '5.00'*/
      $s15 = "o1 /m5PI" fullword ascii /* score: '5.00'*/
      $s16 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s17 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s18 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
      $s19 = "(A_A^A]A\\A[AZAYAX_^ZY[X]" fullword ascii /* score: '4.00'*/
      $s20 = "iBlzxZWNAUI" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9 {
   meta:
      description = "mw - file abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "RgetARH" fullword ascii /* score: '9.00'*/
      $s6 = "bfTpARH" fullword ascii /* score: '9.00'*/
      $s7 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s8 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s9 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s10 = "G7l.AQI" fullword ascii /* score: '7.00'*/
      $s11 = "bINlATI" fullword ascii /* score: '7.00'*/
      $s12 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s13 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s14 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s15 = "GJZEKCSI" fullword ascii /* score: '6.50'*/
      $s16 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s17 = "&5|* `JJAQH" fullword ascii /* score: '5.00'*/
      $s18 = "- (yARH" fullword ascii /* score: '5.00'*/
      $s19 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s20 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad {
   meta:
      description = "mw - file b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "FTPAVH" fullword ascii /* score: '8.50'*/
      $s6 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s7 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s8 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s9 = "bc8.AUH" fullword ascii /* score: '7.00'*/
      $s10 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s11 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s12 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s13 = "ZOPZYASI" fullword ascii /* score: '6.50'*/
      $s14 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s15 = "# QAUI" fullword ascii /* score: '5.00'*/
      $s16 = "\\AoxH3ASH" fullword ascii /* score: '5.00'*/
      $s17 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s18 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s19 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
      $s20 = "(A_A^A]A\\A[AZAYAX_^ZY[X]" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd {
   meta:
      description = "mw - file c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s6 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s7 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s8 = "POJ.APH" fullword ascii /* score: '7.00'*/
      $s9 = "Vn2b.API" fullword ascii /* score: '7.00'*/
      $s10 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s11 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s12 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s13 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s14 = ",+ ^API" fullword ascii /* score: '5.00'*/
      $s15 = "%_%TAQI" fullword ascii /* score: '5.00'*/
      $s16 = "\\y0iZDJAVI" fullword ascii /* score: '5.00'*/
      $s17 = "G* 1AVH" fullword ascii /* score: '5.00'*/
      $s18 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s19 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s20 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc {
   meta:
      description = "mw - file f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "FTPAVH" fullword ascii /* score: '8.50'*/
      $s6 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s7 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s8 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s9 = "bc8.AUH" fullword ascii /* score: '7.00'*/
      $s10 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s11 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s12 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s13 = "ZOPZYASI" fullword ascii /* score: '6.50'*/
      $s14 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s15 = "# QAUI" fullword ascii /* score: '5.00'*/
      $s16 = "\\AoxH3ASH" fullword ascii /* score: '5.00'*/
      $s17 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s18 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s19 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
      $s20 = "(A_A^A]A\\A[AZAYAX_^ZY[X]" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule f5c532e86bd70c29ba104560e94922436bfd8d25117ddc665f6b6f33a83e56c0 {
   meta:
      description = "mw - file f5c532e86bd70c29ba104560e94922436bfd8d25117ddc665f6b6f33a83e56c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "f5c532e86bd70c29ba104560e94922436bfd8d25117ddc665f6b6f33a83e56c0"
   strings:
      $s1 = "C:\\Users\\User\\source\\repos\\ConsoleApplication2\\x64\\Debug\\ConsoleApplication2.pdb" fullword ascii /* score: '29.00'*/
      $s2 = "VCRUNTIME140_1D.dll" fullword ascii /* score: '23.00'*/
      $s3 = "C:\\Users\\User\\source\\repos\\ConsoleApplication2\\x64\\Debug\\Generated Files\\winrt\\base.h" fullword wide /* score: '22.00'*/
      $s4 = "SHELLCODE_BIN" fullword wide /* score: '21.00'*/
      $s5 = "WINRT_IMPL_HeapFree(WINRT_IMPL_GetProcessHeap(), 0, value)" fullword wide /* score: '20.00'*/
      $s6 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s7 = "0 == WINRT_IMPL_SetErrorInfo(0, info.get())" fullword wide /* score: '15.00'*/
      $s8 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\xmemory" fullword wide /* score: '13.00'*/
      $s9 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\atomic" fullword wide /* score: '13.00'*/
      $s10 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\xstring" fullword wide /* score: '13.00'*/
      $s11 = "0 == m_info->GetReference(m_debug_reference.put())" fullword wide /* score: '12.00'*/
      $s12 = "0 == WINRT_IMPL_GetErrorInfo(0, info.put_void())" fullword wide /* score: '12.00'*/
      $s13 = "Hello, %ls!" fullword ascii /* score: '9.00'*/
      $s14 = "(hs -.AUH" fullword ascii /* score: '8.00'*/
      $s15 = "xD:\"AVH" fullword ascii /* score: '7.00'*/
      $s16 = ".?AUhresult_wrong_thread@winrt@@" fullword ascii /* score: '7.00'*/
      $s17 = ".?AUIRestrictedErrorInfo@impl@winrt@@" fullword ascii /* score: '7.00'*/
      $s18 = ".?AUhresult_error@winrt@@" fullword ascii /* score: '7.00'*/
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s20 = ".?AUerror_info_fallback@impl@winrt@@" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069 {
   meta:
      description = "mw - file 31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069"
   strings:
      $s1 = "\\KnownDlls\\ntdll.dll" fullword wide /* score: '21.00'*/
      $s2 = "D:\\Source_Code\\rookit\\heresy\\heresy\\x64\\Release\\heresy.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "APAPAPAP" fullword ascii /* reversed goodware string 'PAPAPAPA' */ /* score: '16.50'*/
      $s4 = "eProcessPH" fullword ascii /* score: '15.00'*/
      $s5 = "ProcessIPH" fullword ascii /* score: '15.00'*/
      $s6 = "AppDataHPH" fullword ascii /* score: '11.00'*/
      $s7 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s8 = "C:\\UsPH" fullword ascii /* score: '10.00'*/
      $s9 = ".dllPH" fullword ascii /* score: '10.00'*/
      $s10 = "LISTENINP" fullword ascii /* score: '9.50'*/
      $s11 = "GetLasPH" fullword ascii /* score: '9.00'*/
      $s12 = "KERNEL32PH" fullword ascii /* score: '9.00'*/
      $s13 = "GetModPH" fullword ascii /* score: '9.00'*/
      $s14 = "GetCurPH" fullword ascii /* score: '9.00'*/
      $s15 = "calhost" fullword ascii /* score: '9.00'*/
      $s16 = "GetSysPH" fullword ascii /* score: '9.00'*/
      $s17 = "GetProcePH" fullword ascii /* score: '9.00'*/
      $s18 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s19 = "e failurPH" fullword ascii /* score: '7.00'*/
      $s20 = "Address P" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f {
   meta:
      description = "mw - file d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
   strings:
      $s1 = "EL32.dllPH" fullword ascii /* score: '13.00'*/
      $s2 = "\\AppDataPH" fullword ascii /* score: '12.00'*/
      $s3 = "PasswordPH" fullword ascii /* score: '12.00'*/
      $s4 = ".com.cn|PH" fullword ascii /* score: '11.00'*/
      $s5 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s6 = "C:\\UPH" fullword ascii /* score: '10.00'*/
      $s7 = "YYYYYPA" fullword ascii /* score: '9.50'*/
      $s8 = "GetCurrePH" fullword ascii /* score: '9.00'*/
      $s9 = "GetProPH" fullword ascii /* score: '9.00'*/
      $s10 = "sGetValuPH" fullword ascii /* score: '9.00'*/
      $s11 = "GetMPH" fullword ascii /* score: '9.00'*/
      $s12 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s13 = "e failurPH" fullword ascii /* score: '7.00'*/
      $s14 = "Address P" fullword ascii /* score: '7.00'*/
      $s15 = " failed PH" fullword ascii /* score: '7.00'*/
      $s16 = "4 runtimPH" fullword ascii /* score: '7.00'*/
      $s17 = "sion %d.PH" fullword ascii /* score: '7.00'*/
      $s18 = "size %d.PH" fullword ascii /* score: '7.00'*/
      $s19 = "ThreadIdPH" fullword ascii /* score: '7.00'*/
      $s20 = "astErrorPH" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a_c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5_0 {
   meta:
      description = "mw - from files 9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a, c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a"
      hash2 = "c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
   strings:
      $s1 = "POJ.APH" fullword ascii /* score: '7.00'*/
      $s2 = "Vn2b.API" fullword ascii /* score: '7.00'*/
      $s3 = ",+ ^API" fullword ascii /* score: '5.00'*/
      $s4 = "%_%TAQI" fullword ascii /* score: '5.00'*/
      $s5 = "\\y0iZDJAVI" fullword ascii /* score: '5.00'*/
      $s6 = "G* 1AVH" fullword ascii /* score: '5.00'*/
      $s7 = "QfOhzfErVI" fullword ascii /* score: '4.00'*/
      $s8 = "r4.AUH" fullword ascii /* score: '4.00'*/
      $s9 = "layRAVI" fullword ascii /* score: '4.00'*/
      $s10 = "akHwkAUH" fullword ascii /* score: '4.00'*/
      $s11 = "johASH" fullword ascii /* score: '4.00'*/
      $s12 = "NPJOlFIhATH" fullword ascii /* score: '4.00'*/
      $s13 = "CmE&.ATI" fullword ascii /* score: '4.00'*/
      $s14 = "PxWcwbhnWI" fullword ascii /* score: '4.00'*/
      $s15 = "xMMI3F/SASI" fullword ascii /* score: '4.00'*/
      $s16 = "\"Vw8.APH" fullword ascii /* score: '4.00'*/
      $s17 = "gPXFC/65ARH" fullword ascii /* score: '4.00'*/
      $s18 = "VQUQui9BVI" fullword ascii /* score: '4.00'*/
      $s19 = "sQzePu+3VI" fullword ascii /* score: '4.00'*/
      $s20 = "Mm.APH" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad_f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710_1 {
   meta:
      description = "mw - from files b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad, f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad"
      hash2 = "f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
   strings:
      $s1 = "FTPAVH" fullword ascii /* score: '8.50'*/
      $s2 = "bc8.AUH" fullword ascii /* score: '7.00'*/
      $s3 = "ZOPZYASI" fullword ascii /* score: '6.50'*/
      $s4 = "# QAUI" fullword ascii /* score: '5.00'*/
      $s5 = "\\AoxH3ASH" fullword ascii /* score: '5.00'*/
      $s6 = "YXIj>PI" fullword ascii /* score: '4.00'*/
      $s7 = "QPQO[SAUI" fullword ascii /* score: '4.00'*/
      $s8 = "NfTwATI" fullword ascii /* score: '4.00'*/
      $s9 = "MXcC9n0fVI" fullword ascii /* score: '4.00'*/
      $s10 = "ibnJ^1}" fullword ascii /* score: '4.00'*/
      $s11 = "jb4vPTe+AQI" fullword ascii /* score: '4.00'*/
      $s12 = "Tb.ATI" fullword ascii /* score: '4.00'*/
      $s13 = "5VAUjQa7AQH" fullword ascii /* score: '4.00'*/
      $s14 = "LjvPNsU4ARH" fullword ascii /* score: '4.00'*/
      $s15 = "+Wb4OckQAUH" fullword ascii /* score: '4.00'*/
      $s16 = "^C.VVH" fullword ascii /* score: '4.00'*/
      $s17 = "/L.ASI" fullword ascii /* score: '4.00'*/
      $s18 = "1xPVO`API" fullword ascii /* score: '4.00'*/
      $s19 = "szSsASI" fullword ascii /* score: '4.00'*/
      $s20 = "AvQZTATI" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069_d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9e_2 {
   meta:
      description = "mw - from files 31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069, d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069"
      hash2 = "d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
   strings:
      $s1 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s2 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s3 = "e failurPH" fullword ascii /* score: '7.00'*/
      $s4 = "Address P" fullword ascii /* score: '7.00'*/
      $s5 = " failed PH" fullword ascii /* score: '7.00'*/
      $s6 = "4 runtimPH" fullword ascii /* score: '7.00'*/
      $s7 = "sion %d.PH" fullword ascii /* score: '7.00'*/
      $s8 = "size %d.PH" fullword ascii /* score: '7.00'*/
      $s9 = "AVAUATUWPH" fullword ascii /* score: '6.50'*/
      $s10 = "AVAUATVSPH" fullword ascii /* score: '6.50'*/
      $s11 = "AUATWVSHPH" fullword ascii /* score: '6.50'*/
      $s12 = "AUATUWVSPH" fullword ascii /* score: '6.50'*/
      $s13 = "ACEGIKMOPH" fullword ascii /* score: '6.50'*/
      $s14 = "AVAUATWSPH" fullword ascii /* score: '6.50'*/
      $s15 = "AWAVAUATPH" fullword ascii /* score: '6.50'*/
      $s16 = "UAWAVAUAPH" fullword ascii /* score: '6.50'*/
      $s17 = "DAFGPMJKPH" fullword ascii /* score: '6.50'*/
      $s18 = "VAUATUWVPH" fullword ascii /* score: '6.50'*/
      $s19 = "UATUWVS" fullword ascii /* score: '6.50'*/
      $s20 = "ILONEHCBPH" fullword ascii /* score: '6.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6_9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faa_3 {
   meta:
      description = "mw - from files 18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6, 9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a, a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00, abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9, b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad, c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd, f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6"
      hash2 = "9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a"
      hash3 = "a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00"
      hash4 = "abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9"
      hash5 = "b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad"
      hash6 = "c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
      hash7 = "f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
   strings:
      $s1 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '14.00'*/
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s4 = "Manages universal application core process that in Windows 8 and continues in Windows 10. It is used to determine whether univer" ascii /* score: '11.00'*/
      $s5 = "tion or microphone. It helps to transact records of your universal apps with the trust and privacy settings of user." fullword ascii /* score: '7.00'*/
      $s6 = "  VirtualProtect failed with code 0x%x" fullword ascii /* score: '7.00'*/
      $s7 = "TransactionBrokerService" fullword ascii /* score: '7.00'*/
      $s8 = "AWAVAUM" fullword ascii /* score: '6.50'*/
      $s9 = "  Unknown pseudo relocation protocol version %d." fullword ascii /* score: '6.00'*/
      $s10 = ":MZuWHcB<H" fullword ascii /* score: '4.00'*/
      $s11 = "  Unknown pseudo relocation bit size %d." fullword ascii /* score: '3.00'*/
      $s12 = "T$XtXM" fullword ascii /* score: '1.00'*/
      $s13 = "([^_A\\H" fullword ascii /* score: '1.00'*/
      $s14 = "@.xdata" fullword ascii /* score: '1.00'*/
      $s15 = "McT$<L" fullword ascii /* score: '1.00'*/
      $s16 = "D$HHcB<H" fullword ascii /* score: '1.00'*/
      $s17 = "sal apps installed from the Windows Store are declaring all of their permissions, like being able to access your telemetry, loca" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6_9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faa_4 {
   meta:
      description = "mw - from files 18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6, 9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a, a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00, abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9, b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad, c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd, f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc, f5c532e86bd70c29ba104560e94922436bfd8d25117ddc665f6b6f33a83e56c0"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "18d3d9bd3a92bf35cac43614cfa3d608a04da93bd9a637df82a0a9b1f9974eb6"
      hash2 = "9fc93b006ee1e91bced1623685bac84e0b42fbcf5e88838b3552854faad27c3a"
      hash3 = "a70e41160d446250a6871201bf8f17c24dd8cabe65f0be0e9cb2e2f7581cdf00"
      hash4 = "abb15dea7104e333ae75bac065c953d671c61471734bdd91fcc08e013a5fb5d9"
      hash5 = "b3f1d3cd1b5dd4fa175d94182e5ab3e9ab7d1229f7c9c3e2409c57c2c03b0aad"
      hash6 = "c264e14b1a3551f6ec3f8b6c8048a22b4c2ba08c7284a946c8a79416f5aab8fd"
      hash7 = "f1d8ce601f8de791d43214792469d0c5f2b505993f1fc376208693d710ab89fc"
      hash8 = "f5c532e86bd70c29ba104560e94922436bfd8d25117ddc665f6b6f33a83e56c0"
   strings:
      $s1 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s2 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s3 = "A_AYAXZYPAQAWH" fullword ascii /* score: '4.00'*/
      $s4 = "A_UPSQRVWAPAQARASATAUAVAWH" fullword ascii /* score: '4.00'*/
      $s5 = "(A_A^A]A\\A[AZAYAX_^ZY[X]" fullword ascii /* score: '4.00'*/
      $s6 = "AWPPPP" fullword ascii /* score: '3.50'*/
      $s7 = "PMch<H" fullword ascii /* score: '1.00'*/
      $s8 = "A_AYAXI" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

