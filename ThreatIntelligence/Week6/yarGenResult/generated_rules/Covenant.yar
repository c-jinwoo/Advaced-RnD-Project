/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a {
   meta:
      description = "mw - file 2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
   strings:
      $x1 = "end of fileno other error listedunknown errorlink loopinvalid filenamenot a directorydirectory not emptylock conflictunknown pri" ascii /* score: '45.00'*/
      $x2 = "DW_FORM_implicit_const used in an invalid context.Expected an attribute value to be a string form.Missing DW_LNCT_path in file e" ascii /* score: '43.00'*/
      $x3 = "SHA512SHA384SHA256SHA224SHA1MD5NONEED448ED25519ECDSADSARSAAnonymousECDSAFixedECDHRSAFixedECDHECDSASignFortezzaDMSDSSEphemeralDHR" ascii /* score: '42.00'*/
      $x4 = "ne_flagsne_autodatane_heapne_stackne_csipne_ssspne_csegne_cmodne_cbnrestabne_segtabne_rsrctabne_restabne_modtabne_imptabne_nrest" ascii /* score: '40.00'*/
      $x5 = "DW_AT_APPLE_propertyDW_AT_APPLE_objc_complete_typeDW_AT_APPLE_property_attributeDW_AT_APPLE_property_setterDW_AT_APPLE_property_" ascii /* score: '39.00'*/
      $x6 = "ImageAuxSymbolTokenDefaux_typereserved1symbol_table_indexreserved2ImageAuxSymbolFunctiontag_indextotal_sizepointer_to_linenumber" ascii /* score: '38.00'*/
      $x7 = "User-AgentFailed to make post requestWQL/root/.cargo/registry/src/github.com-1ecc6299db9ec823/wmi-0.9.3/src/query.rsGot enumerat" ascii /* score: '34.00'*/
      $x8 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\abbrev.rs" fullword ascii /* score: '33.00'*/
      $x9 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\twoway.rs" fullword ascii /* score: '33.00'*/
      $x10 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\prefilter\\x86\\sse.rs" fullword ascii /* score: '33.00'*/
      $x11 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\mod.rs" fullword ascii /* score: '33.00'*/
      $x12 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x13 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\lib.rs" fullword ascii /* score: '33.00'*/
      $x14 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x15 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.26.2\\src\\read\\archive.rs" fullword ascii /* score: '33.00'*/
      $x16 = "cmd.exe/cCommand status: " fullword ascii /* score: '33.00'*/
      $x17 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\rarebytes.rs" fullword ascii /* score: '33.00'*/
      $x18 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\function.rs" fullword ascii /* score: '33.00'*/
      $x19 = "disabled backtraceunsupported backtraceInvalid COFF symbol table offset or sizeC:\\Users\\runneradmin\\.cargo\\registry\\src\\gi" ascii /* score: '33.00'*/
      $x20 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\line.rs" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*)
}

rule sig_5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6 {
   meta:
      description = "mw - file 5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
   strings:
      $x1 = "end of fileno other error listedunknown errorlink loopinvalid filenamenot a directorydirectory not emptylock conflictunknown pri" ascii /* score: '45.00'*/
      $x2 = "DW_FORM_implicit_const used in an invalid context.Expected an attribute value to be a string form.Missing DW_LNCT_path in file e" ascii /* score: '43.00'*/
      $x3 = "SHA512SHA384SHA256SHA224SHA1MD5NONEED448ED25519ECDSADSARSAAnonymousECDSAFixedECDHRSAFixedECDHECDSASignFortezzaDMSDSSEphemeralDHR" ascii /* score: '42.00'*/
      $x4 = "ne_flagsne_autodatane_heapne_stackne_csipne_ssspne_csegne_cmodne_cbnrestabne_segtabne_rsrctabne_restabne_modtabne_imptabne_nrest" ascii /* score: '40.00'*/
      $x5 = "DW_AT_APPLE_propertyDW_AT_APPLE_objc_complete_typeDW_AT_APPLE_property_attributeDW_AT_APPLE_property_setterDW_AT_APPLE_property_" ascii /* score: '39.00'*/
      $x6 = "ImageAuxSymbolTokenDefaux_typereserved1symbol_table_indexreserved2ImageAuxSymbolFunctiontag_indextotal_sizepointer_to_linenumber" ascii /* score: '38.00'*/
      $x7 = "User-AgentFailed to make post requestWQL/root/.cargo/registry/src/github.com-1ecc6299db9ec823/wmi-0.9.3/src/query.rsGot enumerat" ascii /* score: '34.00'*/
      $x8 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\abbrev.rs" fullword ascii /* score: '33.00'*/
      $x9 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\twoway.rs" fullword ascii /* score: '33.00'*/
      $x10 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\prefilter\\x86\\sse.rs" fullword ascii /* score: '33.00'*/
      $x11 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\mod.rs" fullword ascii /* score: '33.00'*/
      $x12 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x13 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\lib.rs" fullword ascii /* score: '33.00'*/
      $x14 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x15 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.26.2\\src\\read\\archive.rs" fullword ascii /* score: '33.00'*/
      $x16 = "cmd.exe/cCommand status: " fullword ascii /* score: '33.00'*/
      $x17 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\rarebytes.rs" fullword ascii /* score: '33.00'*/
      $x18 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\function.rs" fullword ascii /* score: '33.00'*/
      $x19 = "disabled backtraceunsupported backtraceInvalid COFF symbol table offset or sizeC:\\Users\\runneradmin\\.cargo\\registry\\src\\gi" ascii /* score: '33.00'*/
      $x20 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\line.rs" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*)
}

rule sig_6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7 {
   meta:
      description = "mw - file 6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
   strings:
      $x1 = "Unknown section type in `.dwp` index.Invalid hash row in `.dwp` index.Invalid slot count in `.dwp` index.Invalid section count i" ascii /* score: '46.00'*/
      $x2 = "end of fileno other error listedunknown errorlink loopinvalid filenamenot a directorydirectory not emptylock conflictunknown pri" ascii /* score: '45.00'*/
      $x3 = "ImageFileHeaderImageDataDirectorymajor_linker_versionminor_linker_versionsize_of_codesize_of_initialized_datasize_of_uninitializ" ascii /* score: '40.00'*/
      $x4 = "DW_AT_APPLE_propertyDW_AT_APPLE_objc_complete_typeDW_AT_APPLE_property_attributeDW_AT_APPLE_property_setterDW_AT_APPLE_property_" ascii /* score: '39.00'*/
      $x5 = "SHA512SHA384SHA256SHA224SHA1MD5NONEED448ED25519ECDSADSARSAAnonymousECDSAFixedECDHRSAFixedECDHECDSASignFortezzaDMSDSSEphemeralDHR" ascii /* score: '37.00'*/
      $x6 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii /* score: '34.00'*/
      $x7 = "cmd.exe/cCommand status: " fullword ascii /* score: '33.00'*/
      $x8 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.26.1\\src\\read\\abbrev.rs" fullword ascii /* score: '33.00'*/
      $x9 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.5.0\\src\\memmem\\mod.rs" fullword ascii /* score: '33.00'*/
      $x10 = "commentcredentialrealmcred_typefield identifierstruct Credentialscredentialsagenthostportexeccatrmdownloadlistuploadmodeupload_p" ascii /* score: '33.00'*/
      $x11 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.26.1\\src\\read\\line.rs" fullword ascii /* score: '33.00'*/
      $x12 = "commentcredentialrealmcred_typefield identifierstruct Credentialscredentialsagenthostportexeccatrmdownloadlistuploadmodeupload_p" ascii /* score: '33.00'*/
      $x13 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.26.1\\src\\read\\value.rs" fullword ascii /* score: '33.00'*/
      $x14 = "rauth bannerunable to get random byteskeyfile auth failedchannel window fullknown hosts errorbad socketbad encrypterror receivin" ascii /* score: '33.00'*/
      $x15 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.29.0\\src\\read\\coff\\symbol.rs" fullword ascii /* score: '33.00'*/
      $x16 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.17.0\\src\\function.rs" fullword ascii /* score: '33.00'*/
      $x17 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.5.0\\src\\memmem\\prefilter\\mod.rs" fullword ascii /* score: '33.00'*/
      $x18 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.5.0\\src\\memmem\\twoway.rs" fullword ascii /* score: '33.00'*/
      $x19 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.29.0\\src\\read\\archive.rs" fullword ascii /* score: '33.00'*/
      $x20 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.17.0\\src\\lib.rs" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*)
}

rule sig_3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8 {
   meta:
      description = "mw - file 3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8"
   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii /* score: '73.50'*/
      $x2 = "fmt: unknown base; can't happenhash/crc32: tables do not matchhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii /* score: '72.50'*/
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Connection already exists within the agentFa" ascii /* score: '68.50'*/
      $x4 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '67.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size bufferfmt: scanning called" ascii /* score: '64.50'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii /* score: '62.00'*/
      $x7 = "ssh: StdinPipe after process startedssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scannin" ascii /* score: '61.50'*/
      $x8 = "forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii /* score: '61.50'*/
      $x9 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/globs20123456789aAbBcCdD" ascii /* score: '57.00'*/
      $x10 = "Go pointer stored into non-Go memoryIA5String contains invalid characterNo successful authenication attemptsTime.UnmarshalBinary" ascii /* score: '54.50'*/
      $x11 = "explicit tag has no childhttp2: Framer %p: read %vhttp2: Request.URI is nilhttp2: invalid header: %vhttp2: unsupported schemeinc" ascii /* score: '49.50'*/
      $x12 = "setenv NAME VALUEbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunemalformed response from server: malfo" ascii /* score: '49.50'*/
      $x13 = " to non-Go memory , locked to thread/dev/input/event%d/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125: day out of rangeCa" ascii /* score: '49.00'*/
      $x14 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '48.50'*/
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '47.50'*/
      $x16 = "floating point errorforcegc: phase errorgetCert can't be nilgo of nil func valuegopark: bad g statusgzip: invalid headerheader l" ascii /* score: '46.00'*/
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '45.50'*/
      $x18 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii /* score: '44.50'*/
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsggo with non-e" ascii /* score: '44.00'*/
      $x20 = "github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/keylog/keystate.(*KeyLogger).read" fullword ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule sig_4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32 {
   meta:
      description = "mw - file 4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32"
   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii /* score: '73.50'*/
      $x2 = "fmt: unknown base; can't happenhash/crc32: tables do not matchhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii /* score: '72.50'*/
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Connection already exists within the agentFa" ascii /* score: '68.50'*/
      $x4 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '67.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size bufferfmt: scanning called" ascii /* score: '64.50'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii /* score: '62.00'*/
      $x7 = "ssh: StdinPipe after process startedssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scannin" ascii /* score: '61.50'*/
      $x8 = "forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii /* score: '61.50'*/
      $x9 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/globs20123456789aAbBcCdD" ascii /* score: '57.00'*/
      $x10 = "Go pointer stored into non-Go memoryIA5String contains invalid characterNo successful authenication attemptsTime.UnmarshalBinary" ascii /* score: '54.50'*/
      $x11 = "explicit tag has no childhttp2: Framer %p: read %vhttp2: Request.URI is nilhttp2: invalid header: %vhttp2: unsupported schemeinc" ascii /* score: '49.50'*/
      $x12 = "setenv NAME VALUEbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunemalformed response from server: malfo" ascii /* score: '49.50'*/
      $x13 = " to non-Go memory , locked to thread/dev/input/event%d/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125: day out of rangeCa" ascii /* score: '49.00'*/
      $x14 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '48.50'*/
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '47.50'*/
      $x16 = "floating point errorforcegc: phase errorgetCert can't be nilgo of nil func valuegopark: bad g statusgzip: invalid headerheader l" ascii /* score: '46.00'*/
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '45.50'*/
      $x18 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii /* score: '44.50'*/
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsggo with non-e" ascii /* score: '44.00'*/
      $x20 = "github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/keylog/keystate.(*KeyLogger).read" fullword ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule sig_78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206 {
   meta:
      description = "mw - file 78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206"
   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii /* score: '73.50'*/
      $x2 = "fmt: unknown base; can't happenhash/crc32: tables do not matchhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii /* score: '72.50'*/
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Connection already exists within the agentFa" ascii /* score: '68.50'*/
      $x4 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '67.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size bufferfmt: scanning called" ascii /* score: '64.50'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii /* score: '62.00'*/
      $x7 = "ssh: StdinPipe after process startedssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scannin" ascii /* score: '61.50'*/
      $x8 = "forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii /* score: '61.50'*/
      $x9 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/globs20123456789aAbBcCdD" ascii /* score: '57.00'*/
      $x10 = "Go pointer stored into non-Go memoryIA5String contains invalid characterNo successful authenication attemptsTime.UnmarshalBinary" ascii /* score: '54.50'*/
      $x11 = "explicit tag has no childhttp2: Framer %p: read %vhttp2: Request.URI is nilhttp2: invalid header: %vhttp2: unsupported schemeinc" ascii /* score: '49.50'*/
      $x12 = "setenv NAME VALUEbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunemalformed response from server: malfo" ascii /* score: '49.50'*/
      $x13 = " to non-Go memory , locked to thread/dev/input/event%d/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125: day out of rangeCa" ascii /* score: '49.00'*/
      $x14 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '48.50'*/
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '47.50'*/
      $x16 = "floating point errorforcegc: phase errorgetCert can't be nilgo of nil func valuegopark: bad g statusgzip: invalid headerheader l" ascii /* score: '46.00'*/
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '45.50'*/
      $x18 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii /* score: '44.50'*/
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsggo with non-e" ascii /* score: '44.00'*/
      $x20 = "github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/keylog/keystate.(*KeyLogger).read" fullword ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule sig_8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827 {
   meta:
      description = "mw - file 8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii /* score: '73.50'*/
      $x2 = "fmt: unknown base; can't happenhash/crc32: tables do not matchhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii /* score: '72.50'*/
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Connection already exists within the agentFa" ascii /* score: '68.50'*/
      $x4 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '67.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size bufferfmt: scanning called" ascii /* score: '64.50'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii /* score: '62.00'*/
      $x7 = "ssh: StdinPipe after process startedssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scannin" ascii /* score: '61.50'*/
      $x8 = "forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii /* score: '61.50'*/
      $x9 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/globs20123456789aAbBcCdD" ascii /* score: '57.00'*/
      $x10 = "Go pointer stored into non-Go memoryIA5String contains invalid characterNo successful authenication attemptsTime.UnmarshalBinary" ascii /* score: '54.50'*/
      $x11 = "explicit tag has no childhttp2: Framer %p: read %vhttp2: Request.URI is nilhttp2: invalid header: %vhttp2: unsupported schemeinc" ascii /* score: '49.50'*/
      $x12 = "setenv NAME VALUEbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunemalformed response from server: malfo" ascii /* score: '49.50'*/
      $x13 = " to non-Go memory , locked to thread/dev/input/event%d/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125: day out of rangeCa" ascii /* score: '49.00'*/
      $x14 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '48.50'*/
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '47.50'*/
      $x16 = "floating point errorforcegc: phase errorgetCert can't be nilgo of nil func valuegopark: bad g statusgzip: invalid headerheader l" ascii /* score: '46.00'*/
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '45.50'*/
      $x18 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii /* score: '44.50'*/
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsggo with non-e" ascii /* score: '44.00'*/
      $x20 = "github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/keylog/keystate.(*KeyLogger).read" fullword ascii /* score: '43.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule b341324d2fa5752f8595086525d4e1804cdfa779c4e785c215f786e33ed98ed6 {
   meta:
      description = "mw - file b341324d2fa5752f8595086525d4e1804cdfa779c4e785c215f786e33ed98ed6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "b341324d2fa5752f8595086525d4e1804cdfa779c4e785c215f786e33ed98ed6"
   strings:
      $s1 = "exec(''.join(chr(c^k) for c,k in zip(base64.b64decode(b'Dw9IDUQXQV4XHRgRWQoHWg4UGENNRBpCUkVaXxgWS14FCV0WGkMDUBdUDlcURBdcDl0UEERb" ascii /* score: '27.00'*/
      $s2 = "PEIYFhURFBYYEUZCGEIWQ0FFBUJTOBoBEUcMShptFAoWNkpDUDsUFhgRRkIYQhZDQRFEERhDTAUQXjgaW19ZR1oHTFNRE2kWBREyEE0HPENBEUQRGEMYREMVQxgYEBRD" ascii /* score: '16.00'*/
      $s3 = "FkIYFhURFEsyEUZCGEIWQ0ERRBEYEF0IBRsXWUtbXVlRERZXRUFRWFwZEksyQhZDQRFEERgKXkRBRgxbU0MWF18MGEJUQl9fVlY5BlkWV1lrEUQRGEMYREMVQxgYVltF" ascii /* score: '16.00'*/
      $s4 = "WRBMFnZYRF5dQ0pCWQ5RDBNYEFlVEBREDloHXUs6FBcWQhgWFRFSRFdcRgFKG0YXDlYWUEgLQUoLVBlVWUQaR0QLVV9BWEJTSxEPD0gNRBdBWQVCUAZLSENdDllbHBRH" ascii /* score: '16.00'*/
      $s5 = "exec(''.join(chr(c^k) for c,k in zip(base64.b64decode(b'Dw9IDUQXQV4XHRgRWQoHWg4UGENNRBpCUkVaXxgWS14FCV0WGkMDUBdUDlcURBdcDl0UEERb" ascii /* score: '14.00'*/
      $s6 = "Xw5dHmFDQVMRC2xCGEIWQ0ERRBEYQxhEQxVDGBgQFF5QQktTWVcaRllCFQdcKV8PDVUFRV1LEV5pFUMYGBAUFxZCGBYVERQWGBFGQhhCFkNBQgFdXk1dHApBSxEyEBQX" ascii /* score: '12.00'*/
      $s7 = "FkIYFhURFBYYEUZCGEJCAhJaPxNKBksRD0FBZRgNFFhDFkhDQTsUFhgRRkIYQhZDQRFEERhDTAUQXjgaW19ZR1oHTFNRE2kWBREyEE0HPENBEUQRGEMYREMVQ11UQ1EN" ascii /* score: '12.00'*/
      $s8 = "QgcaDBUTBgYKBUtSDk8GW0MdbhEYQxhEQxVDGBgQFBVTDFtpXlRNFAIRHUBcB1U8ClQdEwJDGhchHgIBdQVFVF4bdG9fYUByVVQVMXc3XxIZUBd9SS8KKVB5TFJ9Z0Zh" ascii /* score: '12.00'*/
      $s9 = "FhBdRUVeWkVdQkYfMkIWQ0ERRBEYEV0XE1oNS11vUFZCAxgLFUJRWl4fFg1LFnsGEkIFVl0iVgAxUBdKUVVCUmQHS0ZaX0dTEFwDEUsDUQZIO24RGEMYAAZTQ0hXQ0Bl" ascii /* score: '12.00'*/
      $s10 = "WwNbGH18dXUQWgMbFEJeAhJZAUIWMHAlUQBVEBEcFFVXAVNTW1UdPBgRRkIYQhZDQRFEEVBNTRQHVBddEFlCFx1CW0IcOxQWGBFGQhhCFkNBEQxcWQAYWUNdTV5RXlVb" ascii /* score: '11.00'*/
      $s11 = "T0ACFkZUWFAWUAEHVhZpAA5fAlhfOBoBDVY8U11JFmptQFxTVm5fU0ETO2gYQhZDQRFEEUVpGERDFUMYGBBRWVUNXFNRblBXTFBGXxgAVxAEB1AfWlUMAQ1WDFxdGEdS" ascii /* score: '11.00'*/
      $s12 = "H2gYFhURFBYYEUZCGEIWQ0EREURRBxhZQ1ECTFlrDgQAPzIWFREUFhgRRkIYQhZDQRFEWE5DBUQHVBdZYwMCDQNQZTwVERQWGBFGQhhCFkNBEUQRWxcYWUNRAkxZawEF" ascii /* score: '11.00'*/
      $s13 = "QkpLU1lXGldfVAgWZwFZDQdYA2oaMFQBBkVBZREQHhceBFRZVEUcRV1dAExZBVMNFW4HXlYFUQM4FylRTERRRRQ/ERkEAQQfMhFGQhhCFkNBEUQRGApeRApbFxBOGRQJ" ascii /* score: '11.00'*/
      $s14 = "RxddRUEfZERXSR8qWQxSDwRDTEoyQxhEQxVDGBgQFBcWQhgWFREUFhgTHR8aTFAME1wFRRAXVBdKD0MfQ00OGBkZRQxOTHRNRQsdHx9MUAwTXAVFEBdUF08VEF1UVhpW" ascii /* score: '11.00'*/
      $s15 = "HgtOHxkRVldbWgMMXEs8Q0ERRBEYQxhEQxVDXVZTRk5GFldEFQwUVVFBDgdKTFMNAkMdQUwMSkxKP2kYGBAUFxZCGBYVERRGWVUCB0pCC0MRUABVUQ1fSjN+IGsPGAUF" ascii /* score: '11.00'*/
      $s16 = "FkIYFhURFBYYEUZASxZXERVUABMCJVkIEFBPMhgQFBcWQhgWFREUFhgRRkIaB0QRDkNGC34CVBcGGWkYGBAUFxZCGBYVERQWGBFGQEsWWRMRVAATAiVZCBBQaRgYEBQX" ascii /* score: '11.00'*/
      $s17 = "RgNLRT87FBYYEUZCGEJSAhVQRAwYGDJEQxVDGBgQFBcWQhgUVFJAX1dfRFgYQFULBFIPWFZBFG5DFUMYGBAUFxZCGBYXWEQUAhEPEhRoFkNBEUQRGEMYREMVQVdLEg4X" ascii /* score: '11.00'*/
      $s18 = "UwxMaVZeWlBRVkZfGBk8Q0ERRBEYQxhEQxVDGmtVRkFTEBoMFRNcQkxBXE0XUw9RTwBSCRZTFlZWAUEUMhAUFxZCGBYVERQWGBM2DUoWFFlBE1wBGk8yREMVQxgYEBQX" ascii /* score: '11.00'*/
      $s19 = "FkIYFhURFBYYXhMWSBdCQ1wRF0VKS10WEVoRETIQFBcWQhgWFREUFhgRRkIYQhZDQUUFQlM4GgERRwxKGm0UChY2SkNQERQWGBFGQhhCFkNBEUQRGEMYREMVQxgYOhQX" ascii /* score: '11.00'*/
      $s20 = "UkBlPBURFBYYEUZCGEIWQxJUCFcWAl8BDUE8W1deUl5RORpjYHhwFGURW0JtN38naxFEERhDGERDFUMYGEJRQ0MQVhZhQ0FTMhFGQhhCFkNBVAhCXVkYFgZBFkpWEHJW" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 50KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8_4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6_0 {
   meta:
      description = "mw - from files 3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8, 4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32, 78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206, 8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8"
      hash2 = "4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32"
      hash3 = "78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206"
      hash4 = "8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii /* score: '73.50'*/
      $x2 = "fmt: unknown base; can't happenhash/crc32: tables do not matchhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii /* score: '72.50'*/
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Connection already exists within the agentFa" ascii /* score: '68.50'*/
      $x4 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '67.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size bufferfmt: scanning called" ascii /* score: '64.50'*/
      $x6 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii /* score: '62.00'*/
      $x7 = "ssh: StdinPipe after process startedssh: overflow reading version stringstrings.Builder.Grow: negative countsyntax error scannin" ascii /* score: '61.50'*/
      $x8 = "forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned leng" ascii /* score: '61.50'*/
      $x9 = ".localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/share/mime/globs20123456789aAbBcCdD" ascii /* score: '57.00'*/
      $x10 = "Go pointer stored into non-Go memoryIA5String contains invalid characterNo successful authenication attemptsTime.UnmarshalBinary" ascii /* score: '54.50'*/
      $x11 = "explicit tag has no childhttp2: Framer %p: read %vhttp2: Request.URI is nilhttp2: invalid header: %vhttp2: unsupported schemeinc" ascii /* score: '49.50'*/
      $x12 = "setenv NAME VALUEbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunemalformed response from server: malfo" ascii /* score: '49.50'*/
      $x13 = " to non-Go memory , locked to thread/dev/input/event%d/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125: day out of rangeCa" ascii /* score: '49.00'*/
      $x14 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii /* score: '48.50'*/
      $x15 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '47.50'*/
      $x16 = "floating point errorforcegc: phase errorgetCert can't be nilgo of nil func valuegopark: bad g statusgzip: invalid headerheader l" ascii /* score: '46.00'*/
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '45.50'*/
      $x18 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii /* score: '44.50'*/
      $x19 = "flate: internal error: garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsggo with non-e" ascii /* score: '44.00'*/
      $x20 = "github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/keylog/keystate.(*KeyLogger).read" fullword ascii /* score: '43.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 19000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a_5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca1_1 {
   meta:
      description = "mw - from files 2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a, 5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6, 6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
      hash2 = "5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
      hash3 = "6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
   strings:
      $x1 = "DW_AT_APPLE_propertyDW_AT_APPLE_objc_complete_typeDW_AT_APPLE_property_attributeDW_AT_APPLE_property_setterDW_AT_APPLE_property_" ascii /* score: '39.00'*/
      $x2 = "cmd.exe/cCommand status: " fullword ascii /* score: '33.00'*/
      $s3 = "_ZNC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii /* score: '30.00'*/
      $s4 = "_RC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii /* score: '30.00'*/
      $s5 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii /* score: '30.00'*/
      $s6 = "targetMetadataBuilderSetLoggerError" fullword ascii /* score: '27.00'*/
      $s7 = "credentialsportexecagentpayloadstruct Credentials with 5 elements" fullword ascii /* score: '25.00'*/
      $s8 = "Exec command completed" fullword ascii /* score: '24.00'*/
      $s9 = "attempted to set a logger after the logging system was already initializedattempted to convert a string that doesn't match an ex" ascii /* score: '24.00'*/
      $s10 = "out of range integral type conversion attemptednumber would be zero for non-zero typenumber too small to fit in target typenumbe" ascii /* score: '24.00'*/
      $s11 = "DW_TAG_BORLAND_Delphi_variantDW_TAG_BORLAND_Delphi_setDW_TAG_BORLAND_Delphi_dynamic_arrayDW_TAG_BORLAND_Delphi_stringDW_TAG_BORL" ascii /* score: '24.00'*/
      $s12 = "\\\\.\\pipe\\openssh-ssh-agent" fullword ascii /* score: '24.00'*/
      $s13 = "TooManyIterationsNotEnoughStackItemsInvalidPushObjectAddressBadBranchTargetNotFdePointerNotCiePointerNotCieIdBadUtf8OpcodeBaseZe" ascii /* score: '24.00'*/
      $s14 = "TicketEarlyDataInfoPSKKeyExchangeModesCookieSupportedVersionsEarlyDataPreSharedKeySessionTicketExtendedMasterSecretPaddingSCTALP" ascii /* score: '24.00'*/
      $s15 = "PeerMisbehavedErrorPeerIncompatibleErrorEncryptErrorDecryptErrorUnsupportedNameTypeNoCertificatesPresentedCorruptMessagePayload" fullword ascii /* score: '23.00'*/
      $s16 = "user_outputcompletedportscanpowershellredirectssh-spawnsshshelluploadjobkill" fullword ascii /* score: '22.00'*/
      $s17 = "TooManyIterationsNotEnoughStackItemsInvalidPushObjectAddressBadBranchTargetNotFdePointerNotCiePointerNotCieIdBadUtf8OpcodeBaseZe" ascii /* score: '22.00'*/
      $s18 = "RegistryWow6432KeyWmiGuidObjectProviderDefinedObjectDsObjectAllDsObjectWindowObjectKernelObjectLmShareRegistryKeyPrinterObjectSe" ascii /* score: '22.00'*/
      $s19 = "RegistryWow6432KeyWmiGuidObjectProviderDefinedObjectDsObjectAllDsObjectWindowObjectKernelObjectLmShareRegistryKeyPrinterObjectSe" ascii /* score: '22.00'*/
      $s20 = "Private key unpack failed (correct password?)" fullword ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a_5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca1_2 {
   meta:
      description = "mw - from files 2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a, 5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
      hash2 = "5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
   strings:
      $x1 = "end of fileno other error listedunknown errorlink loopinvalid filenamenot a directorydirectory not emptylock conflictunknown pri" ascii /* score: '45.00'*/
      $x2 = "DW_FORM_implicit_const used in an invalid context.Expected an attribute value to be a string form.Missing DW_LNCT_path in file e" ascii /* score: '43.00'*/
      $x3 = "SHA512SHA384SHA256SHA224SHA1MD5NONEED448ED25519ECDSADSARSAAnonymousECDSAFixedECDHRSAFixedECDHECDSASignFortezzaDMSDSSEphemeralDHR" ascii /* score: '42.00'*/
      $x4 = "ne_flagsne_autodatane_heapne_stackne_csipne_ssspne_csegne_cmodne_cbnrestabne_segtabne_rsrctabne_restabne_modtabne_imptabne_nrest" ascii /* score: '40.00'*/
      $x5 = "ImageAuxSymbolTokenDefaux_typereserved1symbol_table_indexreserved2ImageAuxSymbolFunctiontag_indextotal_sizepointer_to_linenumber" ascii /* score: '38.00'*/
      $x6 = "User-AgentFailed to make post requestWQL/root/.cargo/registry/src/github.com-1ecc6299db9ec823/wmi-0.9.3/src/query.rsGot enumerat" ascii /* score: '34.00'*/
      $x7 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\abbrev.rs" fullword ascii /* score: '33.00'*/
      $x8 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\twoway.rs" fullword ascii /* score: '33.00'*/
      $x9 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\prefilter\\x86\\sse.rs" fullword ascii /* score: '33.00'*/
      $x10 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\mod.rs" fullword ascii /* score: '33.00'*/
      $x11 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x12 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\lib.rs" fullword ascii /* score: '33.00'*/
      $x13 = "internal error: entered unreachable codeC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1" ascii /* score: '33.00'*/
      $x14 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.26.2\\src\\read\\archive.rs" fullword ascii /* score: '33.00'*/
      $x15 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\rarebytes.rs" fullword ascii /* score: '33.00'*/
      $x16 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\addr2line-0.16.0\\src\\function.rs" fullword ascii /* score: '33.00'*/
      $x17 = "disabled backtraceunsupported backtraceInvalid COFF symbol table offset or sizeC:\\Users\\runneradmin\\.cargo\\registry\\src\\gi" ascii /* score: '33.00'*/
      $x18 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\gimli-0.25.0\\src\\read\\line.rs" fullword ascii /* score: '33.00'*/
      $x19 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\memchr-2.4.1\\src\\memmem\\genericsimd.rs" fullword ascii /* score: '33.00'*/
      $s20 = "Invalid COFF/PE section indexC:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\object-0.26.2\\src\\rea" ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a_3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d_3 {
   meta:
      description = "mw - from files 2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a, 3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8, 4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32, 5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6, 6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7, 78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206, 8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
      hash2 = "3285032b8e1cd080ce5df8839db03a1eb9e4d16db252fd64d4c0c5a66d8b0ff8"
      hash3 = "4fac5b0618348de1e6e4843bb4560320eea175ecc4ba807beadd56e2e6a66e32"
      hash4 = "5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
      hash5 = "6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
      hash6 = "78480e7c9273a66498d0514ca4e959a2c002f8f5578c8ec9153bb83cbcc2b206"
      hash7 = "8affdfea794bc04340a453160237e7b6ae77bd909146321daf2ed50401928827"
   strings:
      $s1 = "DOWNGRD" fullword ascii /* score: '6.50'*/
      $s2 = "secret" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 28 times */
      $s3 = "Compression" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 117 times */
      $s4 = "shared" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.83'*/ /* Goodware String - occured 165 times */
      $s5 = "update" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79'*/ /* Goodware String - occured 207 times */
      $s6 = "Request" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.76'*/ /* Goodware String - occured 236 times */
      $s7 = "signature" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.75'*/ /* Goodware String - occured 251 times */
      $s8 = "shutdown" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.74'*/ /* Goodware String - occured 262 times */
      $s9 = "server" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.60'*/ /* Goodware String - occured 401 times */
      $s10 = "connect" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.57'*/ /* Goodware String - occured 429 times */
      $s11 = "password" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.48'*/ /* Goodware String - occured 519 times */
      $s12 = "status" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.34'*/ /* Goodware String - occured 657 times */
      $s13 = "sJfw>7G9@>" fullword ascii /* score: '4.00'*/
      $s14 = "hJxRX@_" fullword ascii /* score: '4.00'*/
      $s15 = "2Uiwp\"9" fullword ascii /* score: '4.00'*/
      $s16 = "wOUigi<" fullword ascii /* score: '4.00'*/
      $s17 = "UUUUUUUUH!" fullword ascii /* score: '4.00'*/
      $s18 = "expand 32-byte kexpand 32-byte k" fullword ascii /* score: '4.00'*/
      $s19 = ".yAu[7" fullword ascii /* score: '4.00'*/
      $s20 = "YedcCH}" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a_6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e_4 {
   meta:
      description = "mw - from files 2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a, 6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "2823e30e772d5d3dcc8c5d0a061f4dbbc884a4583608a63d69b797f3c2eaca3a"
      hash2 = "6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
   strings:
      $s1 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" fullword ascii /* score: '18.00'*/
      $s2 = "`NaiveDate - Duration` overflowed" fullword ascii /* score: '12.00'*/
      $s3 = "`NaiveDateTime - Duration` overflowed" fullword ascii /* score: '12.00'*/
      $s4 = "failed to park thread" fullword ascii /* score: '12.00'*/
      $s5 = "ImageNtHeaders32" fullword ascii /* score: '10.00'*/
      $s6 = "SystemTimeToTzSpecificLocalTime failed with: " fullword ascii /* score: '9.00'*/
      $s7 = "filled overflowfilled must not become larger than initialized" fullword ascii /* score: '9.00'*/
      $s8 = "%Y%m%d%H%M%S.%fa timestamp in WMI format" fullword ascii /* score: '8.00'*/
      $s9 = "Certainly Root R10" fullword ascii /* score: '7.00'*/
      $s10 = "DigiCert TLS RSA4096 Root G50" fullword ascii /* score: '7.00'*/
      $s11 = "ReadBuffilled" fullword ascii /* score: '7.00'*/
      $s12 = "Resuming session" fullword ascii /* score: '7.00'*/
      $s13 = "system time before Unix epoch" fullword ascii /* score: '7.00'*/
      $s14 = "blocking::Spawner" fullword ascii /* score: '7.00'*/
      $s15 = "parser error, see to_string() for detailsJanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii /* score: '7.00'*/
      $s16 = "fde_address_encodingis_signal_trampolineAugmentationData" fullword ascii /* score: '7.00'*/
      $s17 = "__NonexhaustiveBadFormatTooLongTooShortInvalidNotEnoughImpossibleOutOfRange" fullword ascii /* score: '7.00'*/
      $s18 = "DigiCert TLS ECC P384 Root G50" fullword ascii /* score: '7.00'*/
      $s19 = "functionreasonfilelinedataerror:" fullword ascii /* score: '7.00'*/
      $s20 = "Certainly Root E10" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6_6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e_5 {
   meta:
      description = "mw - from files 5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6, 6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "5b8ffd664b0c25b2338ac5e8b32279f483d97160d1f6de953f742b3ca19ceec6"
      hash2 = "6510cb8438b90ec9db3c13fca4e509fea32deea3bde2be058fad87fc6e087fc7"
   strings:
      $s1 = "[{\"name\": \"User-Agent\", \"key\": \"User-Agent\", \"value\": \"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko" ascii /* score: '23.00'*/
      $s2 = "[{\"name\": \"User-Agent\", \"key\": \"User-Agent\", \"value\": \"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko" ascii /* score: '20.00'*/
      $s3 = "assertion failed: socket != winapi::um::winsock2::INVALID_SOCKET as _/root/.cargo/registry/src/github.com-1ecc6299db9ec823/socke" ascii /* score: '16.00'*/
      $s4 = "Failed to get token information " fullword ascii /* score: '15.00'*/
      $s5 = "/root/.cargo/registry/src/github.com-1ecc6299db9ec823/wmi-0.9.3/src/safearray.rs" fullword ascii /* score: '13.00'*/
      $s6 = "AgentTaskcommand" fullword ascii /* score: '12.00'*/
      $s7 = "assertion failed: idx < self.slots.len()" fullword ascii /* score: '10.00'*/
      $s8 = "non-usize content length" fullword ascii /* score: '9.00'*/
      $s9 = "Not resuming any session" fullword ascii /* score: '7.00'*/
      $s10 = "failed to initiate panic, error " fullword ascii /* score: '7.00'*/
      $s11 = "les/http.rs" fullword ascii /* score: '7.00'*/
      $s12 = "Builderworker_threads" fullword ascii /* score: '7.00'*/
      $s13 = "Ticket not saved" fullword ascii /* score: '7.00'*/
      $s14 = " elements in map" fullword ascii /* score: '6.00'*/
      $s15 = "Full Control\\" fullword ascii /* score: '6.00'*/
      $s16 = "source slice length () does not match destination slice length (" fullword ascii /* score: '4.00'*/
      $s17 = "fileline`" fullword ascii /* score: '4.00'*/
      $s18 = "false = " fullword ascii /* score: '4.00'*/
      $s19 = "current: , sub: " fullword ascii /* score: '4.00'*/
      $s20 = "ndows.rs" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

