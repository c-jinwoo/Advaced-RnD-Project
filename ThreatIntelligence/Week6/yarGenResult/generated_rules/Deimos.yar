/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-11
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d {
   meta:
      description = "mw - file 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '79.50'*/
      $x2 = "strings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have at least one keytls: server did not " ascii /* score: '69.50'*/
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii /* score: '68.50'*/
      $x4 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '67.50'*/
      $x5 = "59604644775390625: missing method ; SameSite=StrictCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;DiacriticalTilde;DoubleRig" ascii /* score: '65.00'*/
      $x6 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPR" ascii /* score: '62.50'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '60.50'*/
      $x8 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '57.50'*/
      $x9 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in type %scan't handle %s for arg of" ascii /* score: '56.50'*/
      $x10 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii /* score: '55.50'*/
      $x11 = "tls: client certificate used with invalid signature algorithmtls: server sent a ServerHello extension forbidden in TLS 1.3tls: u" ascii /* score: '53.50'*/
      $x12 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime." ascii /* score: '53.50'*/
      $x13 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii /* score: '53.00'*/
      $x14 = "decoding string array or slice: length exceeds input size (%d elements)decoding uint16 array or slice: length exceeds input size" ascii /* score: '50.50'*/
      $x15 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii /* score: '48.00'*/
      $x16 = "HumpEqual;IP addressKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;ManichaeanMellintrf;Message-IdMinusPlus;No Conte" ascii /* score: '47.50'*/
      $x17 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x19 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failuregob: cannot enco" ascii /* score: '43.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 22000KB and
      1 of ($x*)
}

rule sig_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239 {
   meta:
      description = "mw - file 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '78.50'*/
      $x3 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x4 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '62.50'*/
      $x5 = "$e/-QWORD value is not 8 bytes longRequest Header Fields Too LargeRequested Range Not SatisfiableSERVER_HANDSHAKE_TRAFFIC_SECRET" ascii /* score: '60.50'*/
      $x6 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '60.00'*/
      $x7 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x8 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x9 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x10 = "tls: keys must have at least one keytls: server did not send a key shareuncaching span but s.allocCount == 0unsupported SSLv2 ha" ascii /* score: '52.50'*/
      $x11 = "710542735760100185871124267578125GODEBUG: no value specified for \"GetVolumeNameForVolumeMountPointWapplication/x-www-form-urlen" ascii /* score: '52.50'*/
      $x12 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x13 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '50.50'*/
      $x14 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $x15 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $x16 = " accessing a corrupted shared librarybytes.Reader.ReadAt: negative offsetbytes.Reader.Seek: negative positionchacha20: wrong HCh" ascii /* score: '49.50'*/
      $x17 = "(unknown)+infinity, newval=, oldval=, size = -infinity01234567_244140625: status=<a href=\"Accuracy(AuthorityBassa_VahBhaiksukiC" ascii /* score: '48.00'*/
      $x18 = "bad Content-Lengthbad lfnode addressbad manualFreeListblacktriangledown;blacktriangleleft;bufio: buffer fullcleantimers: bad pco" ascii /* score: '47.00'*/
      $x19 = "Y_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad def" ascii /* score: '47.00'*/
      $x20 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*)
}

rule sig_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2 {
   meta:
      description = "mw - file 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
   strings:
      $x1 = "%s appears in an ambiguous context within a URLP has cached GC work at end of mark terminationattempting to link in too many sha" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '78.50'*/
      $x3 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x4 = "http: no Location header in responsehttp: unexpected EOF reading trailerinternal error: associate not commonjson: encoding error" ascii /* score: '64.50'*/
      $x5 = "vMountain Standard Time (Mexico)Network Authentication RequiredPRIORITY frame with stream ID 0QWORD value is not 8 bytes longReq" ascii /* score: '60.50'*/
      $x6 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '60.00'*/
      $x7 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x8 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x9 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x10 = "^application/x-www-form-urlencodedbad point length: %d, expected %dbase outside usable address spacebytes.Buffer.Grow: negative " ascii /* score: '52.50'*/
      $x11 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '52.50'*/
      $x12 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x13 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $x14 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '50.50'*/
      $x15 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $x16 = "(unknown)+infinity, newval=, oldval=, size = -infinity01234567_244140625: status=<a href=\"Accuracy(AuthorityBassa_VahBhaiksukiC" ascii /* score: '48.00'*/
      $x17 = "mafter top-level valueasync stack too largebad number syntax: %qbad type in compare: block device requiredbufio: negative countc" ascii /* score: '48.00'*/
      $x18 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x20 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*)
}

rule a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9 {
   meta:
      description = "mw - file a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $x1 = "Qtemplate: no files named in call to ParseFilestls: failed to parse certificate from server: tls: received new session ticket fr" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '78.50'*/
      $x3 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x4 = "bad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasgstatus: bad incoming valueschec" ascii /* score: '60.50'*/
      $x5 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '60.00'*/
      $x6 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x7 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x8 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x9 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '57.50'*/
      $x10 = ";application/x-www-form-urlencodedbad point length: %d, expected %dbase outside usable address spacebytes.Buffer.Grow: negative " ascii /* score: '52.50'*/
      $x11 = "dwrong number of args: got %d want %dx509: zero or negative DSA parameter%q is an incomplete or empty template) is smaller than " ascii /* score: '52.50'*/
      $x12 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x13 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $x14 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '50.50'*/
      $x15 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $x16 = "^0raccessing a corrupted shared librarybytes.Reader.ReadAt: negative offsetbytes.Reader.Seek: negative positionchacha20: wrong H" ascii /* score: '49.50'*/
      $x17 = "(unknown)+infinity, newval=, oldval=, size = -infinity01234567_244140625: status=<a href=\"Accuracy(AuthorityBassa_VahBhaiksukiC" ascii /* score: '48.00'*/
      $x18 = "after top-level valueasync stack too largebad number syntax: %qbad type in compare: block device requiredbufio: negative countch" ascii /* score: '48.00'*/
      $x19 = "Rh1_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad d" ascii /* score: '47.00'*/
      $x20 = "bad Content-Lengthbad lfnode addressbad manualFreeListblacktriangledown;blacktriangleleft;bufio: buffer fullcleantimers: bad pco" ascii /* score: '47.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*)
}

rule dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c {
   meta:
      description = "mw - file dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '83.50'*/
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii /* score: '83.50'*/
      $x4 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic" ascii /* score: '70.50'*/
      $x5 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x6 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreDATA frame with stream ID 0Easter Island Standard TimeG waiting list is" ascii /* score: '64.00'*/
      $x7 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '61.50'*/
      $x8 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '60.50'*/
      $x9 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '60.00'*/
      $x10 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x11 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x12 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x13 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x14 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $x15 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $x16 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x17 = "Temporary RedirectTerminateJobObjectUNKNOWN_SETTING_%dVariation_SelectorVerticalSeparator;WriteProcessMemorybad Content-Lengthba" ascii /* score: '47.00'*/
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x19 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x20 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthtml/template:%s:%d: %shttp2: handle" ascii /* score: '44.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*)
}

rule f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd {
   meta:
      description = "mw - file f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $x1 = "curve25519: global Basepoint value was modifiedexplicit string type given to non-string memberfirst record does not look like a " ascii /* score: '92.50'*/
      $x2 = "59604644775390625: missing method ; SameSite=StrictCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;DiacriticalTilde;DoubleRig" ascii /* score: '71.00'*/
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii /* score: '70.50'*/
      $x4 = "dup idle pconn %p in freelisterror adding derived templateexec: Wait was already calledexecuting on Go runtime stackexpected ele" ascii /* score: '64.50'*/
      $x5 = "IDS_Trinary_OperatorInsufficient StorageLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNegativeMediumSpace;NotGreat" ascii /* score: '62.50'*/
      $x6 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '60.50'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '57.50'*/
      $x8 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '57.50'*/
      $x9 = "adding nil Certificate to CertPoolbad executable (or shared library)bad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '56.50'*/
      $x10 = "crypto: Size of unknown hash functiondereference of nil pointer of type %sdnsmessage.TXTResource{TXT: []string{exec: StdinPipe a" ascii /* score: '56.50'*/
      $x11 = "gcSweep being done but phase is not GCoffgob: attempt to decode into a non-pointerhtml/template: cannot Parse after Executehttp2" ascii /* score: '53.50'*/
      $x12 = "function name %q is not a valid identifiergob: bad data: field numbers out of boundsgob: encoded unsigned integer out of rangeht" ascii /* score: '53.50'*/
      $x13 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $x14 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF465661287307739257" ascii /* score: '50.00'*/
      $x15 = "gob: cannot encode nil pointer of type heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid ind" ascii /* score: '48.00'*/
      $x16 = "HumpEqual;IP addressKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;ManichaeanMellintrf;Message-IdMinusPlus;No Conte" ascii /* score: '47.50'*/
      $x17 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x18 = "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Configx509: invalid signature: parent certificate cann" ascii /* score: '46.50'*/
      $x19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x20 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
   condition:
      uint16(0) == 0xfacf and filesize < 24000KB and
      1 of ($x*)
}

rule sig_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df {
   meta:
      description = "mw - file 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '79.50'*/
      $x2 = "strings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have at least one keytls: server did not " ascii /* score: '69.50'*/
      $x3 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii /* score: '68.50'*/
      $x4 = "59604644775390625: missing method ; SameSite=StrictCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;DiacriticalTilde;DoubleRig" ascii /* score: '65.00'*/
      $x5 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '64.50'*/
      $x6 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPR" ascii /* score: '62.50'*/
      $x7 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii /* score: '60.50'*/
      $x8 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '57.50'*/
      $x9 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in type %scan't handle %s for arg of" ascii /* score: '56.50'*/
      $x10 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii /* score: '55.50'*/
      $x11 = "decoding string array or slice: length exceeds input size (%d elements)decoding uint16 array or slice: length exceeds input size" ascii /* score: '55.50'*/
      $x12 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime." ascii /* score: '53.50'*/
      $x13 = "tls: client certificate used with invalid signature algorithmtls: server sent a ServerHello extension forbidden in TLS 1.3tls: u" ascii /* score: '53.50'*/
      $x14 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii /* score: '53.00'*/
      $x15 = "gob: cannot encode nil pointer of type http: putIdleConn: keep alives disabledinvalid indexed representation index %dmismatched " ascii /* score: '48.00'*/
      $x16 = "HumpEqual;IP addressKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;ManichaeanMellintrf;Message-IdMinusPlus;No Conte" ascii /* score: '47.50'*/
      $x17 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x19 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failuregob: cannot enco" ascii /* score: '43.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule sig_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92 {
   meta:
      description = "mw - file 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '79.50'*/
      $x2 = "Fwrong number of args: got %d want %dx509: zero or negative DSA parameter%q is an incomplete or empty template) is smaller than " ascii /* score: '61.50'*/
      $x3 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '60.50'*/
      $x4 = "fmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in literal null (expecting 'u')in l" ascii /* score: '58.50'*/
      $x5 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '57.50'*/
      $x6 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iteratorPR" ascii /* score: '57.50'*/
      $x7 = "adding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in type %scan't handle %s for arg of" ascii /* score: '57.50'*/
      $x8 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii /* score: '55.50'*/
      $x9 = "decoding string array or slice: length exceeds input size (%d elements)decoding uint16 array or slice: length exceeds input size" ascii /* score: '55.50'*/
      $x10 = "<accessing a corrupted shared librarybytes.Reader.ReadAt: negative offsetbytes.Reader.Seek: negative positionchacha20: wrong HCh" ascii /* score: '54.50'*/
      $x11 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime." ascii /* score: '53.50'*/
      $x12 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii /* score: '53.00'*/
      $x13 = "gob: cannot encode nil pointer of type http: putIdleConn: keep alives disabledinvalid indexed representation index %dmismatched " ascii /* score: '48.00'*/
      $x14 = "HumpEqual;IP addressKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;ManichaeanMellintrf;Message-IdMinusPlus;No Conte" ascii /* score: '47.50'*/
      $x15 = "bad Content-Lengthbad manualFreeListblacktriangledown;blacktriangleleft;bufio: buffer fullcleantimers: bad pconnection refusedco" ascii /* score: '47.00'*/
      $x16 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x17 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x18 = "net/http: skip alternate protocolpad size larger than data payloadpseudo header field after regularreflect.nameFrom: name too lo" ascii /* score: '46.50'*/
      $x19 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x20 = "(MISSING)(unknown)+infinity, Body: &, Class: , RCode: , Retry: , newval=, oldval=, size = -07:00:00-infinity/dev/null01234567_20" ascii /* score: '44.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      1 of ($x*)
}

rule a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940 {
   meta:
      description = "mw - file a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '83.50'*/
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii /* score: '83.50'*/
      $x4 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic" ascii /* score: '70.50'*/
      $x5 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x6 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreDATA frame with stream ID 0Easter Island Standard TimeG waiting list is" ascii /* score: '64.00'*/
      $x7 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '64.00'*/
      $x8 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '61.50'*/
      $x9 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '60.50'*/
      $x10 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x11 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x12 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x13 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '55.50'*/
      $x14 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x15 = "(MISSING)(unknown)+infinity, newval=, oldval=, size = ,\"Files\":-07:00:00-infinity/settings01234567_127.0.0.1244140625: status=" ascii /* score: '49.00'*/
      $x16 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x17 = "Temporary RedirectTerminateJobObjectUNKNOWN_SETTING_%dVariation_SelectorVerticalSeparator;WriteProcessMemorybad Content-Lengthba" ascii /* score: '47.00'*/
      $x18 = "_eval_args_alarm clockapplicationbad addressbad m valuebad messagebad timedivbad verb '%broken pipecall of nilcgocall nilcircled" ascii /* score: '47.00'*/
      $x19 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x20 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      1 of ($x*)
}

rule c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233 {
   meta:
      description = "mw - file c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '90.50'*/
      $x2 = "can't represent recursive pointer type chain is not signed by an acceptable CAcipher: incorrect tag size given to GCMcrypto/rsa:" ascii /* score: '78.50'*/
      $x3 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x4 = "key size not a multiple of key alignmalformed MIME header initial line: multiplication of zero with infinityno acceptable authen" ascii /* score: '64.50'*/
      $x5 = "bad write barrier buffer boundscannot assign requested addresscasgstatus: bad incoming valuescheckmark found unmarked objectcryp" ascii /* score: '60.50'*/
      $x6 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x7 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x8 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '55.50'*/
      $x9 = "(MISSING)(unknown)+infinity, newval=, oldval=, size = -07:00:00-infinity01234567_244140625: status=; Domain=<a href=\"Accuracy(A" ascii /* score: '53.00'*/
      $x10 = "Yapplication/x-www-form-urlencodedbad point length: %d, expected %dbytes.Buffer.Grow: negative countbytes.Reader.Seek: invalid w" ascii /* score: '52.50'*/
      $x11 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '52.50'*/
      $x12 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x13 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '50.50'*/
      $x14 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $x15 = "4after top-level valueasync stack too largebad number syntax: %qbad type in compare: block device requiredbufio: negative countc" ascii /* score: '48.00'*/
      $x16 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x17 = "Sbad Content-Lengthbad manualFreeListblacktriangledown;blacktriangleleft;bufio: buffer fullcleantimers: bad pconnection refusedc" ascii /* score: '47.00'*/
      $x18 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x19 = "1NegativeMediumSpace;NotGreaterFullEqual;NotRightTriangleBar;QueryServiceConfig2WQueryServiceStatusExRegisterEventSourceWRequest" ascii /* score: '46.50'*/
      $x20 = "Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-TypeCookie.ValueCreateEventWCreateMu" ascii /* score: '46.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      1 of ($x*)
}

/* Super Rules ------------------------------------------------------------- */

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_0 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash4 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash5 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash6 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash7 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash8 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash9 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash10 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "*template.ExecError" fullword ascii /* score: '30.00'*/
      $s2 = "text/template.ExecError.Unwrap" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
      $s4 = "sync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 public keys are not supported before TLS 1.2tls: server se" ascii /* score: '30.00'*/
      $s5 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s6 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s7 = "text/template.ExecError.Error" fullword ascii /* score: '30.00'*/
      $s8 = "os/exec.ExitError.Sys" fullword ascii /* score: '30.00'*/
      $s9 = "html/template.(*Template).ExecuteTemplate" fullword ascii /* score: '29.00'*/
      $s10 = "text/template.(*Template).ExecuteTemplate" fullword ascii /* score: '29.00'*/
      $s11 = "text/template.(*Template).Execute" fullword ascii /* score: '29.00'*/
      $s12 = "html/template.(*Template).Execute" fullword ascii /* score: '29.00'*/
      $s13 = "text/template.(*ExecError).Error" fullword ascii /* score: '26.00'*/
      $s14 = "text/template.(*ExecError).Unwrap" fullword ascii /* score: '26.00'*/
      $s15 = "q*struct { lock runtime.mutex; newm runtime.muintptr; waiting bool; wake runtime.note; haveTemplateThread uint32 }" fullword ascii /* score: '25.00'*/
      $s16 = "text/template.(*Template).execute" fullword ascii /* score: '25.00'*/
      $s17 = "type..eq.text/template.ExecError" fullword ascii /* score: '25.00'*/
      $s18 = "os/exec.(*ExitError).SysUsage" fullword ascii /* score: '24.00'*/
      $s19 = "os.(*ProcessState).sysUsage" fullword ascii /* score: '24.00'*/
      $s20 = "os.(*ProcessState).SysUsage" fullword ascii /* score: '24.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_1 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash5 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash6 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "59604644775390625: missing method ; SameSite=StrictAdjustTokenGroupsCOMPRESSION_ERRORDiacriticalAcute;DiacriticalGrave;Diacritic" ascii /* score: '51.00'*/
      $x2 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x3 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthtml/template:%s:%d: %shttp2: handle" ascii /* score: '44.50'*/
      $x4 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii /* score: '40.00'*/
      $x5 = "runtime: netpoll: PostQueuedCompletionStatus failed (errno= tls: initial handshake had non-empty renegotiation extensiontls: no " ascii /* score: '38.50'*/
      $x6 = "invalid network interface nameinvalid pointer found on stacklength mismatch in decodeArraylength mismatch in ignoreArraylooking " ascii /* score: '31.00'*/
      $s7 = "triangleq;unixpacketunknown pcuser-agentuser32.dllvalue for varpropto;ws2_32.dllwsarecvmsgwsasendmsg  of size   (targetpc= ErrCo" ascii /* score: '26.00'*/
      $s8 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatch" ascii /* score: '25.50'*/
      $s9 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii /* score: '25.00'*/
      $s10 = "invalid key size crypto/rsa: invalid exponentsdup idle pconn %p in freelisterror adding derived templateexec: Wait was already c" ascii /* score: '25.00'*/
      $s11 = "y typereflect: Out of non-func type rpc: error executing template:rpc: service already defined: runqputslow: queue is not fullru" ascii /* score: '25.00'*/
      $s12 = "unlocked mutextext/javascript; charset=utf-8transform: short source buffertype %s has no exported fieldsunaddressable value of t" ascii /* score: '24.00'*/
      $s13 = "tp2: decoded hpack field %+vhttp: named cookie not presentillegal window increment valuein exponent of numeric literalinappropri" ascii /* score: '24.00'*/
      $s14 = "oot of negative numberstream error: stream ID %d; %vstrings: negative Repeat countsync: inconsistent mutex statesync: unlock of " ascii /* score: '23.50'*/
      $s15 = "Classbad character %#Ucan't scan type: circlearrowright;decryption faileddownharpoonright;entersyscallblockexec format errorexec" ascii /* score: '23.00'*/
      $s16 = "essIdGetDiskFreeSpaceExWGetOverlappedResultGetSystemDirectoryWGetTokenInformationHaiti Standard TimeIDS_Binary_OperatorINADEQUAT" ascii /* score: '23.00'*/
      $s17 = "[originating from goroutine _html_template_rcdataescaper_html_template_srcsetescaper_html_template_urlnormalizerasn1: string not" ascii /* score: '23.00'*/
      $s18 = "eature \"GetProcessPreferredUILanguagesGetSecurityDescriptorRMControlGetSystemTimePreciseAsFileTimeHEADERS frame with stream ID " ascii /* score: '23.00'*/
      $s19 = "eAndDomain: NetUserGetLocalGroups() returned an empty list for domain: %s, username: %shttp2: Transport: cannot retry err [%v] a" ascii /* score: '22.50'*/
      $s20 = "golang.org/x/sys/windows.Token.IsElevated" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_2 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash3 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash4 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $x1 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii /* score: '31.50'*/
      $s2 = "[originating from goroutine _html_template_rcdataescaper_html_template_srcsetescaper_html_template_urlnormalizerasn1: string not" ascii /* score: '28.00'*/
      $s3 = "IORITY frame payload size was %d; want 5PrintableString contains invalid characterTime.MarshalBinary: unexpected zone offsetacqu" ascii /* score: '24.50'*/
      $s4 = "net/http: invalid Cookie.Domain %q; dropping domain attributerpc.Register: argument type of method %q is not exported: %q" fullword ascii /* score: '22.50'*/
      $s5 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s6 = "strings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have at least one keytls: server did not " ascii /* score: '21.00'*/
      $s7 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii /* score: '20.50'*/
      $s8 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s9 = "*x509.SystemRootsError" fullword ascii /* score: '19.00'*/
      $s10 = "go.(*struct { sync.Mutex; os.dir string }).Lock" fullword ascii /* score: '18.00'*/
      $s11 = "tp: HTTP/1.x transport connection broken: %vnet/http: Transport failed to read from server: %vnet/http: invalid header field val" ascii /* score: '18.00'*/
      $s12 = "iteral true (expecting 'e')in literal true (expecting 'r')in literal true (expecting 'u')internal error - misuse of itabinvalid " ascii /* score: '18.00'*/
      $s13 = "go.(*struct { sync.Mutex; os.dir string }).Unlock" fullword ascii /* score: '18.00'*/
      $s14 = "aring uncomparable type crypto/rsa: decryption errorcurrent time %s is before %sdestination address requireddnsmessage.MXResourc" ascii /* score: '18.00'*/
      $s15 = ">*func(dnsmessage.ResourceHeader, dnsmessage.TXTResource) error" fullword ascii /* score: '16.00'*/
      $s16 = "runtime.sigpipe" fullword ascii /* score: '16.00'*/
      $s17 = "runtime.pipe" fullword ascii /* score: '16.00'*/
      $s18 = "indicated early data in second ClientHellotls: failed to create cipher while encrypting ticket: tls: received HelloRetryRequest " ascii /* score: '16.00'*/
      $s19 = "internal/poll.DupCloseOnExec" fullword ascii /* score: '16.00'*/
      $s20 = "runtime.nonblockingPipe" fullword ascii /* score: '16.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_3 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash4 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash6 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = ":*struct { lock runtime.mutex; free [35]runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s2 = "math.log2" fullword ascii /* score: '16.00'*/
      $s3 = "omitempt" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s5 = "type..eq.struct { runtime.lock runtime.mutex; runtime.stack runtime.gList; runtime.noStack runtime.gList; runtime.n int32 }" fullword ascii /* score: '13.00'*/
      $s6 = "type..eq.runtime.rwmutex" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.memhash128" fullword ascii /* score: '13.00'*/
      $s8 = "vendor/golang.org/x/sys/cpu.xgetbv" fullword ascii /* score: '12.00'*/
      $s9 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii /* score: '12.00'*/
      $s10 = "omitemptH9" fullword ascii /* score: '12.00'*/
      $s11 = "*struct { F uintptr; addrRangeToSummaryRange func(int, runtime.addrRange) (int, int); summaryRangeToSumAddrRange func(int, int, " ascii /* score: '12.00'*/
      $s12 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii /* score: '11.00'*/
      $s13 = "crypto/elliptic.(*p256Curve).CombinedMult" fullword ascii /* score: '11.00'*/
      $s14 = "{{templaL" fullword ascii /* score: '11.00'*/
      $s15 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii /* score: '11.00'*/
      $s16 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii /* score: '11.00'*/
      $s17 = "crypto/elliptic.p256Curve.CombinedMult" fullword ascii /* score: '11.00'*/
      $s18 = "3333330" wide /* reversed goodware string '0333333' */ /* score: '11.00'*/
      $s19 = "555555555555555555555" wide /* reversed goodware string '555555555555555555555' */ /* score: '11.00'*/
      $s20 = "5555555555555555555555555" wide /* reversed goodware string '5555555555555555555555555' */ /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_4 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $s1 = "55555555555555555555" wide /* reversed goodware string '55555555555555555555' */ /* score: '27.00'*/ /* hex encoded string 'UUUUUUUUUU' */
      $s2 = ":*struct { lock runtime.mutex; free [19]runtime.mSpanList }" fullword ascii /* score: '18.00'*/
      $s3 = "runtime.mapassign_fast32ptr" fullword ascii /* score: '13.00'*/
      $s4 = "sync/atomic.CompareAndSwapInt32" fullword ascii /* score: '11.00'*/
      $s5 = "This program can only be run on processors with MMX support." fullword ascii /* score: '11.00'*/
      $s6 = "sync/atomic.CompareAndSwapUint32" fullword ascii /* score: '11.00'*/
      $s7 = "sync/atomic.CompareAndSwapUint64" fullword ascii /* score: '11.00'*/
      $s8 = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f55ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b" ascii /* score: '11.00'*/
      $s9 = "runtime.uint64tofloat64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.goPanicExtendIndex" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.goPanicExtendSliceAlenU" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.float64touint64" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.emptyfunc" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.panicExtendSliceB" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.panicExtendSliceAlenU" fullword ascii /* score: '10.00'*/
      $s16 = "runtime.panicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s17 = "runtime.uint64div" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.uint32tofloat64" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.rotl_15" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.int64div" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_5 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash3 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
   strings:
      $x1 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii /* score: '57.50'*/
      $x2 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: sum" ascii /* score: '55.50'*/
      $x3 = "%s slice too big: %d elements of %d bytes34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime." ascii /* score: '53.50'*/
      $x4 = "template: no template %q associated with template %qtls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '45.50'*/
      $x5 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthtml/template:%s:%d: %shttp2: handle" ascii /* score: '39.50'*/
      $x6 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncomparable type %s: %vunexpected %s in operandunexpect" ascii /* score: '35.50'*/
      $x7 = "invalid network interface nameinvalid pointer found on stacklength mismatch in decodeArraylength mismatch in ignoreArraylooking " ascii /* score: '34.50'*/
      $x8 = "/dev/urandom100-continue127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;Content-" ascii /* score: '34.00'*/
      $x9 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '30.50'*/
      $s10 = "th d._panic != nilgob: decoding into local type html/template: %q is undefinedhttp2: decoded hpack field %+vhttp: named cookie n" ascii /* score: '30.00'*/
      $s11 = "evaluating %s.%snotewakeup - double wakeup (os: process already finishedos: process already releasedoverflow on character value " ascii /* score: '26.00'*/
      $s12 = " awaiting response headersno multipart boundary param in Content-Typenon executable command in pipeline stage %dreflect: Call wi" ascii /* score: '26.00'*/
      $s13 = "cannot Clone %q after it has executedhttp2: Transport readFrame error on conn %p: (%T) %vhttp: method cannot contain a Content-L" ascii /* score: '25.50'*/
      $s14 = ", received remote type /etc/apache2/mime.types/etc/pki/tls/cacert.pem0123456789aAbBcCdDeEfF_0123456789abcdefABCDEF_200 Connected" ascii /* score: '25.00'*/
      $s15 = "t Parse after Executehttp2: invalid Upgrade request header: %qhttp2: no cached connection was availableidna: internal error in p" ascii /* score: '25.00'*/
      $s16 = " type rpc: error executing template:rpc: service already defined: runqputslow: queue is not fullruntime: bad pointer in frame ru" ascii /* score: '25.00'*/
      $s17 = "locked mutextext/javascript; charset=utf-8transform: short source buffertype %s has no exported fieldsunaddressable value of typ" ascii /* score: '24.00'*/
      $s18 = "ml/template: pattern matches no files: %#qhttp2: could not negotiate protocol mutuallyhttp2: invalid Connection request header: " ascii /* score: '24.00'*/
      $s19 = "typecontext.TODOcurlyeqprec;curlyeqsucc;diamondsuit;dumping heapend tracegc" fullword ascii /* score: '24.00'*/
      $s20 = "t of negative numberstream error: stream ID %d; %vstrings: negative Repeat countsync: inconsistent mutex statesync: unlock of un" ascii /* score: '23.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_6 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x2 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x3 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRat.Scan: invalid verbRtlGetNtVersionNumbersSakhalin Standard " ascii /* score: '59.00'*/
      $x4 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x5 = " is unavailable not a function()<>@,;:\\\"/[]?=0601021504Z0700476837158203125: cannot parse :ValidateLabels<invalid Value>ASCII_" ascii /* score: '44.00'*/
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failuregob: cannot enco" ascii /* score: '43.50'*/
      $s7 = "mputerNameExContent-LengthControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomDifferentialD;Dkim" ascii /* score: '28.00'*/
      $s8 = "awaiting response headersno multipart boundary param in Content-Typenon executable command in pipeline stage %dreflect: Call wit" ascii /* score: '26.00'*/
      $s9 = "morebuf={pc:accept-encodingaccept-languageadvertise errorapplication/pdfasyncpreemptoffbad certificatebad debugCallV1bad trailer" ascii /* score: '26.00'*/
      $s10 = " Executehttp2: invalid Upgrade request header: %qhttp2: no cached connection was availableidna: internal error in punycode encod" ascii /* score: '25.00'*/
      $s11 = "ORITY frame payload size was %d; want 5PrintableString contains invalid characterTime.MarshalBinary: unexpected zone offsetacqui" ascii /* score: '24.50'*/
      $s12 = "WENABLE_PUSHEND_HEADERSEarly HintsEqualTilde;ExitProcessFouriertrf;FreeLibraryGOTRACEBACKGetFileTypeHTTPS_PROXYIdeographicImagin" ascii /* score: '23.00'*/
      $s13 = "imeoutGetAdaptersInfoGetCommandLineWGetProcessTimesGetSecurityInfoGetStartupInfoWGreaterGreater;Hanifi_RohingyaHorizontalLine;Id" ascii /* score: '23.00'*/
      $s14 = " of args for %s: want %d got %dx509: Common Name is not a valid hostname: x509: failed to parse dnsName constraint %q using valu" ascii /* score: '22.50'*/
      $s15 = "... omitting accept-charsetallocfreetracebad allocCountbad record MACbad span statebad stack sizebigtriangleup;blacktriangle;con" ascii /* score: '22.00'*/
      $s16 = "ase %djson: unknown field %qkernel32.dll not foundmalformed HTTP versionminpc or maxpc invalidmissing ']' in addressnetwork is u" ascii /* score: '22.00'*/
      $s17 = "SubsetEqual;NotVerticalBar;OpenCurlyQuote;OpenThreadTokenOther_LowercaseOther_UppercasePartial ContentProcess32FirstWPsalter_Pah" ascii /* score: '21.00'*/
      $s18 = "baseinvalid kindinvalid portinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmax-forwardsnRightarrow;netapi32.dllno s" ascii /* score: '21.00'*/
      $s19 = "k too muchinvalid header field value %qinvalid length of trace eventio: read/write on closed pipemachine is not on the networkmi" ascii /* score: '21.00'*/
      $s20 = "htls: unsupported certificate curve (%s)transport endpoint is already connectedusername/password authentication failedx509: fail" ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_7 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
   strings:
      $x1 = "decoding string array or slice: length exceeds input size (%d elements)decoding uint16 array or slice: length exceeds input size" ascii /* score: '55.50'*/
      $x2 = ", RecursionAvailable: .localhost.localdomain/etc/apache/mime.types/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/local/share/c" ascii /* score: '53.00'*/
      $x3 = "gob: cannot encode nil pointer of type http: putIdleConn: keep alives disabledinvalid indexed representation index %dmismatched " ascii /* score: '48.00'*/
      $x4 = "HumpEqual;IP addressKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;ManichaeanMellintrf;Message-IdMinusPlus;No Conte" ascii /* score: '47.50'*/
      $x5 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failuregob: cannot enco" ascii /* score: '43.50'*/
      $x7 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version unsupported compression for x509: unknown elliptic curv" ascii /* score: '39.00'*/
      $s8 = "morebuf={pc:accept-encodingaccept-languageadvertise errorapplication/pdfasyncpreemptoffbad certificatebad debugCallV1bad system " ascii /* score: '29.00'*/
      $s9 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETNetw" ascii /* score: '25.00'*/
      $s10 = "nvalid port %q after hostinvalid request descriptorinvalid value; expected %smalformed HTTP status codemalformed chunked encodin" ascii /* score: '21.00'*/
      $s11 = "en= targetpc= throwing= until pc=%!(NOVERB)%!Weekday(%s|%s%s|%s(BADINDEX), Expire: , Length: , MinTTL: , OpCode: , Serial: , Tar" ascii /* score: '21.00'*/
      $s12 = "ablehttp: idle connection timeoutinteger not minimally-encodedinternal error: took too muchinvalid header field value %qinvalid " ascii /* score: '20.00'*/
      $s13 = "pected end of string, found %qgo package net: hostLookupOrder(http2: invalid header field namein literal false (expecting 'a')in" ascii /* score: '20.00'*/
      $s14 = "lformed character constant: %smime: expected token after slashnode %s shared between templatesnon-Go code disabled sigaltstacknu" ascii /* score: '20.00'*/
      $s15 = " lockedg= lockedm= m->curg= method:  ms cpu,  not in [ of type  runtime= s.limit= s.state= sigcode= threads= u_a/u_g= wbuf1.n= w" ascii /* score: '19.50'*/
      $s16 = "v initgsignal quirk too lategzip: invalid checksumheader field %q = %q%shpack: string too longhttp2: frame too largeidna: invali" ascii /* score: '19.00'*/
      $s17 = "ack: gp=s.freeindex > s.nelemsscanstack - bad statussend on closed channelskipping Question Nameskipping Question Typeslice leng" ascii /* score: '19.00'*/
      $s18 = "rypto/rsa: invalid exponentsdup idle pconn %p in freelisterror adding derived templateexec: Wait was already calledgc done but g" ascii /* score: '18.00'*/
      $s19 = "smessage.AResource{A: [4]byte{dnsmessage.CNAMEResource{CNAME: dnsmessage.ResourceHeader{Name: ed25519: bad public key length: ex" ascii /* score: '18.00'*/
      $s20 = "onright;write error: %v already; errno= is not exported mheap.sweepgen= not in ranges:" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 19000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940_c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4_8 {
   meta:
      description = "mw - from files a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash2 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $x1 = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version x509: unknown elliptic curve cannot be converted to typ" ascii /* score: '69.50'*/
      $x2 = "HumpEqual;IP addressIsValidSidKeep-AliveKharoshthiLeftArrow;LeftFloor;Leftarrow;LessTilde;LockFileExManichaeanMellintrf;Message-" ascii /* score: '59.50'*/
      $x3 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '55.50'*/
      $x4 = "checkdead: no m for timercontext deadline exceedederror decoding []byte: %sexpected string; found %sexplicit tag has no childhtt" ascii /* score: '46.50'*/
      $x5 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failuregob: cannot enco" ascii /* score: '43.50'*/
      $x6 = "authorizationbad flushGen bad map stateblacklozenge;cache-controlcontent-rangedalTLDpSugct?define clauseemail addressempty comma" ascii /* score: '38.00'*/
      $s7 = "key expansionlast-modifiedlevel 3 resetload64 failedmaster secretmin too largenil stackbaseout of memoryparsing time powrprof.dl" ascii /* score: '29.00'*/
      $s8 = "morebuf={pc:accept-encodingaccept-languageadvertise errorapplication/pdfasyncpreemptoffbad certificatebad debugCallV1bad trailer" ascii /* score: '29.00'*/
      $s9 = " is unavailable not a function()<>@,;:\\\"/[]?=0601021504Z0700476837158203125: cannot parse :ValidateLabels; SameSite=None<inval" ascii /* score: '29.00'*/
      $s10 = "oundary param in Content-Typenon executable command in pipeline stage %dreflect: Call with too many input argumentsreflect: Call" ascii /* score: '26.00'*/
      $s11 = "eCookie.PathCreateFileWDeleteFileWENABLE_PUSHEND_HEADERSEarly HintsEqualTilde;ExitProcessFouriertrf;FreeLibraryGOTRACEBACKGetFil" ascii /* score: '26.00'*/
      $s12 = "d open-coded defers in deferreturnunknown runnable goroutine during bootstrapwrong number of args for %s: want %d got %dx509: Co" ascii /* score: '24.50'*/
      $s13 = "se is not GCoffgob: attempt to decode into a non-pointerhtml/template: cannot Parse after Executehttp2: invalid Upgrade request " ascii /* score: '24.00'*/
      $s14 = "OfFileGateway TimeoutGetAdaptersInfoGetCommandLineWGetProcessTimesGetSecurityInfoGetStartupInfoWGreaterGreater;Hanifi_RohingyaHo" ascii /* score: '23.00'*/
      $s15 = "eld %qkernel32.dll not foundmalformed HTTP versionminpc or maxpc invalidmissing ']' in addressnetwork is unreachablenon-Go funct" ascii /* score: '22.00'*/
      $s16 = "ime.main not on m0runtime: work.nwait = runtime:scanstack: gp=s.freeindex > s.nelemsscanstack - bad statussend on closed channel" ascii /* score: '22.00'*/
      $s17 = "tion name %q is not a valid identifiergob: bad data: field numbers out of boundsgob: encoded unsigned integer out of rangehttp: " ascii /* score: '22.00'*/
      $s18 = "baseinvalid kindinvalid portinvalid slotiphlpapi.dllkernel32.dllmadvdontneedmax-forwardsnRightarrow;netapi32.dllno such hostnot " ascii /* score: '21.00'*/
      $s19 = "tEqual;NotVerticalBar;OpenCurlyQuote;OpenThreadTokenOther_LowercaseOther_UppercasePartial ContentProcess32FirstWPsalter_PahlaviQ" ascii /* score: '21.00'*/
      $s20 = "atchimage/svg+xmlinvalid base kernel32.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940_dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322_9 {
   meta:
      description = "mw - from files a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash2 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic" ascii /* score: '70.50'*/
      $x2 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreDATA frame with stream ID 0Easter Island Standard TimeG waiting list is" ascii /* score: '64.00'*/
      $x3 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dcan't evaluate field %s in" ascii /* score: '61.50'*/
      $x4 = "tls: certificate used with invalid signature algorithmtls: client indicated early data in second ClientHellotls: failed to creat" ascii /* score: '60.50'*/
      $x5 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint.(*WindowsProcess).Executable" fullword ascii /* score: '42.00'*/
      $x6 = "github.com/DeimosC2/DeimosC2/agents/resources/shellinject/shellcode_windows.go" fullword ascii /* score: '41.00'*/
      $x7 = "AElig;AacuteAcceptAcirc;AgraveAlpha;Amacr;AnswerAogon;ArabicAring;AtildeAugustBasic BrahmiBreve;CANCELCarianCcedilCcirc;ChakmaCo" ascii /* score: '40.50'*/
      $x8 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncomparable type %s: %vunexpected %s in operandunexpect" ascii /* score: '39.50'*/
      $x9 = "C:\\Windows\\System32\\cmd.exeCertEnumCertificatesInStoreDATA frame with stream ID 0Easter Island Standard TimeG waiting list is" ascii /* score: '35.00'*/
      $x10 = " using %03d %s%s %s; , goid=, j0 = 19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625:method:scheme:statusAacute;Abreve;Ag" ascii /* score: '34.50'*/
      $x11 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint.processes" fullword ascii /* score: '33.00'*/
      $x12 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint.newWindowsProcess" fullword ascii /* score: '33.00'*/
      $x13 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint.(*WindowsProcess).Pid" fullword ascii /* score: '33.00'*/
      $x14 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint.(*WindowsProcess).PPid" fullword ascii /* score: '33.00'*/
      $x15 = "CreateSymbolicLinkWCryptAcquireContextCryptReleaseContextDownRightTeeVector;DownRightVectorBar;Egypt Standard TimeGetCurrentProc" ascii /* score: '33.00'*/
      $x16 = "github.com/DeimosC2/DeimosC2/agents/resources/shellexec/exec_windows.go" fullword ascii /* score: '32.00'*/
      $x17 = "value=aacute;abortedabreve;agrave;andand;angmsd;angsph;apacir;approx;archiveatilde;barvee;barwed;bdoUxXvbecaus;bernou;bigcap;big" ascii /* score: '31.00'*/
      $s18 = ", received remote type 0123456789aAbBcCdDeEfF_0123456789abcdefABCDEF_200 Connected to Go RPC23283064365386962890625<invalid refl" ascii /* score: '29.00'*/
      $s19 = "rruptedGetSecurityDescriptorLengthGetUserPreferredUILanguagesStartServiceCtrlDispatcherW\"2006-01-02T15:04:05Z07:00\"_html_templ" ascii /* score: '28.00'*/
      $s20 = "il pointerlen of untyped nilmultihop attemptednegative bit indexno child processesno locks availablenon-minimal lengthoperation " ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366_10 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "en= targetpc= throwing= until pc=%!Weekday(%s|%s%s|%s, Expire: , Length: , MinTTL: , OpCode: , Serial: , Target: , Weight: , bou" ascii /* score: '23.50'*/
      $s2 = "nwait = runtime:scanstack: gp=s.freeindex > s.nelemsscanstack - bad statussend on closed channelskipping Question Nameskipping Q" ascii /* score: '22.00'*/
      $s3 = " lockedg= lockedm= m->curg= ms cpu,  not in [ of type  runtime= s.limit= s.state= sigcode= threads= u_a/u_g= wbuf1.n= wbuf2.n=#Z" ascii /* score: '19.50'*/
      $s4 = "crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled115792089210356248762697446949407573529996955224135" ascii /* score: '18.00'*/
      $s5 = "gotmplZ%s %q: %s%s %x %x" fullword ascii /* score: '16.50'*/
      $s6 = " type runtime: blocked write on free polldescruntime: casfrom_Gscanstatus failed gp=runtime: function symbol table header: stack" ascii /* score: '16.00'*/
      $s7 = " (%d vs %+v) %+v %s @%dtemplate: pattern matches no files: %#qtls: internal error: wrong nonce lengthtls: unsupported certificat" ascii /* score: '16.00'*/
      $s8 = " H_T= H_a= H_g= MB,  W_a= and  cnt= h_a= h_g= h_t= max= not  ptr  siz= tab= top= u_a= u_g=$HOME$USER%s %q%s*%d%s=%s&#10;&#11;&#1" ascii /* score: '14.00'*/
      $s9 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, Response: -byte li" ascii /* score: '13.00'*/
      $s10 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, Response: -byte li" ascii /* score: '13.00'*/
      $s11 = "myhostna" fullword ascii /* score: '13.00'*/
      $s12 = "trarr;gtrdot;gtrsim;hairsp;hamilt;hardcy;headershearts;hellip;hercon;homtht;horbar;hslash;hstrok;http://hybull;hyphen;iacute;igr" ascii /* score: '12.00'*/
      $s13 = "Signercrypto/rand: blocked for 60 seconds waiting to read random data from the kernel" fullword ascii /* score: '12.00'*/
      $s14 = "\\QQQQQ" fullword ascii /* reversed goodware string 'QQQQQ\\' */ /* score: '12.00'*/
      $s15 = " nilcircledast;clobberfreecomplement;contextmenucreated by crossorigincurlywedge;dnsmessage.element of empty fieldeqslantgtr;exp" ascii /* score: '12.00'*/
      $s16 = "ar;nexist;nil keynltrie;nosniffnotinE;nparsl;nprcue;nrarrc;nrarrw;nrtrie;nsccue;nsimeq;ntilde;number numero;nvDash;nvHarr;nvdash" ascii /* score: '12.00'*/
      $s17 = "exed representation index %dmismatched count during itab table copymspan.sweep: bad span state after sweepno mutually supported " ascii /* score: '12.00'*/
      $s18 = "runtime.(*sigctxt).rsi" fullword ascii /* score: '10.00'*/
      $s19 = "runtime.(*sigctxt).rsp" fullword ascii /* score: '10.00'*/
      $s20 = "runtime.(*sigctxt).rbx" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_11 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
   strings:
      $x1 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x2 = "github.com/DeimosC2/DeimosC2/agents/resources/shellinject/shellcode_linux.go" fullword ascii /* score: '41.00'*/
      $x3 = "IDS_Trinary_OperatorInsufficient StorageLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic_HieroglyphsNegativeMediumSpace;NotGreat" ascii /* score: '40.50'*/
      $x4 = "AElig;AacuteAcceptAcirc;AgraveAlpha;Amacr;AnswerAogon;ArabicAring;AtildeAugustBasic BrahmiBreve;CANCELCarianCcedilCcirc;ChakmaCo" ascii /* score: '40.50'*/
      $x5 = "github.com/DeimosC2/DeimosC2/agents/resources/shellinject.ShellInject.func1" fullword ascii /* score: '37.00'*/
      $x6 = "github.com/DeimosC2/DeimosC2/agents/resources/shellinject.getPage" fullword ascii /* score: '37.00'*/
      $x7 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatch" ascii /* score: '36.50'*/
      $x8 = "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Configx509: invalid signature: parent certificate cann" ascii /* score: '36.50'*/
      $x9 = " using %03d %s%s %s; , TTL: , goid=, j0 = /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625::1/128:method:scheme:s" ascii /* score: '35.50'*/
      $x10 = "%s overflows int+-/0123456789.eE, not a function.WithValue(type /etc/resolv.conf0123456789ABCDEF0123456789abcdef2384185791015625" ascii /* score: '33.00'*/
      $s11 = "lmultihop attemptednegative bit indexno child processesno locks availablenon-minimal lengthoperation canceledproxy-authenticater" ascii /* score: '29.00'*/
      $s12 = "ative countcheckdead: runnable gcommand not supportedconcurrent map writesdecompression failuredefer on system stackexec: alread" ascii /* score: '26.00'*/
      $s13 = "ing{exec: StdinPipe after process startedexplicitly tagged member didn't matchfailed to reserve page summary memorygob NewTypeOb" ascii /* score: '26.00'*/
      $s14 = "fsetSeek: invalid whenceSquareSupersetEqual;Terminal_PunctuationUnprocessable Entity__vdso_clock_gettimeasn1: syntax error: bad " ascii /* score: '23.00'*/
      $s15 = "github.com/DeimosC2/DeimosC2/agents/resources/selfdestruction/kill_linux.go" fullword ascii /* score: '22.00'*/
      $s16 = "github.com/DeimosC2/DeimosC2/agents/resources/filebrowser/filebrowser_linux.go" fullword ascii /* score: '22.00'*/
      $s17 = "github.com/DeimosC2/DeimosC2/agents/resources/fingerprint/fingerprint_linux.go" fullword ascii /* score: '22.00'*/
      $s18 = "ine too longhtml/template:%s: %shttp2: stream closedhttp: POST too largeif/with can't use %vindex of nil pointerindex of untyped" ascii /* score: '20.50'*/
      $s19 = "github.com/DeimosC2/DeimosC2/lib/privileges/isadmin_linux.go" fullword ascii /* score: '20.00'*/
      $s20 = "SOAResource.MBoxSRVResource bodyShortRightArrow;TXTResource bodyUpgrade RequiredUpperRightArrow;User-Agent: %s" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_12 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash4 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash5 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash6 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "sync/atomic: store of inconsistently typed value into Valuesync: WaitGroup is reused before previous Wait has returnedtls: serve" ascii /* score: '24.50'*/
      $s2 = "er: missing status pseudo headernet/http: server response headers exceeded %d bytes; abortedrpc.Register: return type of method " ascii /* score: '15.00'*/
      $s3 = "net/http.(*Client).Get" fullword ascii /* score: '15.00'*/
      $s4 = "command-line-arguments/HTTPS_agent.go" fullword ascii /* score: '15.00'*/
      $s5 = "net/http.stripPassword" fullword ascii /* score: '15.00'*/
      $s6 = "s*struct { F uintptr; c *http.Client; icookies map[string][]*http.Cookie; ireqhdr http.Header; preq **http.Request }" fullword ascii /* score: '15.00'*/
      $s7 = "*map.hdr[string][]*http.Cookie" fullword ascii /* score: '13.00'*/
      $s8 = "*func(*url.URL) []*http.Cookie" fullword ascii /* score: '13.00'*/
      $s9 = "net/http.shouldCopyHeaderOnRedirect" fullword ascii /* score: '12.00'*/
      $s10 = "net/http.Post" fullword ascii /* score: '12.00'*/
      $s11 = "net/http.(*Client).Head" fullword ascii /* score: '12.00'*/
      $s12 = "net/http.(*Client).makeHeadersCopier.func1" fullword ascii /* score: '12.00'*/
      $s13 = "net/http.(*Client).PostForm" fullword ascii /* score: '12.00'*/
      $s14 = "net/http.(*Client).makeHeadersCopier" fullword ascii /* score: '12.00'*/
      $s15 = "net/http.(*Client).Post" fullword ascii /* score: '12.00'*/
      $s16 = "net/http.cloneOrMakeHeader" fullword ascii /* score: '12.00'*/
      $s17 = "icookies" fullword ascii /* score: '11.00'*/
      $s18 = "8*func(string, string, io.Reader) (*http.Response, error)" fullword ascii /* score: '10.00'*/
      $s19 = "*[8][]*http.Cookie" fullword ascii /* score: '10.00'*/
      $s20 = "*[][]*http.Cookie" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_13 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash5 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $x1 = "github.com/DeimosC2/DeimosC2/agents/resources/shellinject.ShellInject" fullword ascii /* score: '37.00'*/
      $x2 = "github.com/DeimosC2/DeimosC2/agents/resources/shellexec.ShellExecute" fullword ascii /* score: '36.00'*/
      $s3 = "github.com/DeimosC2/DeimosC2/lib/privileges.AdminOrElevated" fullword ascii /* score: '29.00'*/
      $s4 = "github.com/DeimosC2/DeimosC2/lib/crypto.EncryptWithPublicKey" fullword ascii /* score: '28.00'*/
      $s5 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.Download" fullword ascii /* score: '28.00'*/
      $s6 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.Shell" fullword ascii /* score: '27.00'*/
      $s7 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.Upload" fullword ascii /* score: '24.00'*/
      $s8 = "runtime:greyobject: checkmarks finds unexpected unmarked object obj=unpad error. This could happen when incorrect encryption key" ascii /* score: '23.50'*/
      $s9 = "github.com/DeimosC2/DeimosC2/lib/crypto.BytesToPublicKey" fullword ascii /* score: '23.00'*/
      $s10 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.ErrHandling" fullword ascii /* score: '22.00'*/
      $s11 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.AgentFileBrowsers" fullword ascii /* score: '22.00'*/
      $s12 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.ShouldIDie" fullword ascii /* score: '22.00'*/
      $s13 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.SleepDelay" fullword ascii /* score: '22.00'*/
      $s14 = "github.com/DeimosC2/DeimosC2/lib/logging.init" fullword ascii /* score: '22.00'*/
      $s15 = "github.com/DeimosC2/DeimosC2/lib/logging/log.go" fullword ascii /* score: '22.00'*/
      $s16 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.KillNetList" fullword ascii /* score: '22.00'*/
      $s17 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.init" fullword ascii /* score: '22.00'*/
      $s18 = "github.com/DeimosC2/DeimosC2/agents/resources/selfdestruction.SelfDelete" fullword ascii /* score: '22.00'*/
      $s19 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions.Kill" fullword ascii /* score: '22.00'*/
      $s20 = "github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions/functions.go" fullword ascii /* score: '22.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_14 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $x1 = "CreateSymbolicLinkWCryptAcquireContextCryptReleaseContextDownRightTeeVector;DownRightVectorBar;Egypt Standard TimeGetCurrentProc" ascii /* score: '34.00'*/
      $s2 = "&#9;&gt;&lt;'\\''(?:)(\"'/) = ) m=+Inf+inf, n -Inf-inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml0x%x10803125: p=<%s>AC" ascii /* score: '29.00'*/
      $s3 = "ghtharpoons;len of nil pointerlen of untyped nilmultihop attemptednegative bit indexno child processesno locks availablenon-mini" ascii /* score: '22.00'*/
      $s4 = "stack=[acceptexaddress alefsym;angrtvb;angzarr;asympeq;autoplaybacksim;beEfFgGvbecause;bemptyv;between;bigcirc;bigodot;bigstar;b" ascii /* score: '22.00'*/
      $s5 = "_cgo_thread_start missing_html_template_cssescaper_html_template_urlescaperallgadd: bad status Gidlearena already initializedbad" ascii /* score: '18.00'*/
      $s6 = "TUUUUUUUU" fullword ascii /* reversed goodware string 'UUUUUUUUT' */ /* score: '16.50'*/
      $s7 = " H_T= H_a= H_g= MB,  W_a= and  cnt= h_a= h_g= h_t= max= not  ptr  siz= tab= top= u_a= u_g=%s %q%s*%d%s=%s&#10;&#11;&#12;&#13;&#3" ascii /* score: '16.00'*/
      $s8 = "after object keyapplication/wasmbad SAN sequencebad frame layoutbad g transitionbad special kindbad summary databad symbol table" ascii /* score: '16.00'*/
      $s9 = " faultsequence truncatedstreams pipe errorsystem page size (text/javascript1.0text/javascript1.1text/javascript1.2text/javascrip" ascii /* score: '15.00'*/
      $s10 = "bad Content-Lengthbad lfnode addressbad manualFreeListblacktriangledown;blacktriangleleft;bufio: buffer fullcleantimers: bad pco" ascii /* score: '14.00'*/
      $s11 = "ENG;ETH;Ecy;Efr;Eta;EtagEumlFcy;Ffr;FromGOGCGcy;Gfr;GoneHEADHat;Hfr;HostIMAGIcy;Ifr;Int;IumlJcy;Jfr;JulyJuneKcy;Kfr;Lcy;Lfr;Lisu" ascii /* score: '14.00'*/
      $s12 = " status in shrinkstackbad system huge page sizebootstrap type wrong id: can't evaluate command %qcan't print %s of type %schanse" ascii /* score: '14.00'*/
      $s13 = ": no such fileidentifier removedin numeric literalindex out of rangeinput/output errorinvalid IP addressinvalid character leftri" ascii /* score: '13.00'*/
      $s14 = ";DZcy;Darr;DograDopf;Dscr;ECDSAEcircEdot;Eopf;ErrorEscr;Esim;Euml;FLOATFopf;FoundFscr;GJcy;Gdot;Gopf;GreekGscr;HTTP/Hopf;Hscr;ID" ascii /* score: '12.00'*/
      $s15 = "mal lengthoperation canceledproxy-authenticatereflect.Value.Callreflect.Value.Elemreflect.Value.Sendreflect.Value.Typereflect.Va" ascii /* score: '11.00'*/
      $s16 = "_cgo_thread_start missing_html_template_cssescaper_html_template_urlescaperallgadd: bad status Gidlearena already initializedbad" ascii /* score: '10.00'*/
      $s17 = "lue.Uintreflect: Zero(nil)rightleftharpoons;rpc.Serve: accept:runtime.semacreateruntime.semawakeupruntime: npages = segmentation" ascii /* score: '10.00'*/
      $s18 = "Lsh;Map;Mcy;Mfr;MiaoModiNZDTNZSTNcy;NewaNfr;Not;Ocy;Ofr;OumlPINGPOSTPcy;Pfr;Phi;Psi;QUOTQfr;REG;Rcy;Rfr;Rho;Rsh;SASTScy;Sfr;Stat" ascii /* score: '9.00'*/
      $s19 = "acket;RightDownTeeVector;RightDownVectorBar;RightTriangleEqual;Russia Time Zone 10Russia Time Zone 11Samoa Standard TimeService " ascii /* score: '7.00'*/
      $s20 = "nnection refusedcontext.Backgrounddecoding error: %velem align too bigfile name too longforEachP: not donegarbage collectionhttp" ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_15 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $x1 = "entersyscalleqslantless;exit status expectation;gcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii /* score: '60.00'*/
      $x2 = "(unknown)+infinity, newval=, oldval=, size = -infinity01234567_244140625: status=<a href=\"Accuracy(AuthorityBassa_VahBhaiksukiC" ascii /* score: '48.00'*/
      $x3 = "tls: client certificate used with invalid signature algorithmtls: server sent a ServerHello extension forbidden in TLS 1.3tls: u" ascii /* score: '40.50'*/
      $x4 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii /* score: '40.50'*/
      $x5 = "_eval_args_alarm clockbad addressbad m valuebad messagebad timedivbad verb '%broken pipecall of nilcgocall nilcircledast;clobber" ascii /* score: '38.00'*/
      $x6 = ".WithDeadline(.in-addr.arpa.1907348632812595367431640625: extra text: <not Stringer>Accept-CharsetApplyFunction;CertCloseStoreCo" ascii /* score: '38.00'*/
      $s7 = "kCount64GetUserNameExWINTERNAL_ERRORIsWellKnownSidIsWow64ProcessLeftTeeVector;LeftVectorBar;LessFullEqual;LoadLibraryExWLongLeft" ascii /* score: '26.00'*/
      $s8 = " gcwaiting= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock,  nBSSRoots= p->mcache= p->status= s.nelems=  schedt" ascii /* score: '25.00'*/
      $s9 = "pc= throwing= until pc=%!Weekday(%s|%s%s|%s, bound = , limit = /debug/rpc/dev/stdin012345678912207031256103515625: parsing :auth" ascii /* score: '23.50'*/
      $s10 = "panDeadmSpanFreemap[%s]%smapstoup;maxlengthmulticastmultimap;naturals;ncongdot;nil errornotindot;ntdll.dllole32.dllomitemptyotim" ascii /* score: '22.00'*/
      $s11 = "try-afterrightarrow;rmoustache;runtime: P runtime: p scheddetailsecur32.dllshell32.dllshort writesqsubseteq;sqsupseteq;subsetneq" ascii /* score: '20.00'*/
      $s12 = "tShareDelNew_Tai_LueNotElement;NotGreater;Old_PersianOld_SogdianOpenProcessPRIVATE KEYPau_Cin_HauProportion;RegCloseKeyReturn-Pa" ascii /* score: '18.00'*/
      $s13 = "ntegerexchange fullexponentiale;fatal error: getTypeInfo: gethostbynamegetservbynamegzip, deflatehttp2client=0if-none-matchimage" ascii /* score: '17.00'*/
      $s14 = "Gen bad map stateblacklozenge;cache-controlcontent-rangedalTLDpSugct?debugCall2048define clauseemail addressempty commandempty i" ascii /* score: '16.00'*/
      $s15 = " ] = (acircacuteaeligallowandd;andv;ange;aopf;apid;apos;argp=aringarrayascr;asyncattr(auml;bNot;bad nbbrk;beta;beth;blockbnot;bo" ascii /* score: '16.00'*/
      $s16 = "thRightArrow;RightFloor;Rightarrow;SYSTEMROOT=SetFileTimeSignWritingSoft_DottedTESTING KEYTTL expiredThickSpace;TildeEqual;Tilde" ascii /* score: '15.00'*/
      $s17 = "thornthrowtimestint;titletls: toea;topf;tosa;trie;tscr;tscy;uArr;uHar;uarr;ucircuint8uopf;upsi;usageuscr;utf-8utri;uuml;vArr;vBa" ascii /* score: '14.00'*/
      $s18 = "lde;OpenSCManagerWOther_ID_StartPROTOCOL_ERRORPattern_SyntaxPoincareplane;PrecedesEqual;PrecedesTilde;Process32NextWQuotation_Ma" ascii /* score: '14.00'*/
      $s19 = "Arrow;Longleftarrow;MAX_FRAME_SIZEMB; allocated MakeAbsoluteSDNetUserGetInfoNot AcceptableNotEqualTilde;NotTildeEqual;NotTildeTi" ascii /* score: '14.00'*/
      $s20 = "esas;panicwaitparallel;pclmulqdqplusacir;pointint;precneqq;precnsim;preemptedprofalar;profline;profsurf;protocol psapi.dllraempt" ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_16 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash4 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash5 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash6 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash7 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash8 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash9 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "p2: Framer %p: read %vhttp2: invalid header: %vhttp2: unsupported schemeillegal number syntax: %qinconsistent poll.fdMutexinvali" ascii /* score: '28.50'*/
      $s2 = "am counter: http2: Framer %p: failed to decode just-written framehttp2: Transport failed to get client conn for %s: %vhttp: putI" ascii /* score: '22.50'*/
      $s3 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthtml/template:%s:%d: %shttp2: handle" ascii /* score: '20.50'*/
      $s4 = "s %q: %vinvalid runtime symbol tableinvalid slice index: %d > %djson: Unmarshal(non-pointer malformed MIME header line: mheap.fr" ascii /* score: '17.50'*/
      $s5 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncomparable type %s: %vunexpected %s in operandunexpect" ascii /* score: '17.50'*/
      $s6 = "eeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockedmultipart: boundary is emptymultipart: message too l" ascii /* score: '17.00'*/
      $s7 = ": no Host in request URLhttp: request body too largeinvalid byte in chunk lengthinvalid header field name %qinvalid proxy addres" ascii /* score: '17.00'*/
      $s8 = "runtime.getproccount" fullword ascii /* score: '15.00'*/
      $s9 = "d cross-device linkinvalid network interfaceinvalid object identifierinvalid username/passwordjson: Unexpected key typejson: uns" ascii /* score: '15.00'*/
      $s10 = "ate key (use ParseECPrivateKey instead for this key format) has no exported methods of suitable type (hint: pass a pointer to va" ascii /* score: '13.00'*/
      $s11 = "constraints but leaf contains unknown or unconstrained name: x509: signature algorithm specifies an %s public key, but have publ" ascii /* score: '13.00'*/
      $s12 = "remote I/O errorrightleftarrows;rightsquigarrow;rightthreetimes;runtime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '13.00'*/
      $s13 = "boxvr;breve;brvbarbsemi;bsime;bsolb;bumpE;bumpe;caret;caron;ccaps;ccedilccirc;ccups;cedil;chan<-check;closedclubs;colon;comma;co" ascii /* score: '11.00'*/
      $s14 = "runtime.LockOSThread" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.UnlockOSThread" fullword ascii /* score: '10.00'*/
      $s16 = "jackedhttp: persistConn.readLoop exitinghttp: read on closed response bodyillegal base64 data at input byte in \\u hexadecimal c" ascii /* score: '10.00'*/
      $s17 = "runtime.exitThread" fullword ascii /* score: '10.00'*/
      $s18 = "runtime.stackcheck" fullword ascii /* score: '10.00'*/
      $s19 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=proxy-connectionquoted-printablereflect mismatch" ascii /* score: '10.00'*/
      $s20 = "l;dharr;diams;disin;dividedomaindoteq;dtdot;dtrif;duarr;duhar;eDDot;eacuteecirc;efDot;efenceegraveemacr;empty;eogon;eplus;epsiv;" ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_17 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '79.50'*/
      $s2 = " contexts: %v, %v%s has arguments but cannot be invoked as functionFloat.GobDecode: encoding version %d not supportedattempt to " ascii /* score: '28.50'*/
      $s3 = "d unrequested ALPN extensiontls: server sent a cookie in a normal ServerHellox509: Ed25519 key encoded with illegal parametersx5" ascii /* score: '27.00'*/
      $s4 = "tls: server changed cipher suite after a HelloRetryRequesturlPartNoneurlPartPreQueryurlPartQueryOrFragurlPartUnknownRoundTripper" ascii /* score: '26.00'*/
      $s5 = "execute system stack code on user stackcrypto/cipher: incorrect nonce length given to GCMcryptobyte: attempted write while child" ascii /* score: '24.00'*/
      $s6 = "failed to parseInt.GobDecode: encoding version %d not supportedRat.GobDecode: encoding version %d not supportedTime.MarshalJSON:" ascii /* score: '20.00'*/
      $s7 = "request body closed due to handler exitinghttp: wrote more than the declared Content-Lengthinvalid memory address or nil pointer" ascii /* score: '17.00'*/
      $s8 = "otedelimSingleQuotedelimSpaceOrTagEndhtml/template internal error: template escaping out of synchttp2: Transport received Server" ascii /* score: '16.00'*/
      $s9 = "fertransport endpoint is not connectedunclosed right paren: unexpected %sunsigned integer overflow on token x509: decryption pas" ascii /* score: '15.00'*/
      $s10 = "ientHellotls: client offered only unsupported versions: %xtls: client using inappropriate protocol fallbacktls: server advertise" ascii /* score: '15.00'*/
      $s11 = "sword incorrectx509: wrong Ed25519 public key size LastStreamID=%v ErrCode=%v Debug=%q%s is not a method but has arguments) is l" ascii /* score: '14.00'*/
      $s12 = " dereferenceinvalid or incomplete multibyte or wide characternet/http: Transport.Dial hook returned (nil, nil)panicwrap: unexpec" ascii /* score: '13.00'*/
      $s13 = "09: private key contains zero or negative primex509: private key contains zero or negative value{{%s}} branches end in different" ascii /* score: '13.00'*/
      $s14 = "alid string length %d: exceeds input size %dinvalid type name length %d: exceeds input sizeprotocol error: received DATA on a HE" ascii /* score: '12.50'*/
      $s15 = "chtls: server selected TLS 1.3 in a renegotiationtls: server sent two HelloRetryRequest messagesx509: internal error: IP SAN %x " ascii /* score: '12.00'*/
      $s16 = "509: trailing data after X.509 BasicConstraintsx509: trailing data after X.509 ExtendedKeyUsagex509: trailing data after X.509 a" ascii /* score: '12.00'*/
      $s17 = "too few input argumentsslice bounds out of range [::%x] with length %ytemplate: %q is an incomplete or empty templatetls: handsh" ascii /* score: '11.00'*/
      $s18 = "ake did not verify certificate chaintls: incorrect renegotiation extension contentstls: internal error: pskBinders length mismat" ascii /* score: '11.00'*/
      $s19 = "h hex stringexpected unsigned integer; found %sfile type does not support deadlinefindfunc: bad findfunctab entry idxfindrunnabl" ascii /* score: '10.00'*/
      $s20 = "dshake completetls: CurvePreferences includes unsupported curvex509: IP constraint contained value of length %dx509: internal er" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949_18 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash3 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '90.50'*/
      $s2 = "ls: server sent a cookie in a normal ServerHellox509: Ed25519 key encoded with illegal parametersx509: private key contains zero" ascii /* score: '30.00'*/
      $s3 = "ents but cannot be invoked as functionFloat.GobDecode: encoding version %d not supportedattempt to execute system stack code on " ascii /* score: '30.00'*/
      $s4 = "ayruntime.reflect_makemap: unsupported map key typeruntime: unexpected waitm - semaphore out of syncs.allocCount != s.nelems && " ascii /* score: '24.00'*/
      $s5 = "cursive call during initialization - linker skewreflect.Value.Slice3: slice of unaddressable arrayruntime: GetQueuedCompletionSt" ascii /* score: '22.00'*/
      $s6 = "late: cannot Clone %q after it has executedhttp2: Transport readFrame error on conn %p: (%T) %vhttp: method cannot contain a Con" ascii /* score: '20.50'*/
      $s7 = "n %d not supportedRat.GobDecode: encoding version %d not supportedTime.MarshalJSON: year outside of range [0,9999]Time.MarshalTe" ascii /* score: '20.00'*/
      $s8 = "erlapping in-use allocations detectedprotocol error: received %T before a SETTINGS frameruntime: netpoll: PostQueuedCompletionSt" ascii /* score: '20.00'*/
      $s9 = " or negative primex509: private key contains zero or negative value{{%s}} branches end in different contexts: %v, %v%s has argum" ascii /* score: '19.50'*/
      $s10 = "port connection broken: %vnet/http: Transport failed to read from server: %vnet/http: invalid header field value %q for key %vre" ascii /* score: '18.00'*/
      $s11 = "rrect renegotiation extension contentstls: internal error: pskBinders length mismatchtls: server selected TLS 1.3 in a renegotia" ascii /* score: '15.00'*/
      $s12 = "ed goroutinehtml/template: no files named in call to ParseFileshttp2: invalid Transfer-Encoding request header: %qpotentially ov" ascii /* score: '15.00'*/
      $s13 = "9 BasicConstraintsx509: trailing data after X.509 ExtendedKeyUsagex509: trailing data after X.509 authority key-id (Client.Timeo" ascii /* score: '15.00'*/
      $s14 = "ositive numberx509: missing ASN.1 contents; use ParseCertificateJSON decoder out of sync - data changing underfoot?ScanState's R" ascii /* score: '15.00'*/
      $s15 = "tiontls: server sent two HelloRetryRequest messagesx509: internal error: IP SAN %x failed to parseInt.GobDecode: encoding versio" ascii /* score: '14.00'*/
      $s16 = "user stackcrypto/cipher: incorrect nonce length given to GCMcryptobyte: attempted write while child is pendinggot CONTINUATION f" ascii /* score: '14.00'*/
      $s17 = "atus failedtls: VerifyHostname called on TLS server connectiontls: server selected unsupported compression formattls: server's i" ascii /* score: '14.00'*/
      $s18 = "atus failed (errno= runtime: unable to acquire - semaphore out of synctls: invalid signature by the client certificate: tls: inv" ascii /* score: '14.00'*/
      $s19 = "me.SetFinalizer: pointer not in allocated blockruntime: GetQueuedCompletionStatusEx failed (errno= runtime: use of FixAlloc_Allo" ascii /* score: '14.00'*/
      $s20 = "tent-Length; got %qmath/big: cannot unmarshal %q into a *big.Float (%v)protocol error: received DATA before a HEADERS framerunti" ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_19 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $x1 = "AElig;AacuteAcceptAcirc;AgraveAlpha;Amacr;AnswerAogon;ArabicAring;AtildeAugustBasic BrahmiBreve;CANCELCarianCcedilCcirc;ChakmaCo" ascii /* score: '38.50'*/
      $x2 = " using %03d %s%s %s; , goid=, j0 = 19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625:method:scheme:statusAacute;Abreve;Ag" ascii /* score: '34.50'*/
      $s3 = "value=aacute;abortedabreve;agrave;andand;angmsd;angsph;apacir;approx;archiveatilde;barvee;barwed;bdoUxXvbecaus;bernou;bigcap;big" ascii /* score: '27.00'*/
      $s4 = "strns;structsubnE;subne;supnE;supne;swArr;swarr;sweep switchszlig;targettelnettheta;thkap;thorn;tilde;times;token(trade;trisb;ts" ascii /* score: '22.00'*/
      $s5 = "&#9;&gt;&lt;'\\''(?:)(\"'/) = ) m=+Inf+inf, n -Inf-inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml0x%x10803125: p=<%s>AC" ascii /* score: '20.00'*/
      $s6 = "--] = ] n=acE;acd;acy;afr;amp;and;ang;apE;ape;asn1ast;aumlavx2basebcy;bfr;bindbmi1bmi2bne;boolbot;callcap;cas1cas2cas3cas4cas5ca" ascii /* score: '19.00'*/
      $s7 = "riableWGetLogicalDriveStringsWGetSidSubAuthorityCountGetSystemTimeAsFileTimeGreenland Standard TimeGreenwich Standard TimeLogica" ascii /* score: '16.00'*/
      $s8 = "xlArr;xlarr;xodot;xrArr;xrarr;xutri;yacuteycirc; %v=%v, (conn) (scan  (scan) MB in  Value> dying= flags= len=%d locks= m->g0= nm" ascii /* score: '15.50'*/
      $s9 = "arr;rsquo;rtrie;rtrif;sbquo;sccue;scirc;scnap;scopedscriptscsim;sdotb;sdote;seArr;searr;secondselectsendtoserversetmn;sharp;sigm" ascii /* score: '15.00'*/
      $s10 = "dGODEBUGGammad;Gbreve;Gcedil;GranthaHARDcy;HEADERSHanunooHstrok;ILLEGALIM UsedIO waitIacute;Igrave;Itilde;JanuaryJsercy;KannadaK" ascii /* score: '14.00'*/
      $s11 = "CertEnumCertificatesInStoreDATA frame with stream ID 0Easter Island Standard TimeG waiting list is corruptedGetSecurityDescripto" ascii /* score: '14.00'*/
      $s12 = "t;openord;ordfordmorv;oumlpar;parapathpcy;pfr;phi;pipepiv;pop3prE;pre;psi;qfr;quitquotrcy;readreg;rfr;rho;rlm;rowsrpc:rsh;sbrksc" ascii /* score: '13.00'*/
      $s13 = "*.*/*=+++-+=, - ---=->._/*///=00010X0b0o0s0x2580: :=; <-<<<==#==> >=>>A3A4CNCcCfCoCsGTLTLlLmLoLtLuMcMeMnNdNlNoOKOUPcPdPePfPiPoPs" ascii /* score: '12.00'*/
      $s14 = "*.*/*=+++-+=, - ---=->._/*///=00010X0b0o0s0x2580: :=; <-<<<==#==> >=>>A3A4CNCcCfCoCsGTLTLlLmLoLtLuMcMeMnNdNlNoOKOUPcPdPePfPiPoPs" ascii /* score: '12.00'*/
      $s15 = "ard TimeAfghanistan Standard TimeClockwiseContourIntegral;Content-Transfer-EncodingDoubleLongLeftRightArrow;ExpandEnvironmentStr" ascii /* score: '9.00'*/
      $s16 = "Arr;nwarr;oacuteobjectocirc;odash;oelig;ofcir;ograveohbar;olarr;olcir;oline;omacr;omega;operp;oplus;orarr;order;oslashotildeovba" ascii /* score: '9.00'*/
      $s17 = "E;sce;scy;sectseeksfr;shy;sim;sizesmt;smtpsol;spansqu;sse2sse3stepsub;sum;sup1sup2sup3sup;synctag:tau;tcp4tcp6tcy;tfr;top;truety" ascii /* score: '9.00'*/
      $s18 = "hcy;twixt;typeofuacuteubrcy;ucirc;udarr;udhar;ugraveuharl;uharr;uhblk;uint16uint32uint64ultri;umacr;unuseduogon;uplus;upsih;urin" ascii /* score: '9.00'*/
      $s19 = "l_Order_ExceptionLord Howe Standard TimeMB during sweep; swept Marquesas Standard TimeMauritius Standard TimeNoncharacter_Code_P" ascii /* score: '9.00'*/
      $s20 = "r;parsl;phone;plusb;pluse;plusmnpopcntposterpound;prcue;prime;printfprnap;prsim;quest;rAarr;rBarr;radic;rangd;range;raquo;rarrb;" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322_20 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "N,M,NBMSNdMDNmM,N" fullword ascii /* score: '4.00'*/
      $s2 = "MONeM)NBMSN{M" fullword ascii /* score: '4.00'*/
      $s3 = "NIMSN/M)N#M&N" fullword ascii /* score: '4.00'*/
      $s4 = "M$NYMSNmM)N<MJN" fullword ascii /* score: '4.00'*/
      $s5 = "MsNlMJN!MsN8M2N" fullword ascii /* score: '4.00'*/
      $s6 = "M8N8M,N" fullword ascii /* score: '1.00'*/
      $s7 = "M2N4M,N<M,N" fullword ascii /* score: '1.00'*/
      $s8 = "M;NRM,N;M,N" fullword ascii /* score: '1.00'*/
      $s9 = "M)N8M\"N" fullword ascii /* score: '1.00'*/
      $s10 = "M,NEMSN" fullword ascii /* score: '1.00'*/
      $s11 = "P!O!P&OsP" fullword ascii /* score: '1.00'*/
      $s12 = "M)NDMJN" fullword ascii /* score: '1.00'*/
      $s13 = ";C2P2O)P" fullword ascii /* score: '1.00'*/
      $s14 = "NmM)N0M&N" fullword ascii /* score: '1.00'*/
      $s15 = "M;N`M8N" fullword ascii /* score: '1.00'*/
      $s16 = "MM,N8MPN4MDN_M" fullword ascii /* score: '1.00'*/
      $s17 = "M9N!M,N@MDN" fullword ascii /* score: '1.00'*/
      $s18 = "M,N,M,N" fullword ascii /* score: '1.00'*/
      $s19 = "[%\\D[,\\q[Q\\" fullword ascii /* score: '1.00'*/
      $s20 = "CO\"PKO)P" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4_21 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $x1 = "runtime: GetQueuedCompletionStatus returned invalid mode= tls: server changed cipher suite after a HelloRetryRequesturlPartNoneu" ascii /* score: '34.00'*/
      $s2 = "&#9;&gt;&lt;'\\''(?:)(\"'/) = ) m=+Inf+inf, n -Inf-inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml0x%x10803125: p=<%s>AC" ascii /* score: '29.00'*/
      $s3 = "rflow on token x509: decryption password incorrectx509: wrong Ed25519 public key size LastStreamID=%v ErrCode=%v Debug=%q%s is n" ascii /* score: '24.00'*/
      $s4 = "oCompletionPortDEBUG_HTTP2_GOROUTINESDateline Standard TimeDoubleContourIntegral;FilledVerySmallSquare;Georgian Standard TimeGet" ascii /* score: '18.00'*/
      $s5 = "to/sha1: invalid hash state sizecrypto/sha512: invalid hash functionexceeded maximum template depth (%v)expected an ECDSA public" ascii /* score: '17.00'*/
      $s6 = " field %SystemRoot%\\system32\\/lib/time/zoneinfo.zip0123456789aAbBcCdDeEfF4656612873077392578125Aleutian Standard TimeAtlantic " ascii /* score: '16.00'*/
      $s7 = "EnvironmentStringsWGetTimeZoneInformationHawaiian Standard TimeInscriptional_ParthianInt.Scan: invalid verbMAX_CONCURRENT_STREAM" ascii /* score: '16.00'*/
      $s8 = "tedelimSingleQuotedelimSpaceOrTagEndhtml/template internal error: template escaping out of synchttp2: Transport received Server'" ascii /* score: '16.00'*/
      $s9 = "d status in shrinkstackbad system huge page sizebootstrap type wrong id: can't evaluate command %qcan't print %s of type %schans" ascii /* score: '14.00'*/
      $s10 = "nd in %PATH%expected unsigned integer; found %sfile type does not support deadlinefindfunc: bad findfunctab entry idxfindrunnabl" ascii /* score: '14.00'*/
      $s11 = "has been severednegative shift amountpackage not installedpanic on system stackread-only file systemreflect.Value.Complexreflect" ascii /* score: '14.00'*/
      $s12 = " Contextunrecognized option: unsupported extensionuser defined signal 1user defined signal 2x509: invalid padding into Go struct" ascii /* score: '12.00'*/
      $s13 = "dynamic table size update too largeed25519: cannot sign hashed messageencoding/hex: odd length hex stringexecutable file not fou" ascii /* score: '11.00'*/
      $s14 = "elytransform: short destination buffertransport endpoint is not connectedunclosed right paren: unexpected %sunsigned integer ove" ascii /* score: '10.00'*/
      $s15 = " read deadlinestrings.Reader.Seek: invalid whencesuperfluous leading zeros in lengthtls: invalid or missing PSK binderstls: serv" ascii /* score: '10.00'*/
      $s16 = "DSA-SHA1DecemberDiamond;DownTee;DuployanElement;Epsilon;EqualSidEthiopicExtenderFebruaryFullPathGeorgianGoStringGujaratiGurmukhi" ascii /* score: '9.00'*/
      $s17 = "Map;Mcy;Mfr;MiaoModiNZDTNZSTNcy;NewaNfr;Not;Ocy;Ofr;OumlPINGPOSTPcy;Pfr;Phi;Psi;QUOTQfr;REG;Rcy;Rfr;Rho;Rsh;SASTScy;Sfr;StatSub;" ascii /* score: '9.00'*/
      $s18 = "ENG;ETH;Ecy;Efr;Eta;EtagEumlFcy;Ffr;FromGOGCGcy;Gfr;GoneHat;Hfr;HostIMAGIcy;Ifr;Int;IumlJcy;Jfr;JulyJuneKcy;Kfr;Lcy;Lfr;LisuLsh;" ascii /* score: '9.00'*/
      $s19 = "perpc: server cannot decode request: runtime: close polldesc w/o unblockruntime: createevent failed; errno=runtime: inconsistent" ascii /* score: '8.00'*/
      $s20 = "searchIdx = runtime: work.nwait= sequence tag mismatchset bit is not 0 or 1stale NFS file handlestartlockedm: m has pstartm: m i" ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_22 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash5 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash6 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash7 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "tus pseudo headernet/http: server replied with more than declared Content-Length; truncatedtls: certificate RSA key size too sma" ascii /* score: '21.00'*/
      $s2 = "ecoded from remote interface type; received concrete type client doesn't support any cipher suites compatible with the certifica" ascii /* score: '18.00'*/
      $s3 = "128 array or slice: length exceeds input size (%d elements)tls: internal error: attempted to read record with pending applicatio" ascii /* score: '16.00'*/
      $s4 = "os.executable" fullword ascii /* score: '16.00'*/
      $s5 = "ll for supported signature algorithmsUnsolicited response received on idle HTTP channel starting with %q; err=%vdecoding complex" ascii /* score: '15.50'*/
      $s6 = "runtime.getPageSize" fullword ascii /* score: '15.00'*/
      $s7 = "o heap (incorrect use of unsafe or cgo?)http2: request header list larger than peer's advertised limitruntime: internal error: m" ascii /* score: '15.00'*/
      $s8 = "ed handshake message of type %T when waiting for %Tbytes.Buffer: UnreadRune: previous operation was not a successful ReadRunedec" ascii /* score: '12.00'*/
      $s9 = "e (%d elements)dynamic table size update MUST occur at the beginning of a header blockjson: invalid use of ,string struct tag, t" ascii /* score: '12.00'*/
      $s10 = "315ececbb6406837bf51f55ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b6b17d1f2e12c4247f8bce6e563a440f277037d812d" ascii /* score: '11.00'*/
      $s11 = " type %scan't handle %s for arg of type %schacha20: wrong HChaCha20 key sizeconnection doesn't support Ed25519crypto/aes: invali" ascii /* score: '11.00'*/
      $s12 = "runtime.semawakeup" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.semasleep" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.semacreate" fullword ascii /* score: '10.00'*/
      $s15 = "oding complex64 array or slice: length exceeds input size (%d elements)malformed response from server: malformed non-numeric sta" ascii /* score: '10.00'*/
      $s16 = "lice: length exceeds input size (%d elements)got %s for stream %d; expected CONTINUATION following %s for stream %ddecoding stri" ascii /* score: '9.50'*/
      $s17 = "cated a fixed-size bufferelementNoneelementScriptelementStyleelementTextareaelementTitlehttp2: push would exceed peer's SETTINGS" ascii /* score: '9.00'*/
      $s18 = "size (%d elements)decoding uintptr array or slice: length exceeds input size (%d elements)tls: certificate private key of type %" ascii /* score: '9.00'*/
      $s19 = "isuse of lockOSThread/unlockOSThreadstrings.Reader.UnreadRune: previous operation was not ReadRunetls: certificate cannot be use" ascii /* score: '8.00'*/
      $s20 = "rying to unmarshal %q into %vtls: peer doesn't support any of the certificate's signature algorithmstoo many concurrent operatio" ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_23 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '58.00'*/
      $x2 = "Already ReportedCloseCurlyQuote;Content-EncodingContent-LanguageContent-Length: ContourIntegral;CreateDirectoryWCreateJobObjectW" ascii /* score: '37.00'*/
      $s3 = "onsoleCPGetLastErrorGetLengthSidGetProcessIdGetStdHandleGetTempPathWGreaterLess;I'm a teapotJoin_ControlLeftCeiling;LessGreater;" ascii /* score: '30.00'*/
      $s4 = "ShortRightArrow;TerminateProcessUpgrade RequiredUpperRightArrow;User-Agent: %s" fullword ascii /* score: '28.00'*/
      $s5 = "oportional;RegDeleteKeyWRegEnumKeyExWRegEnumValueWRegOpenKeyExWReset ContentRightCeiling;RoundImplies;RoundingMode(RtlGetVersion" ascii /* score: '27.00'*/
      $s6 = "TypeCookie.ValueCreateEventWCreateMutexWDES-EDE3-CBCECDSA-SHA256ECDSA-SHA384ECDSA-SHA512Equilibrium;FindNextFileGetAddrInfoWGetC" ascii /* score: '26.00'*/
      $s7 = "SHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSSSTREAM_CLOSEDShellExecuteWShortUpArrow;SquareSubset;StartServiceWThread32FirstUnderBracke" ascii /* score: '24.00'*/
      $s8 = "close notifycontent-typecontext.TODOcurlyeqprec;curlyeqsucc;diamondsuit;dumping heapend tracegc" fullword ascii /* score: '21.00'*/
      $s9 = "NotSquareSubset;OpenProcessTokenOther_AlphabeticOverParenthesis;Payment RequiredProxy-ConnectionRCodeFormatErrorRegQueryInfoKeyW" ascii /* score: '21.00'*/
      $s10 = "Bar;VirtualAllocX-ImforwardsX-Powered-Byabi mismatchadvapi32.dllautocompletebackepsilon;bad flushGenbad g statusbad g0 stackbad " ascii /* score: '21.00'*/
      $s11 = "DOMCONNECT_ERRORCache-ControlCertOpenStoreCoTaskMemFreeContent-RangeDeleteServiceDownArrowBar;DownTeeArrow;EnumProcessesExitWind" ascii /* score: '19.00'*/
      $s12 = "eds;NotSuperset;OpenServiceWOverBracket;PUSH_PROMISEPahawh_HmongRCodeRefusedRCodeSuccessReadConsoleWReleaseMutexReportEventWResu" ascii /* score: '18.00'*/
      $s13 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONCircleMinus;CircleTimes;CoCreateGuidContent TypeContent-" ascii /* score: '17.00'*/
      $s14 = ";Precondition FailedProxy-AuthorizationQueryServiceConfigWRCodeNotImplementedRegConnectRegistryWReverseEquilibrium;RightDoubleBr" ascii /* score: '16.00'*/
      $s15 = "meThreadRevertToSelfRightVector;Rrightarrow;RuleDelayed;SERIALNUMBERSetEndOfFileSetErrorModeSetStdHandleSmallCircle;Sora_Sompeng" ascii /* score: '15.00'*/
      $s16 = "owsExExponentialE;FQDN too longFindFirstFileFindNextFileWFreeAddrInfoWGC sweep waitGetDriveTypeWGreaterEqual;GreaterTilde;Gunjal" ascii /* score: '14.00'*/
      $s17 = "LoadLibraryWMax-ForwardsMediumSpace;Meetei_MayekMime-VersionMulti-StatusNot ExtendedNot ModifiedNotLessLess;NotPrecedes;NotSucce" ascii /* score: '12.00'*/
      $s18 = "eftarrow;internal errorinvalid syntaxis a directorykey size wrongleftarrowtail;leftharpoonup;len of type %slevel 2 haltedlevel 3" ascii /* score: '10.00'*/
      $s19 = "tent-lengthdata truncateddivideontimes;fallingdotseq;file too largefinalizer waitformnovalidategcstoptheworldgetprotobynamehookl" ascii /* score: '8.00'*/
      $s20 = "recoveryblacksquare;block clausec ap trafficc hs trafficcaller errorcan't happencas64 failedchan receivecircledcirc;circleddash;" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_24 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Configx509: invalid signature: parent certificate cann" ascii /* score: '36.50'*/
      $s2 = "golang.org/x/sys/windows/exec_windows.go" fullword ascii /* score: '18.00'*/
      $s3 = "golang.org/x/sys/windows/dll_windows.go" fullword ascii /* score: '15.00'*/
      $s4 = "golang.org/x/sys/windows.(*DLL).FindProcByOrdinal" fullword ascii /* score: '15.00'*/
      $s5 = "golang.org/x/sys/windows.(*DLL).MustFindProcByOrdinal" fullword ascii /* score: '15.00'*/
      $s6 = "golang.org/x/sys/windows.GetProcAddressByOrdinal" fullword ascii /* score: '14.00'*/
      $s7 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '14.00'*/
      $s8 = "golang.org/x/sys/windows/registry/key.go" fullword ascii /* score: '13.00'*/
      $s9 = "07172737475767778798081828384858687888990919293949596979899stateTextstateTagstateAttrNamestateAfterNamestateBeforeValuestateHTML" ascii /* score: '11.00'*/
      $s10 = "golang.org/x/sys/windows/registry/value.go" fullword ascii /* score: '10.00'*/
      $s11 = "golang.org/x/sys/windows/str.go" fullword ascii /* score: '10.00'*/
      $s12 = "meW. Australia Standard TimeWest Pacific Standard Time_html_template_attrescaper_html_template_htmlescaperaddress type not suppo" ascii /* score: '10.00'*/
      $s13 = "golang.org/x/sys/windows/security_windows.go" fullword ascii /* score: '10.00'*/
      $s14 = "%s overflows int+-/0123456789.eE, not a function.WithValue(type 0123456789ABCDEF0123456789abcdef2384185791015625: value of type " ascii /* score: '9.00'*/
      $s15 = ":VerifyDNSLengthAddDllDirectory" fullword ascii /* score: '9.00'*/
      $s16 = "%*func(uintptr) (*windows.Proc, error)" fullword ascii /* score: '7.00'*/
      $s17 = "CSSDqStrstateCSSSqStrstateCSSDqURLstateCSSSqURLstateCSSURLstateCSSBlockCmtstateCSSLineCmtstateError<html>" fullword ascii /* score: '7.00'*/
      $s18 = "golang.org/x/sys/windows/syscall_windows.go" fullword ascii /* score: '6.00'*/
      $s19 = "golang.org/x/sys/windows/zsyscall_windows.go" fullword ascii /* score: '6.00'*/
      $s20 = "golang.org/x/sys/windows/syscall.go" fullword ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_25 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $s1 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic" ascii /* score: '28.00'*/
      $s2 = " of unlocked RWMutextls: failed to write to key log: tls: invalid client finished hashtls: invalid server finished hashtls: unex" ascii /* score: '26.00'*/
      $s3 = "HandleExGetProcessShutdownParametersGetQueuedCompletionStatusEx" fullword ascii /* score: '23.00'*/
      $s4 = " after object key:value pair args stack map entries for %q is not a defined function18189894035458564758300781259094947017729282" ascii /* score: '22.00'*/
      $s5 = "pected ServerKeyExchangetoo many Answers to pack (>65535)too many levels of symbolic linksunsupported transfer encoding: %qwaiti" ascii /* score: '17.00'*/
      $s6 = "ounded allocation in sysAllocnet/http: skip alternate protocolpad size larger than data payloadpseudo header field after regular" ascii /* score: '17.00'*/
      $s7 = "username/password versionjsCtxRegexpjsCtxDivOpjsCtxUnknownleafCounts[maxBits][maxBits] != nmin must be a non-zero power of 2misr" ascii /* score: '15.00'*/
      $s8 = " oldval=runtime: failed mSpanList.insert runtime: failed to decommit pagesruntime: goroutine stack exceeds runtime: memory alloc" ascii /* score: '13.00'*/
      $s9 = " key length: findrunnable: negative nmspinningfreeing stack not in a stack spanheapBitsSetType: unexpected shifthttp2: invalid h" ascii /* score: '13.00'*/
      $s10 = "d Read on closed Bodyhttp: multiple registrations for incompatible types for comparisonindefinite length found (not DER)invalid " ascii /* score: '13.00'*/
      $s11 = "of range [%x:%y]stackalloc not on scheduler stackstoplockedm: inconsistent lockingstruct contains unexported fieldssync: RUnlock" ascii /* score: '12.50'*/
      $s12 = "ng for unsupported file typex509: no DEK-Info header in block%s %q is excluded by constraint %q355271367880050092935562133789062" ascii /* score: '12.00'*/
      $s13 = "eader field valuehttp2: invalid pseudo headers: %vhttp2: recursive push not allowedhttp: CloseIdleConnections calledhttp: invali" ascii /* score: '11.00'*/
      $s14 = "angereflect: chanDir of non-chan typereflect: slice index out of rangerpc: gob error encoding response:runtime: castogscanstatus" ascii /* score: '11.00'*/
      $s15 = "y rulesetcrypto/aes: output not full blockcrypto/des: output not full blockcrypto: requested hash function #ed25519: bad private" ascii /* score: '10.00'*/
      $s16 = "countbytes.Reader.Seek: invalid whencecannot index slice/array with nilconcurrent map read and map writeconnection not allowed b" ascii /* score: '9.00'*/
      $s17 = "5: day-of-year does not match monthOther_Default_Ignorable_Code_PointRat.GobEncode: numerator too largeSetFileCompletionNotifica" ascii /* score: '8.00'*/
      $s18 = "CreateCertificateContextEd25519 verification failureEnglish name for time zone \"FixedStack is not power-of-2GetFileInformationB" ascii /* score: '8.00'*/
      $s19 = " after object key:value pair args stack map entries for %q is not a defined function18189894035458564758300781259094947017729282" ascii /* score: '7.00'*/
      $s20 = "ated by OS [runtime: name offset out of rangeruntime: text offset out of rangeruntime: type offset out of rangeslice bounds out " ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_26 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
   strings:
      $s1 = "bytes.Reader.UnreadByte: at beginning of slicebytes.Reader.UnreadRune: at beginning of slicecipher.NewCTR: IV length must equal " ascii /* score: '27.50'*/
      $s2 = "les: %#qhttp2: could not negotiate protocol mutuallyhttp2: invalid Connection request header: %qhttp: Request.ContentLength=%d w" ascii /* score: '25.00'*/
      $s3 = "compute output context for template %scannot send after transport endpoint shutdowncharacter string exceeds maximum length (255)" ascii /* score: '15.00'*/
      $s4 = "To with pre-connected connectionx509: internal error: cannot parse domain %qcan't call method/function %q with %d resultscannot " ascii /* score: '14.00'*/
      $s5 = "h out of range in SetLenruntime: lfstack.push invalid packing: node=template: multiple definition of template %qtls: server sent" ascii /* score: '14.00'*/
      $s6 = "sallowed in templatereflect: FieldByNameFunc of non-struct type reflect: funcLayout with interface receiver reflect: slice lengt" ascii /* score: '11.00'*/
      $s7 = "ith nil Bodyhttp: putIdleConn: too many idle connectionsinsufficient data for calculated length typemime: unexpected content aft" ascii /* score: '11.00'*/
      $s8 = "ched montgomery number lengthsmemory reservation exceeds address space limitnet/http: internal error: misuse of tryDelivernet/ht" ascii /* score: '10.00'*/
      $s9 = "ange in SetCapreleased less than one physical page of memoryrequest Content-Type isn't multipart/form-dataruntime: debugCallV1 c" ascii /* score: '10.00'*/
      $s10 = "client conn %p to %vinvalid slice length %d: exceeds input size %dlength of string exceeds input size (%d bytes)math/big: mismat" ascii /* score: '9.50'*/
      $s11 = "block sizefirst path segment in URL cannot contain colonfunction called with %d args; should be 1 or 2http2: Transport creating " ascii /* score: '9.00'*/
      $s12 = "cipher: NewGCM requires 128-bit block ciphercrypto/sha256: invalid hash state identifiercrypto/sha512: invalid hash state identi" ascii /* score: '7.00'*/
      $s13 = "fierencoding alphabet contains newline charactergcmarknewobject called while doing checkmarkhtml/template: pattern matches no fi" ascii /* score: '7.00'*/
      $s14 = "ic before malloc heap initialized" fullword ascii /* score: '6.00'*/
      $s15 = "alled by unknown caller runtime: failed to create new OS thread (have runtime: name offset base pointer out of rangeruntime: pan" ascii /* score: '6.00'*/
      $s16 = "context: internal error: missing cancel errorexitsyscall: syscall frame is no longer validheapBitsSetType: called with non-point" ascii /* score: '6.00'*/
      $s17 = "tp: too many 1xx informational responsesos: unexpected result from WaitForSingleObjectpanicwrap: unexpected string after type na" ascii /* score: '4.00'*/
      $s18 = " an incorrect legacy versiontls: server's Finished message was incorrectunfinished escape sequence in CSS string: %quse of Write" ascii /* score: '3.00'*/
      $s19 = "me: reflect.Value.Slice: slice index out of boundsreflect: nil type passed to Type.ConvertibleToreflect: slice capacity out of r" ascii /* score: '3.00'*/
      $s20 = "er media subtypemultipart: expecting a new Part; got line %qout of memory allocating heap arena metadatapredefined escaper %q di" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_27 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "runtime: GetQueuedCompletionStatus returned invalid mode= tls: server changed cipher suite after a HelloRetryRequesturlPartNoneu" ascii /* score: '34.00'*/
      $s2 = "dhpack: invalid Huffman-encoded datahttp: server closed idle connectioninvalid sequence number in responsemheap.freeSpanLocked -" ascii /* score: '26.00'*/
      $s3 = ": unexpected %sunsigned integer overflow on token x509: decryption password incorrectx509: wrong Ed25519 public key size LastStr" ascii /* score: '20.00'*/
      $s4 = "h hex stringexecutable file not found in %PATH%expected unsigned integer; found %sfile type does not support deadlinefindfunc: b" ascii /* score: '19.00'*/
      $s5 = " invalid freemime: bogus characters after %%: %qmime: invalid RFC 2047 encoded-wordnetwork dropped connection on resetno such mu" ascii /* score: '14.00'*/
      $s6 = "c returns advance count beyond inputdelimNonedelimDoubleQuotedelimSingleQuotedelimSpaceOrTagEndhtml/template internal error: tem" ascii /* score: '14.00'*/
      $s7 = "35)traceback did not unwind completelytransform: short destination buffertransport endpoint is not connectedunclosed right paren" ascii /* score: '13.00'*/
      $s8 = "failed; errno=runtime: inconsistent read deadlinestrings.Reader.Seek: invalid whencesuperfluous leading zeros in lengthtls: inva" ascii /* score: '10.00'*/
      $s9 = "DSA-SHA1DecemberDiamond;DownTee;DuployanElement;Epsilon;EqualSidEthiopicExtenderFebruaryFullPathGeorgianGoStringGujaratiGurmukhi" ascii /* score: '9.00'*/
      $s10 = "plate escaping out of synchttp2: Transport received Server's graceful shutdown GOAWAYreflect: indirection through nil pointer to" ascii /* score: '9.00'*/
      $s11 = "rlPartPreQueryurlPartQueryOrFragurlPartUnknownRoundTripper returned a response & error; ignoring responsebufio.Scanner: SplitFun" ascii /* score: '8.00'*/
      $s12 = "esreflect.MakeSlice of non-slice typerpc: server cannot decode request: runtime: close polldesc w/o unblockruntime: createevent " ascii /* score: '8.00'*/
      $s13 = "lid or missing PSK binderstls: server selected an invalid PSKtls: too many non-advancing recordstoo many Questions to pack (>655" ascii /* score: '7.00'*/
      $s14 = "ad findfunctab entry idxfindrunnable: netpoll with spinningflate: corrupt input before offset greyobject: obj not pointer-aligne" ascii /* score: '7.00'*/
      $s15 = "NotLess;NovemberOl_ChikiOmicron;OverBar;PRIORITYParseIntPhags_PaProduct;QuestionReadFileReceivedSETTINGSSHA1-RSASaturdaySetEvent" ascii /* score: '7.00'*/
      $s16 = "TagbanwaTai_ThamTai_VietThursdayTifinaghTypeAAAATypeAXFRUgariticUpArrow;Uparrow;Upsilon;WSAIoctlZgotmplZ[signal " fullword ascii /* score: '7.00'*/
      $s17 = "125200204206304400404443500625://::1:\\/<<=>>=???ACKADTAMPASTAprAugBSTCATCDTCETCSTDD;DSADecDltEATEDTEETEOFESTETHFebFriGETGMTGT;G" ascii /* score: '5.00'*/
      $s18 = "tGg;Gt;HDTHSTHanIDTINTISTIm;JSTJanJulJunKSTLT;LaoLl;Lt;MDTMSKMSTMarMayMonMroMu;NDTNSTNULNaNNkoNovNu;OctOr;PC=PDTPKTPSTPi;Pr;REGR" ascii /* score: '4.00'*/
      $s19 = " embedded structrpc.Register: reply type of method %q is not a pointer: %q" fullword ascii /* score: '4.00'*/
      $s20 = "HTTP/1.1HTTP/2.0HiraganaImplies;JavaneseKatakanaKayah_LiLeftTee;Linear_ALinear_BLocationMahajaniNO_ERRORNO_PROXYNewLine;NoBreak;" ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_28 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash3 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "ansport encoding header %q = %qhttp2: invalid pseudo header in trailershttp2: timeout awaiting response headersmalformed MIME he" ascii /* score: '15.00'*/
      $s2 = "pc: service/method request ill-formed: runtime.SetFinalizer: first argument is runtime: netpollBreak write failed with runtime: " ascii /* score: '13.00'*/
      $s3 = "ing ']' in addressnetwork is unreachablenon-Go function at pc=oldoverflow is not niloperation was canceledparenthesized pipeline" ascii /* score: '11.00'*/
      $s4 = "ress of length x509: trailing data after DSA parametersx509: trailing data after DSA public keyx509: trailing data after RSA pub" ascii /* score: '10.00'*/
      $s5 = "rypto/rsa: input must be hashed messagedeferproc: d.panic != nil after newdeferevictOldest(%v) on table with %v entrieshttp2: Tr" ascii /* score: '10.00'*/
      $s6 = "status=, not pointer-byte block (/etc/services3814697265625::ffff:0:0/96:UseSTD3RulesAccept-RangesAuthorizationCLIENT_RANDOMCONN" ascii /* score: '10.00'*/
      $s7 = "address familyinvalid message lengthinvalid number base %djson: unknown field %qmalformed HTTP versionminpc or maxpc invalidmiss" ascii /* score: '10.00'*/
      $s8 = "Tai_VietThursdayTifinaghTypeAAAATypeAXFRUgariticUpArrow;Uparrow;Upsilon;ZgotmplZ[::1]:53[signal " fullword ascii /* score: '7.00'*/
      $s9 = "protocol not availableprotocol not supportedreflect.Value.MapIndexreflect.Value.SetFloatreflectlite.Value.Elemreflectlite.Value." ascii /* score: '7.00'*/
      $s10 = "d label %qinappropriate fallbackindex out of range: %dinteger divide by zerointerface conversion: internal inconsistencyinvalid " ascii /* score: '7.00'*/
      $s11 = "t countreflect.Value.SetBytes of non-byte slicereflect.Value.setRunes of non-rune slicereflect: FieldByName of non-struct type r" ascii /* score: '7.00'*/
      $s12 = "07814456755295395851135253906256938893903907228377647697925567626953125Frame accessor called on non-owned FrameMapIter.Key calle" ascii /* score: '6.00'*/
      $s13 = "ue: nil elementencoding/hex: invalid byte: %#Uentersyscallblock inconsistent expected colon after object keyfailed to parse cert" ascii /* score: '6.00'*/
      $s14 = "ader: missing colon: %qmultipart: unexpected line in Next(): %qoversized record received with length %dquotedprintable: invalid " ascii /* score: '4.00'*/
      $s15 = "NovemberOl_ChikiOmicron;OverBar;PRIORITYParseIntPhags_PaPriorityProduct;QuestionReceivedSETTINGSSHA1-RSASaturdayTagbanwaTai_Tham" ascii /* score: '4.00'*/
      $s16 = "nx509: trailing data after DSA signaturex509: trailing data after X.509 subject%s %q is not permitted by any constraint138777878" ascii /* score: '4.00'*/
      $s17 = "t provide a certificatetls: received empty certificates messagewrong type (%s) for received field %s.%sx509: cannot parse IP add" ascii /* score: '3.00'*/
      $s18 = "overlapclient doesn't support certificate curvecrypto/cipher: message too large for GCMcrypto/cipher: output smaller than inputc" ascii /* score: '3.00'*/
      $s19 = "out of memory: cannot allocate runtime: typeBitsBulkBarrier with type  time: Stop called on uninitialized Timertls: client didn'" ascii /* score: '3.00'*/
      $s20 = "ificate: %wfatal: bad g in signal handler" fullword ascii /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322_29 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash3 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "downloadH97" fullword ascii /* score: '11.00'*/
      $s2 = "shellInjL9" fullword ascii /* score: '10.00'*/
      $s3 = "downloadI" fullword ascii /* score: '10.00'*/
      $s4 = "shellInj" fullword ascii /* score: '9.00'*/
      $s5 = "pivotKilH97" fullword ascii /* score: '5.00'*/
      $s6 = "pivotJobL9" fullword ascii /* score: '5.00'*/
      $s7 = "pivotTCPL9" fullword ascii /* score: '5.00'*/
      $s8 = "No commaH" fullword ascii /* score: '4.00'*/
      $s9 = "fileBrowI" fullword ascii /* score: '4.00'*/
      $s10 = "fileBrowH97u" fullword ascii /* score: '4.00'*/
      $s11 = "pivotTCP" fullword ascii /* score: '4.00'*/
      $s12 = "check_inH" fullword ascii /* score: '4.00'*/
      $s13 = "pivotJobI" fullword ascii /* score: '4.00'*/
      $s14 = "pivotKil" fullword ascii /* score: '4.00'*/
      $s15 = "?moduu" fullword ascii /* score: '1.00'*/
      $s16 = "?shelu" fullword ascii /* score: '1.00'*/
      $s17 = "?killt" fullword ascii /* score: '1.00'*/
      $s18 = "?reinu" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_30 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash3 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash4 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash5 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $s1 = "main.main.func3" fullword ascii /* score: '7.00'*/
      $s2 = "main.main.func2" fullword ascii /* score: '7.00'*/
      $s3 = "main.main.func4" fullword ascii /* score: '7.00'*/
      $s4 = "main.main.func5" fullword ascii /* score: '7.00'*/
      $s5 = "main.main.func6" fullword ascii /* score: '7.00'*/
      $s6 = "main.init" fullword ascii /* score: '7.00'*/
      $s7 = "main.main.func1" fullword ascii /* score: '7.00'*/
      $s8 = "nctions.go" fullword ascii /* score: '4.00'*/
      $s9 = "main.glob..func3" fullword ascii /* score: '2.00'*/
      $s10 = "main.glob..func4" fullword ascii /* score: '2.00'*/
      $s11 = "main.glob..func2" fullword ascii /* score: '2.00'*/
      $s12 = "main.glob..func1" fullword ascii /* score: '2.00'*/
      $s13 = "main.glob..func5" fullword ascii /* score: '2.00'*/
      $s14 = "012345678912207031256103515625" ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_31 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "Saint Pierre Standard TimeSetProcessWorkingSetSizeExSetSecurityDescriptorGroupSetSecurityDescriptorOwnerSouth Africa Standard Ti" ascii /* score: '49.50'*/
      $s2 = "UUUUUUUQUUUUUUUU" fullword ascii /* score: '6.50'*/
      $s3 = "mplate escaped correctlytoo many colons in addresstoo many slice indexes: %dtruncated base 128 integerunexpected . after term %q" ascii /* score: '6.00'*/
      $s4 = "***@:path<nil>AEligAcircAdlamAopf;AprilAringAscr;Auml;BamumBarv;BatakBeta;Bopf;Bscr;BuhidCHcy;COPY;Call Cdot;Copf;Cscr;DJcy;DScy" ascii /* score: '5.00'*/
      $s5 = "pe !#$%&()*+-./:<=>?@[]^_{|}~ %q in attribute name: %.32q363797880709171295166015625AddVectoredContinueHandler" fullword ascii /* score: '4.00'*/
      $s6 = "unexpected right paren %#Uunexpected type in connectunterminated quoted stringx509: invalid simple chain is not assignable to ty" ascii /* score: '4.00'*/
      $s7 = "!@\"*!@\"" fullword ascii /* score: '1.00'*/
      $s8 = "J!:\"'!:\")" fullword ascii /* score: '1.00'*/
      $s9 = "K'LEK'LN" fullword ascii /* score: '1.00'*/
      $s10 = "D#N$L#!$" fullword ascii /* score: '1.00'*/
      $s11 = "=''(9''(%" fullword ascii /* score: '1.00'*/
      $s12 = "I''(l''(." fullword ascii /* score: '1.00'*/
      $s13 = "!',4<?EJRZ" fullword ascii /* score: '1.00'*/
      $s14 = "K'L!K'L!K'L!" fullword ascii /* score: '1.00'*/
      $s15 = "%+2378:;<<s" fullword ascii /* score: '1.00'*/
      $s16 = "ime: bad span s.state=segment prefix is reservedshrinking stack in libcallstartlockedm: locked to mestopped after 10 redirectste" ascii /* score: '0.00'*/
      $s17 = "#(08=AGNV\\6" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_32 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "github.com/DeimosC2/DeimosC2" fullword ascii /* score: '17.00'*/
      $s2 = "command-line-arguments" fullword ascii /* score: '12.00'*/
      $s3 = "golang.org/x/sys" fullword ascii /* score: '10.00'*/
      $s4 = "stateTextstateTagstateAttrNamestateAfterNamestateBeforeValuestateHTMLCmtstateRCDATAstateAttrstateURLstateSrcsetstateJSstateJSDqS" ascii /* score: '7.00'*/
      $s5 = "tateCSSBlockCmtstateCSSLineCmtstateError<html>" fullword ascii /* score: '7.00'*/
      $s6 = "trstateJSSqStrstateJSRegexpstateJSBlockCmtstateJSLineCmtstateCSSstateCSSDqStrstateCSSSqStrstateCSSDqURLstateCSSSqURLstateCSSURLs" ascii /* score: '4.00'*/
      $s7 = "h1:5B6i6EAiSYyejWfvc5Rc9BbI3rzIsrrXfAQBWnYfn+w=" fullword ascii /* score: '4.00'*/
      $s8 = "stateTextstateTagstateAttrNamestateAfterNamestateBeforeValuestateHTMLCmtstateRCDATAstateAttrstateURLstateSrcsetstateJSstateJSDqS" ascii /* score: '4.00'*/
      $s9 = "20200501145240" ascii /* score: '1.00'*/
      $s10 = "(devel)" fullword ascii /* score: '1.00'*/
      $s11 = "bc7a7d42d5c3" ascii /* score: '1.00'*/
      $s12 = "01020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364" ascii /* score: '1.00'*/
      $s13 = "v0.0.0-20200501145240-bc7a7d42d5c3" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_33 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "AuthorizH9" fullword ascii /* score: '8.00'*/
      $s2 = "ransportH9H" fullword ascii /* score: '7.00'*/
      $s3 = "*http2.TH9" fullword ascii /* score: '7.00'*/
      $s4 = "@DLMIHJA" fullword ascii /* score: '4.00'*/
      $s5 = "Www-AuthH9" fullword ascii /* score: '4.00'*/
      $s6 = "9httpu$" fullword ascii /* score: '4.00'*/
      $s7 = "@A'#\" " fullword ascii /* score: '1.00'*/
      $s8 = "z(H9r0" fullword ascii /* score: '1.00'*/
      $s9 = "4_=H$G" fullword ascii /* score: '1.00'*/
      $s10 = "Kh7g<h" fullword ascii /* score: '1.00'*/
      $s11 = "enticateH9A" fullword ascii /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_34 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $x1 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8uncomparable type %s: %vunexpected %s in operandunexpect" ascii /* score: '39.50'*/
      $s2 = ", received remote type 0123456789aAbBcCdDeEfF_0123456789abcdefABCDEF_200 Connected to Go RPC23283064365386962890625<invalid refl" ascii /* score: '29.00'*/
      $s3 = "heckdead: runnable gcommand not supportedconcurrent map writesdecompression failuredefer on system stackexec: already startedfin" ascii /* score: '26.00'*/
      $s4 = "usGetSecurityDescriptorDaclGetSecurityDescriptorSaclGetSidIdentifierAuthorityInitiateSystemShutdownExWIsValidSecurityDescriptorK" ascii /* score: '18.00'*/
      $s5 = "drunnable: wrong phttp: Handler timeouthttp: invalid patternhttp: nil Request.URLin string escape codekey is not comparablelink " ascii /* score: '12.00'*/
      $s6 = "ationJobObjectSetProcessPriorityBoostSingapore Standard TimeSri Lanka Standard TimeTocantins Standard TimeVariant Also Negotiate" ascii /* score: '11.00'*/
      $s7 = "ointNotSquareSupersetEqual;QueryServiceLockStatusWQyzylorda Standard TimeSERVER_TRAFFIC_SECRET_0SetEnvironmentVariableWSetInform" ascii /* score: '10.00'*/
      $s8 = "aliningrad Standard TimeMiddle East Standard TimeNew Zealand Standard TimeNorth Korea Standard TimeSetSecurityDescriptorDaclSetS" ascii /* score: '10.00'*/
      $s9 = "ecurityDescriptorSaclTransbaikal Standard TimeUS Mountain Standard TimeUlaanbaatar Standard TimeVladivostok Standard TimeW. Mong" ascii /* score: '10.00'*/
      $s10 = "sVenezuela Standard TimeVolgograd Standard TimeW. Europe Standard TimeWSAGetOverlappedResult" fullword ascii /* score: '9.00'*/
      $s11 = "Temporary RedirectTerminateJobObjectUNKNOWN_SETTING_%dVariation_SelectorVerticalSeparator;" fullword ascii /* score: '7.00'*/
      $s12 = "olia Standard Time" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_35 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "mstartbad unicode format bad value for fieldblacktriangleright;client disconnectedcontent-dispositiondevice not a streamdirector" ascii /* score: '33.00'*/
      $s2 = "trianglerighteq;unclosed commentunknown network unknown node: %svartriangleleft;workbuf is emptywww-authenticate after object ke" ascii /* score: '21.00'*/
      $s3 = "in hostmissing deferreturnmspan.sweep: state=multipart/form-datanetwork unreachableno such template %qnotesleep not on g0ntdll.d" ascii /* score: '21.00'*/
      $s4 = "ChunkBytestemplate: no files named in call to ParseFilestls: failed to parse certificate from server: tls: received new session " ascii /* score: '13.00'*/
      $s5 = "y initialHeapLive= is unimplemented spinningthreads=%%!%c(big.Int=%s), s.searchAddr = 0123456789ABCDEFX0123456789abcdefx06010215" ascii /* score: '13.00'*/
      $s6 = "e already closedfile already existsfile does not existhttp: Server closedif-unmodified-sinceillegal instructioninvalid Trailer k" ascii /* score: '10.00'*/
      $s7 = "trianglerighteq;unclosed commentunknown network unknown node: %svartriangleleft;workbuf is emptywww-authenticate after object ke" ascii /* score: '9.00'*/
      $s8 = "ticket from a clienttls: server chose an unconfigured cipher suitetls: server did not echo the legacy session IDx509: cannot sig" ascii /* score: '6.00'*/
      $s9 = "ll not foundnwait > work.nprocspanic during mallocpanic during panic" fullword ascii /* score: '4.00'*/
      $s10 = "0405Z070011920928955078125405 must CONNECT" fullword ascii /* score: '4.00'*/
      $s11 = "eyinvalid URL escape longleftrightarrow;m not found in allmmarking free objectmarkroot: bad indexmime: no media typemissing ']' " ascii /* score: '3.00'*/
      $s12 = "y not emptydisk quota exceededdodeltimer: wrong Pempty option stringerr must be non-nilevictCount overflowexpired certificatefil" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949_36 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash3 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $x1 = "_html_template_urlfilterapplication/octet-streamapplication/x-ecmascriptapplication/x-javascriptbad defer entry in panicbad defe" ascii /* score: '47.00'*/
      $x2 = "panic holding lockspanicwrap: no ( in panicwrap: no ) in proxy-authorizationreflect.Value.Fieldreflect.Value.Floatreflect.Value." ascii /* score: '33.50'*/
      $s3 = " by peerdouble traceGCSweepStartencodeArray: nil elementerror decrypting messageexec: Stderr already setexec: Stdout already set" ascii /* score: '22.00'*/
      $s4 = "eunknown cipher typeunknown status codeunknown wait reasonwinmm.dll not foundx509: unknown errorzero length segment after array " ascii /* score: '19.00'*/
      $s5 = "unhashable type http2: canceling requesthttp: nil Request.Headeridna: disallowed rune %UinitSpan: unaligned baseinvalid argument" ascii /* score: '14.00'*/
      $s6 = " to Intninvalid pseudo-header %qinvalid request :path %qjson: unsupported type: level 2 not synchronizedlink number out of range" ascii /* score: '12.00'*/
      $s7 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii /* score: '10.00'*/
      $s8 = "rtially overlapsreflect.Value.SetComplexreflect.Value.UnsafeAddrresource length too longrpc: can't find service runqsteal: runq " ascii /* score: '9.00'*/
      $s9 = "non-empty decoder buffernot supported by windowson range loop re-entry: out of streams resourcesqueuefinalizer during GCrange pa" ascii /* score: '9.00'*/
      $s10 = "element markroot jobs done" fullword ascii /* score: '9.00'*/
      $s11 = "expected float; found %sflate: maxBits too largefloating point exceptionfunction not implementedgcDrainN phase incorrecthash of " ascii /* score: '7.00'*/
      $s12 = "overflowruntime: VirtualFree of runtime: found obj at *(runtime: s.searchAddr = span has no free objectsstack trace unavailable" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a_37 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash3 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $x1 = "github.com/DeimosC2/DeimosC2/agents/resources/shellexec/exec_both.go" fullword ascii /* score: '32.00'*/
      $x2 = "sched={pc: (core dumped) /* %s */null  but progSize  nmidlelocked= on zero Value out of range  to finalizer  untyped args $htmlt" ascii /* score: '31.00'*/
      $s3 = " using %03d %s%s %s; , TTL: , goid=, j0 = /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82.5.4.99765625::1/128:method:scheme:s" ascii /* score: '25.50'*/
      $s4 = "sched={pc: (core dumped) /* %s */null  but progSize  nmidlelocked= on zero Value out of range  to finalizer  untyped args $htmlt" ascii /* score: '21.00'*/
      $s5 = ";ExpiresForAll;GODEBUGGammad;Gbreve;Gcedil;GranthaHARDcy;HEADERSHanunooHstrok;ILLEGALIM UsedIO waitIacute;Igrave;Itilde;JanuaryJ" ascii /* score: '14.00'*/
      $s6 = "%s overflows int+-/0123456789.eE, not a function.WithValue(type /etc/resolv.conf0123456789ABCDEF0123456789abcdef2384185791015625" ascii /* score: '8.00'*/
      $s7 = "golang.org/x/sys@v0.0.0-20200501145240-bc7a7d42d5c3/unix/syscall_unix.go" fullword ascii /* score: '6.00'*/
      $s8 = "golang.org/x/sys@v0.0.0-20200501145240-bc7a7d42d5c3/unix/syscall.go" fullword ascii /* score: '6.00'*/
      $s9 = "sercy;KannadaKcedil;Lacute;Lambda;Lcaron;Lcedil;Lmidot;Lstrok;MD2-RSAMD5-RSAMakasarMandaicMarchenMultaniMyanmarNacute;Ncaron;Nce" ascii /* score: '4.00'*/
      $s10 = "oundaryboxplus;ccupssm;cemptyv;cgocheckcheck_incirscir;codebasecoloneq;congdot;continuecontrolscudarrl;cudarrr;cularrp;curarrm;d" ascii /* score: '4.00'*/
      $s11 = "tent-lengthdata truncateddivideontimes;fallingdotseq;file too largefinalizer waitformnovalidategcstoptheworldhookleftarrow;inter" ascii /* score: '3.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4_38 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $s1 = ".Interfacereflectlite.Value.NumMethodrunlock of unlocked rwmutexruntime: asyncPreemptStack=runtime: checkdead: find g runtime: c" ascii /* score: '18.00'*/
      $s2 = "slice: len out of rangemap has no entry for key %qmspan.sweep: bad span statenet/http: invalid method %qnet/http: use last respo" ascii /* score: '15.00'*/
      $s3 = "ead errorinvalid HTTP header name %qinvalid argument to Shuffleinvalid dependent stream IDinvalid profile bucket typeinvalid typ" ascii /* score: '12.00'*/
      $s4 = "heckdead: nmidle=runtime: corrupted polldescruntime: netpollinit failedruntime: thread ID overflowruntime" fullword ascii /* score: '10.00'*/
      $s5 = "gehkdf: entropy limit reachedhttp chunk length too largehttp2: response body closedinsufficient security levelinternal lockOSThr" ascii /* score: '7.00'*/
      $s6 = "e for comparisoninvalid type name length %dkey was rejected by servicemakechan: size out of rangemakeslice: cap out of rangemake" ascii /* score: '6.00'*/
      $s7 = "rrect length IVcommunication error on sendcould not find QPC syscallscrypto/rsa: invalid moduluscryptobyte: invalid OID: %vcrypt" ascii /* score: '6.00'*/
      $s8 = "obyte: length overflowcurrent time %s is after %sdecode can't handle type %sgcstopm: not waiting for gcgrowslice: cap out of ran" ascii /* score: '5.00'*/
      $s9 = "lue pairbad data: undefined type %scan't index item of type %scan't slice item of type %schannel number out of rangecipher: inco" ascii /* score: '5.00'*/
      $s10 = "nsenot a XENIX named type fileprogToPointerMask: overflowrange can't iterate over %vreflect.Value.OverflowFloatreflectlite.Value" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92_f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366_39 {
   meta:
      description = "mw - from files 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash2 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "SOAResource bodySOAResource.MBoxSRVResource bodyShortRightArrow;TXTResource bodyUpgrade RequiredUpperRightArrow;User-Agent: %s" fullword ascii /* score: '17.00'*/
      $s2 = "anProportional;Reset ContentRightCeiling;RoundImplies;RoundingMode(SHA256-RSAPSSSHA384-RSAPSSSHA512-RSAPSSSIGKILL: killSIGQUIT: " ascii /* score: '14.00'*/
      $s3 = "ngmsdaa;angmsdab;angmsdac;angmsdad;angmsdae;angmsdaf;angmsdag;angmsdah;angrtvbd;approxeq;atomicor8attempts:autofocusawconint;bac" ascii /* score: '11.00'*/
      $s4 = "OverParenthesis;PTRResource bodyPayment RequiredProxy-ConnectionRCodeFormatErrorRightDownVector;SETTINGS_TIMEOUTSIGNONE: no trap" ascii /* score: '10.00'*/
      $s5 = "ECT_ERRORCache-ControlContent-RangeDownArrowBar;DownTeeArrow;ExponentialE;FQDN too longGC sweep waitGreaterEqual;GreaterTilde;Gu" ascii /* score: '8.00'*/
      $s6 = "ContourIntegral;DoubleDownArrow;DoubleLeftArrow;DownRightVector;FRAME_SIZE_ERRORGC scavenge waitGC worker (idle)GODEBUG: value " ascii /* score: '6.00'*/
      $s7 = "Multiple ChoicesNotGreaterEqual;NotGreaterTilde;NotHumpDownHump;NotLeftTriangle;NotSquareSubset;OPTResource bodyOther_Alphabetic" ascii /* score: '4.00'*/
      $s8 = "njala_GondiHilbertSpace;HumpDownHump;If-None-MatchIntersection;Last-ModifiedLeftArrowBar;LeftTeeArrow;LeftTriangle;LeftUpVector;" ascii /* score: '4.00'*/
      $s9 = "Loop DetectedMXResource.MXMasaram_GondiMende_KikakuiNewFloat(NaN)NotCongruent;NotHumpEqual;NotLessEqual;NotLessTilde;Old_Hungari" ascii /* score: '4.00'*/
      $s10 = "IV for ECDSA CTRImperial_AramaicLeftRightVector;LeftTriangleBar;LeftUpTeeVector;LeftUpVectorBar;LowerRightArrow;Meroitic_Cursive" ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_40 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "runtime: bad pointer in frame runtime: found in object at *(runtime: impossible type kind socket operation on non-socketsquare r" ascii /* score: '25.50'*/
      $s2 = "t address unexpected key value typeunknown Go type for slice using unaddressable value using zero Value argument1455191522836685" ascii /* score: '7.00'*/
      $s3 = "180664062572759576141834259033203125: day-of-year out of rangeBougainville Standard TimeCentral Asia Standard TimeCertFreeCertif" ascii /* score: '4.00'*/
      $s4 = "wrong medium type  but memory size  because dotdotdot to non-Go memory , locked to thread298023223876953125404 page not found: d" ascii /* score: '3.00'*/
      $s5 = "icateContextE. Australia Standard TimeECDSA verification failureEkaterinburg Standard TimeFindFirstVolumeMountPointWGODEBUG: can" ascii /* score: '3.00'*/
      $s6 = ") not in usable address space: ...additional frames elided..." fullword ascii /* score: '2.00'*/
      $s7 = "07007450580596923828125A" ascii /* score: '1.00'*/
      $s8 = "363797880709171295166015625Add" ascii /* score: '1.00'*/
      $s9 = "7450580596923828125A" ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949_41 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash3 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "time zone \"FixedStack is not power-of-2GetFileInformationByHandleExGetProcessShutdownParametersGetQueuedCompletionStatusEx" fullword ascii /* score: '23.00'*/
      $s2 = "unlock: lock countsigsend: inconsistent statestack size not a power of 2startm: negative nmspinningstopTheWorld: holding locksti" ascii /* score: '22.00'*/
      $s3 = "ears in an ambiguous context within a URLP has cached GC work at end of mark terminationattempting to link in too many shared li" ascii /* score: '10.00'*/
      $s4 = "n with hash function requestedx509: failed to parse rfc822Name constraint %qx509: failed to unmarshal elliptic curve point%s app" ascii /* score: '10.00'*/
      $s5 = "brariesbufio: reader returned negative count from Readchacha20poly1305: message authentication failedcurve25519: global Basepoin" ascii /* score: '9.00'*/
      $s6 = "dingsunsupported protocol schemework.nwait was > work.nproc after object key:value pair args stack map entries for %q is not a d" ascii /* score: '7.00'*/
      $s7 = "en. Australia Standard TimeCentral Europe Standard TimeCertCreateCertificateContextEd25519 verification failureEnglish name for " ascii /* score: '3.00'*/
      $s8 = "efined function18189894035458564758300781259094947017729282379150390625Aus Central W. Standard TimeCanada Central Standard TimeC" ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_42 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
   strings:
      $s1 = "lmRopf;Rscr;RunicSHcy;STermSopf;Sqrt;Sscr;Star;THORNTScy;TakriTamilTopf;Tscr;TypeAUarr;UcircUopf;Upsi;Uscr;Uuml;Vbar;Vert;Vopf;V" ascii /* score: '12.00'*/
      $s2 = "division by zerodownharpoonleft;expected integerexpected newlinegc: unswept spangcshrinkstackoffhost unreachableinteger overflow" ascii /* score: '9.00'*/
      $s3 = "Mopf;Mscr;NJcy;Nopf;Nscr;NushuOcircOghamOopf;OriyaOsageOscr;Ouml;P-224P-256P-384P-521Popf;Pscr;QUOT;Qopf;Qscr;Rang;RangeRarr;Rea" ascii /* score: '9.00'*/
      $s4 = "no route to hostnon-Go function" fullword ascii /* score: '9.00'*/
      $s5 = "ENTIEcy;IOcy;IcircIdot;Iopf;Iota;Iscr;Iuml;Jopf;Jscr;KHcy;KJcy;KhmerKopf;Kscr;LJcy;Lang;Larr;LatinLimbuLocalLopf;Lscr;LstatMarch" ascii /* score: '8.00'*/
      $s6 = "invalid argumentinvalid encodinginvalid exchangeinvalid g statusinvalid rune %#Uinvalid spdelta leftharpoondown;leftrightarrows;" ascii /* score: '7.00'*/
      $s7 = "scr;Wopf;Wscr;Xopf;Xscr;YAcy;YIcy;YUcy;Yopf;Yscr;Yuml;ZHcy;Zdot;Zeta;Zopf;Zscr;\"'<=`\\u202" fullword ascii /* score: '4.00'*/
      $s8 = "length too largemSpanList.insertmSpanList.removemessage too longmissing stackmapnLeftrightarrow;nleftrightarrow;no renegotiation" ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_43 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $s1 = "t1.3text/javascript1.4text/javascript1.5tracebackancestorstruncated sequencetwoheadrightarrow;unexpected messageunexpected newli" ascii /* score: '11.00'*/
      $s2 = "main.glob..func6" fullword ascii /* score: '2.00'*/
      $s3 = "main.glob..func9" fullword ascii /* score: '2.00'*/
      $s4 = "main.glob..func7" fullword ascii /* score: '2.00'*/
      $s5 = "main.glob..func8" fullword ascii /* score: '2.00'*/
      $s6 = "@tT@TT@DT@" fullword ascii /* score: '1.00'*/
      $s7 = "@`T@`TU`" fullword ascii /* score: '1.00'*/
      $s8 = "%%%%%%!!!!!!!!!!        !!" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_44 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeSe" ascii /* score: '28.00'*/
      $s2 = "yphsGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetProcessMemoryInfoGetWindowsDirectoryWHTTP" ascii /* score: '23.00'*/
      $s3 = "rviceConfigWCheckTokenMembershipCreateProcessAsUserWCryptAcquireContextWDoubleLongLeftArrow;DownLeftRightVector;Egyptian_Hierogl" ascii /* score: '21.00'*/
      $s4 = "andleInformationSetVolumeMountPointWSquareSupersetEqual;Taipei Standard TimeTerminal_PunctuationTurkey Standard TimeUnprocessabl" ascii /* score: '15.00'*/
      $s5 = "_HieroglyphsNegativeMediumSpace;NotGreaterFullEqual;NotRightTriangleBar;QueryServiceConfig2WQueryServiceStatusExRegisterEventSou" ascii /* score: '10.00'*/
      $s6 = "rceWRequest URI Too LongRightArrowLeftArrow;SHGetKnownFolderPathSeek: invalid offsetSeek: invalid whenceSetCurrentDirectoryWSetH" ascii /* score: '9.00'*/
      $s7 = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeSe" ascii /* score: '6.00'*/
      $s8 = "/%d.%d %03d %s" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949_45 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
   strings:
      $s1 = "lantgtr;expected :=fallthroughfile existsfileBrowserfinal tokenfloat32nan2float64nan2float64nan3formenctypegccheckmarkgeneralize" ascii /* score: '7.00'*/
      $s2 = "9*struct { F uintptr; newConfig *tls.Config; c *tls.Conn } " fullword ascii /* score: '7.00'*/
      $s3 = ";killt" fullword ascii /* score: '1.00'*/
      $s4 = ";downu" fullword ascii /* score: '1.00'*/
      $s5 = ";reinu" fullword ascii /* score: '1.00'*/
      $s6 = ";moduu" fullword ascii /* score: '1.00'*/
      $s7 = ";shelu" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 19000KB and ( all of them )
      ) or ( all of them )
}

rule _a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9_c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4_46 {
   meta:
      description = "mw - from files a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash2 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $s1 = "andard TimeFilledSmallSquare;GetComputerNameExWGetCurrentThreadIdGetExitCodeProcessGetFileAttributesWGetModuleFileNameWGetModule" ascii /* score: '23.00'*/
      $s2 = " elements)http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; " ascii /* score: '20.50'*/
      $s3 = "closing connectionhttp: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless All" ascii /* score: '18.00'*/
      $s4 = "ay out of rangeArab Standard TimeCaucasian_AlbanianCloseServiceHandleCommandLineToArgvWCreateFileMappingWCreateWellKnownSidCuba " ascii /* score: '11.00'*/
      $s5 = "ord with version %x when expecting version %xruntime:stoplockedm: g is not Grunnable or Gscanrunnable" fullword ascii /* score: '11.00'*/
      $s6 = "owIllegalWrites is enabledrpc.Register: method %q has %d output parameters; needs exactly one" fullword ascii /* score: '7.00'*/
      $s7 = "Standard TimeDoubleUpDownArrow;DoubleVerticalBar;DownLeftTeeVector;DownLeftVectorBar;Expectation FailedFLOW_CONTROL_ERRORFiji St" ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75_47 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash3 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash4 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "cong;constcopf;copy;cscr;csub;csup;cups;dArr;dHar;darr;dash;data-deferdiam;djcy;dopf;dscr;dscy;dsol;dtri;dzcy;eDot;ecir;ecircedo" ascii /* score: '9.00'*/
      $s2 = "pf;boxH;boxV;boxh;boxv;breakbscr;bsim;bsol;bull;bump;bytescaps;cdot;cedilcent;chcy;chdirchmodchowncirE;circ;cire;classclosecomp;" ascii /* score: '8.00'*/
      $s3 = " ] = (acircacuteaeligallowandd;andv;ange;aopf;apid;apos;argp=aringarrayascr;asyncattr(auml;bNot;bad nbbrk;beta;beth;blockbnot;bo" ascii /* score: '5.00'*/
      $s4 = "= incr=%v is not  mcount= minutes nalloc= newval= nfreed= packed= ping=%q pointer stack=[ status %!Month(%.10q...%s&#x%x;%s:%d:%" ascii /* score: '4.50'*/
      $s5 = "> addr= base  code= ctxt: curg= goid  jobs= list= m->p= next= null  p->m= prev= span= varp=% util%%%02x' for '\"&<>" fullword ascii /* score: '4.00'*/
      $s6 = "null<!--" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_48 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $s1 = "lice: len out of rangemap has no entry for key %qmspan.sweep: bad span statenet/http: invalid method %qnet/http: use last respon" ascii /* score: '15.00'*/
      $s2 = "ad errorinvalid HTTP header name %qinvalid argument to Shuffleinvalid dependent stream IDinvalid profile bucket typeinvalid type" ascii /* score: '12.00'*/
      $s3 = "_html_template_jsstrescaper_html_template_jsvalescaperaccess-control-allow-originaddress not a stack addressafter object key:val" ascii /* score: '10.00'*/
      $s4 = "ehkdf: entropy limit reachedhttp chunk length too largehttp2: response body closedinsufficient security levelinternal lockOSThre" ascii /* score: '7.00'*/
      $s5 = " for comparisoninvalid type name length %dkey was rejected by servicemakechan: size out of rangemakeslice: cap out of rangemakes" ascii /* score: '6.00'*/
      $s6 = "ue pairbad data: undefined type %scan't index item of type %scan't slice item of type %schannel number out of rangecipher: incor" ascii /* score: '5.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_49 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
   strings:
      $s1 = "ob: gopf;gscr;gsim;gtcc;gvnE;hArr;half;harr;hbar;hopf;hscr;httpsicirciecy;iexclimap2imap3imapsimof;indexinputint16int32int64iocy" ascii /* score: '12.00'*/
      $s2 = "ap;lneq;lopf;lozf;lpar;lscr;lsim;lsqb;ltcc;ltri;lvnE;macr;male;malt;mediamicromlcp;mldr;monthmopf;mscr;nGtv;nLtv;nang;napE;nbsp;" ascii /* score: '4.00'*/
      $s3 = "ncap;ncup;ngeq;nges;ngtr;nisd;njcy;nldr;nleq;nles;nmid;nopf;npar;npre;nsce;nscr;nsim;nsub;nsup;ntgl;ntlg;ntohsnvap;nvge;nvgt;nvl" ascii /* score: '0.00'*/
      $s4 = ";iopf;iota;iscr;isin;ismapiuml;jopf;jscr;khcy;kjcy;kopf;kscr;lArr;lHar;labellang;laquolarr;late;lcub;ldca;ldsh;leqq;lesg;ljcy;ln" ascii /* score: '0.00'*/
      $s5 = ";Cconint;Cedilla;CherokeeClassANYConflictContinueCyrillicDEK-InfoDNS nameDOWNGRD" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f_50 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
   strings:
      $s1 = "ncoding error for type %q: %qjsonrpc: request body missing paramskey size not a multiple of key alignmalformed MIME header initi" ascii /* score: '17.50'*/
      $s2 = "c key, got %Thttp: no Location header in responsehttp: unexpected EOF reading trailerinternal error: associate not commonjson: e" ascii /* score: '17.00'*/
      $s3 = "pto/sha1: invalid hash state sizecrypto/sha512: invalid hash functionexceeded maximum template depth (%v)expected an ECDSA publi" ascii /* score: '14.00'*/
      $s4 = "can't handle assignment of %s to empty interface argumentgentraceback cannot trace user goroutine on its own stackhttp: Request." ascii /* score: '9.00'*/
      $s5 = "big: invalid 2nd argument to Int.Jacobi: need odd integer but got %sdecoding int array or slice: length exceeds input size (%d e" ascii /* score: '7.00'*/
      $s6 = "aCha20 nonce sizecompressed name in SRV resource datacrypto/cipher: input not full blockscrypto/rand: argument to Int is <= 0cry" ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_51 {
   meta:
      description = "mw - from files 7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "7bec7b246c7ba157f16dde3cee2225c1066bac706aa3113031df351a75c22239"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      hash5 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $x1 = "tls: client certificate contains an unsupported public key of type %Ttls: handshake message of length %d bytes exceeds maximum o" ascii /* score: '50.50'*/
      $s2 = " keycontenteditablecurvearrowleft;doublebarwedge;downdownarrows;elem size wrongforce gc (idle)hookrightarrow;html/template: inva" ascii /* score: '19.00'*/
      $s3 = "n dataruntime: found space for saved base pointer, but no framepointer experiment" fullword ascii /* score: '10.00'*/
      $s4 = "eb33a0f4a13945d898c296ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop" ascii /* score: '6.00'*/
      $s5 = "type..eq.runtime.mOS" fullword ascii /* score: '5.00'*/
      $s6 = ")!_\"\\!" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366_52 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "patible types for comparisonindefinite length found (not DER)invalid username/password versionjsCtxRegexpjsCtxDivOpjsCtxUnknownl" ascii /* score: '18.00'*/
      $s2 = "main.recvMsg" fullword ascii /* score: '7.00'*/
      $s3 = "otinva;notinvb;notinvc;notniva;notnivb;notnivc;npolint;npreceq;nsqsube;nsqsupe;nsubset;nsucceq;nsupset;nvinfin;nvltrie;nvrtrie;n" ascii /* score: '4.00'*/
      $s4 = "eafCounts[maxBits][maxBits] != nmin must be a non-zero power of 2misrounded allocation in sysAllocnet/http: skip alternate proto" ascii /* score: '3.00'*/
      $s5 = "108031254444" ascii /* score: '1.00'*/
      $s6 = ";BopomofoBugineseCayleys;Cconint;Cedilla;CherokeeClassANYConflictContinueCyrillicDEK-InfoDNS nameDOWNGRD" fullword ascii /* score: '0.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( all of them )
      ) or ( all of them )
}

rule _82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_53 {
   meta:
      description = "mw - from files 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
   strings:
      $s1 = "ip: invalid headerheader line too longhtml/template:%s: %shttp2: stream closedhttp: POST too largeif/with can't use %vindex of n" ascii /* score: '20.50'*/
      $s2 = "minimum page size (2220446049250313080847263336181640625_cgo_notify_runtime_init_done missingall goroutines are asleep - deadloc" ascii /* score: '15.00'*/
      $s3 = "public exponent too smallcrypto/rsa: unsupported hash functioncrypto: Size of unknown hash functiondereference of nil pointer of" ascii /* score: '13.00'*/
      $s4 = "ice/array with type %schacha20poly1305: plaintext too largecipher: message authentication failedcomment ends before closing deli" ascii /* score: '9.00'*/
      $s5 = "k!bad data: ignore can't handle type %sbytes.Buffer: truncation out of rangecannot exec a shared library directlycannot index sl" ascii /* score: '8.00'*/
      $s6 = "mitercrypto/cipher: incorrect GCM tag sizecrypto/cipher: invalid buffer overlapcrypto/rsa: public exponent too largecrypto/rsa: " ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d_dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322_54 {
   meta:
      description = "mw - from files 05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
      hash2 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "bad symbol tablebigtriangledown;castogscanstatuscirclearrowleft;content-encodingcontent-languagecontent-locationcontext canceled" ascii /* score: '10.00'*/
      $s2 = "curvearrowright;division by zerodownharpoonleft;expected integerexpected newlinegc: unswept spangcshrinkstackoffhost unreachable" ascii /* score: '9.00'*/
      $s3 = " @* `* d* t* `" fullword ascii /* score: '5.00'*/
      $s4 = "after object keyapplication/jsonapplication/wasmbad SAN sequencebad frame layoutbad g transitionbad special kindbad summary data" ascii /* score: '3.00'*/
      $s5 = "D$F{}H" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_55 {
   meta:
      description = "mw - from files 80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "80654f07fdc9bb1eddf1c83313008b9df88ac16dddcebf6ef8a253a03a2952df"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash4 = "f3ed51d699b1c4a111e71845a1376ffe80c517eacd80b118e03c403366f6bbdd"
   strings:
      $s1 = "sync/atomic: store of inconsistently typed value into Valuesync: WaitGroup is reused before previous Wait has returnedtls: serve" ascii /* score: '28.50'*/
      $s2 = "une: previous operation was not ReadRunemalformed response from server: missing status pseudo headernet/http: server response he" ascii /* score: '20.00'*/
      $s3 = "r resumed a session with a different cipher suitetls: server selected TLS 1.3 using the legacy version fieldbytes.Reader.UnreadR" ascii /* score: '13.00'*/
      $s4 = "aders exceeded %d bytes; abortedrpc.Register: return type of method %q is %q, must be error" fullword ascii /* score: '12.50'*/
      $s5 = "command-line-arguments/TCP_agent.go" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and ( all of them )
      ) or ( all of them )
}

rule _82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92_9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb_56 {
   meta:
      description = "mw - from files 82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92, 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
      hash2 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash3 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
   strings:
      $s1 = "runtime:greyobject: checkmarks finds unexpected unmarked object obj=decoding bool array or slice: length exceeds input size (%d " ascii /* score: '18.50'*/
      $s2 = " size (%d elements)http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)rpc.Register: method %q has %d input par" ascii /* score: '15.50'*/
      $s3 = "runtime:greyobject: checkmarks finds unexpected unmarked object obj=decoding bool array or slice: length exceeds input size (%d " ascii /* score: '10.00'*/
      $s4 = "elements)decoding int8 array or slice: length exceeds input size (%d elements)decoding uint array or slice: length exceeds input" ascii /* score: '7.00'*/
      $s5 = "ameters; needs exactly three" fullword ascii /* score: '4.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2_a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1be_57 {
   meta:
      description = "mw - from files 9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2, a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9, a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940, c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233, dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-11"
      hash1 = "9ef8ef433675caa00e1fc95c93ed9e5c8daac94ea4c653ac7571b8beeb1fb9d2"
      hash2 = "a2b00d2e10f83eee19ddd99470faf1c3fa79c3a2b04457b96e2a54b1befbd1c9"
      hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
      hash4 = "c7e81d55f390c00d444907885952e2a927a8a363102f850fe73e14c1d4785233"
      hash5 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
   strings:
      $s1 = "pcdata is runtime: preempt g0semaRoot rotateLeftskip this directorystopm holding lockssync.Cond is copiedtemplate: %s:%d: %stoo " ascii /* score: '19.50'*/
      $s2 = "IDS_Trinary_OperatorInsufficient StorageIsrael Standard TimeJordan Standard TimeLeftArrowRightArrow;MAX_HEADER_LIST_SIZEMeroitic" ascii /* score: '14.00'*/
      $s3 = "Rat.Scan: invalid syntaxRequest Entity Too LargeSA Eastern Standard TimeSA Pacific Standard TimeSA Western Standard TimeUS Easte" ascii /* score: '13.00'*/
      $s4 = "many open filesunclosed left parenunexpected %s in %sunexpected g statusunknown Go type: %vunknown branch typeunknown certificat" ascii /* score: '6.00'*/
      $s5 = "rn Standard Time\", required CPU feature" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

