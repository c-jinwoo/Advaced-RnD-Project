rule TurlaMosquito_Mal_1 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b295032919143f5b6b3c87ad22bcf8b55ecc9244aa9f6f88fc28f36f5aa2925e"
   strings:
      $s1 = "Pipetp" fullword ascii
      $s2 = "EStOpnabn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "169d4237c79549303cca870592278f42" or
        all of them
      )
}

rule TurlaMosquito_Mal_2 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "68c6e9dea81f082601ae5afc41870cea3f71b22bfc19bcfbc61d84786e481cb4"
      hash2 = "05254971fe3e1ca448844f8cfcfb2b0de27e48abd45ea2a3df897074a419a3f4"
   strings:
      $s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
      $s3 = "no_address" fullword wide
      $s6 = "SRRRQP" fullword ascii
      $s7 = "QWVPQQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
        pe.imphash() == "cd918073f209c5da7a16b6c125d73746" or
        all of them
      )
}

rule TurlaMosquito_Mal_3 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "443cd03b37fca8a5df1bbaa6320649b441ca50d1c1fcc4f5a7b94b95040c73d1"
   strings:
      $x1 = "InstructionerDLL.dll" fullword ascii

      $s1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $s2 = "/scripts/m/query.php?id=" fullword wide
      $s3 = "SELECT * FROM AntiVirusProduct" fullword ascii
      $s4 = "Microsoft Update" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "88488fe0b8bcd6e379dea6433bb5d7d8" or
         ( pe.exports("InstallRoutineW") and pe.exports("StartRoutine") ) or
         $x1 or
         3 of them
      )
}

rule TurlaMosquito_Mal_4 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "17b328245e2874a76c2f46f9a92c3bad"
}

rule TurlaMosquito_Mal_5 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "26a1a42bc74e14887616f9d6048c17b1b4231466716a6426e7162426e1a08030"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "ac40cf7479f53a4754ac6481a4f24e57"
}

rule TurlaMosquito_Mal_6 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
   strings:
      $a1 = "/scripts/m/query.php?id=" fullword wide
      $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $a3 = "GetUserNameW fails" fullword wide

      $s1 = "QVSWQQ" fullword ascii
      $s2 = "SRRRQP" fullword ascii
      $s3 = "QSVVQQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         2 of ($a*) or
         4 of them
      )
}

rule APT_TurlaMosquito_MAL_Oct22_1 {
   meta:
      description = "Detects Turla Mosquito malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2022-10-25"
      score = 80
      hash1 = "6b9e48e3f4873cfb95639d9944fe60e3b056daaa2ea914add14c982e3e11128b"
      hash2 = "b868b674476418bbdffbe0f3d617d1cce4c2b9dae0eaf3414e538376523e8405"
      hash3 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"
   strings:
      $s1 = "Logger32.dll" ascii fullword
      $s4 = " executing %u command on drive %martCommand : CWin32ApiErrorExce" wide
      $s5 = "Unsupported drive!!!" ascii fullword
      $s7 = "D:\\Build_SVN\\PC_MAGICIAN_4." ascii fullword

      $op1 = { 40 cc 8b 8b 06 cc 55 00 70 8b 10 10 33 51 04 46 04 64 }
      $op2 = { c3 10 e8 50 04 00 cc ff 8d 00 69 8d 75 ff 68 ec 6a 4d }
      $op3 = { e8 64 a1 6e 00 64 a1 c2 04 08 75 40 73 1d 8b ff cc 10 89 cc 8b c3 cc af }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and
      (
         pe.imphash() == "073235ae6dfbb1bf5db68a039a7b7726" or
         all of them
      )
}
rule APT_Turla_Agent_BTZ_Gen_1 {
   meta:
      description = "Detects Turla Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-06-16"
      score = 80
      hash1 = "c905f2dec79ccab115ad32578384008696ebab02276f49f12465dcd026c1a615"
   strings:
      $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii

      $s1 = "release mutex - %u (%u)(%u)" fullword ascii
      $s2 = "\\system32\\win.com" ascii
      $s3 = "Command Id:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s4 = "MakeFile Error(%d) copy file to temp file %s" fullword ascii
      $s5 = "%s%%s08x.tmp" fullword ascii
      $s6 = "Run instruction: %d ID:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s7 = "Mutex_Log" fullword ascii
      $s8 = "%s\\system32\\winview.ocx" fullword ascii
      $s9 = "Microsoft(R) Windows (R) Operating System" fullword wide
      $s10 = "Error: pos(%d) > CmdSize(%d)" fullword ascii
      $s11 = "\\win.com" ascii
      $s12 = "Error(%d) run %s " fullword ascii
      $s13 = "%02d.%02d.%04d Log begin:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "9d0d6daa47d6e6f2d80eb05405944f87" or
         ( pe.exports("Entry") and pe.exports("InstallM") and pe.exports("InstallS") ) or
         $x1 or 3 of them
      ) or ( 5 of them )
}
rule APT_MAL_LNX_Turla_Apr202004_1 { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings: 
      $ = "/root/.hsperfdata" ascii fullword
      $ = "Desc| Filename | size |state|" ascii fullword
      $ = "VS filesystem: %s" ascii fullword
      $ = "File already exist on remote filesystem !" ascii fullword 
      $ = "/tmp/.sync.pid" ascii fullword
      $ = "rem_fd: ssl " ascii fullword
      $ = "TREX_PID=%u" ascii fullword
      $ = "/tmp/.xdfg" ascii fullword
      $ = "__we_are_happy__" ascii
      $ = "/root/.sess" ascii fullword
      /* $ = "ZYSZLRTS^Z@@NM@@G_Y_FE" ascii fullword */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      4 of them
}

rule APT_MAL_LNX_Turla_Apr202004_1_opcode { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings:
      $op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 } /* Xor string loop_p1 x32*/ 
      $op1 = { 48FFC14883F94975E9 } /*Xorstringloop_p2x32*/
      $op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
      /* Load eth0 interface*/
      $op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0}
      /* Opcode exceptions*/ 
      $op4 = { 88D380C305329AC1D60C08889A60A10F084283FA0876E9 }
      /* Xor string loop x64*/
      $op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 } /* Kill call x32 */ 
      $op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB } /* Decrypt init str */ 
      $op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB} /* Decrypt init str */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      2 of them
}
rule SnakeTurla_Malware_May17_1 {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      modified = "2023-01-06"
      hash1 = "5b7792a16c6b7978fca389882c6aeeb2c792352076bf6a064e7b8b90eace8060"
   strings:
      $s1 = "/Users/vlad/Desktop/install/install/" ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 200KB and all of them )
}

rule SnakeTurla_Malware_May17_2 {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "b8ee4556dc09b28826359b98343a4e00680971a6f8c6602747bd5d723d26eaea"
   strings:
      $s1 = "b_openssl: oops - number of mutexes is 0" fullword ascii
      $s2 = "networksetup -get%sproxy Ethernet" fullword ascii
      $s3 = "012A04DECBC441e49C527B2798F54CA7LOG_NAMED_PIPE_NAME" fullword ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 6000KB and all of them )
}

rule SnakeTurla_Malware_May17_4 {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "d5ea79632a1a67abbf9fb1c2813b899c90a5fb9442966ed4f530e92715087ee2"
   strings:
      $s1 = "Install Adobe Flash Player.app/com.adobe.updatePK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 5000KB and all of them )
}

rule SnakeTurla_Installd_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
   strings:
      $s1 = "PIDS=`ps cax | grep installdp" ascii
      $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}

rule SnakeTurla_Install_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
   strings:
      $s1 = "${TARGET_PATH}/installd.sh" ascii
      $s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii
   condition:
   ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}
rule Turla_APT_srsvc {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
		hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"
	strings:
		$x1 = "SVCHostServiceDll.dll" fullword ascii

		$s2 = "msimghlp.dll" fullword wide
		$s3 = "srservice" fullword wide
		$s4 = "ModStart" fullword ascii
		$s5 = "ModStop" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) or all of ($s*) ) )
		or ( all of them )
}

rule Turla_APT_Malware_Gen1 {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
		hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
		hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash5 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash6 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash7 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash8 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash9 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash10 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
	strings:
		$x1 = "too long data for this type of transport" fullword ascii
		$x2 = "not enough server resources to complete operation" fullword ascii
		$x3 = "Task not execute. Arg file failed." fullword ascii
		$x4 = "Global\\MSCTF.Shared.MUTEX.ZRX" fullword ascii

		$s1 = "peer has closed the connection" fullword ascii
		$s2 = "tcpdump.exe" fullword ascii
		$s3 = "windump.exe" fullword ascii
		$s4 = "dsniff.exe" fullword ascii
		$s5 = "wireshark.exe" fullword ascii
		$s6 = "ethereal.exe" fullword ascii
		$s7 = "snoop.exe" fullword ascii
		$s8 = "ettercap.exe" fullword ascii
		$s9 = "miniport.dat" fullword ascii
		$s10 = "net_password=%s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 2 of ($x*) or 8 of ($s*) ) )
		or ( 12 of them )
}
rule Turla_APT_Malware_Gen3 {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash2 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash3 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash4 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash5 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash6 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash7 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		hash8 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash9 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
	strings:
		$x1 = "\\\\.\\pipe\\sdlrpc" fullword ascii
		$x2 = "WaitMutex Abandoned %p" fullword ascii
		$x3 = "OPER|Wrong config: no port|" fullword ascii
		$x4 = "OPER|Wrong config: no lastconnect|" fullword ascii
		$x5 = "OPER|Wrong config: empty address|" fullword ascii
		$x6 = "Trans task %d obj %s ACTIVE fail robj %s" fullword ascii
		$x7 = "OPER|Wrong config: no auth|" fullword ascii
		$x8 = "OPER|Sniffer '%s' running... ooopppsss...|" fullword ascii

		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Post Platform" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Pre Platform" fullword ascii
		$s3 = "www.yahoo.com" fullword ascii
		$s4 = "MSXIML.DLL" fullword wide
		$s5 = "www.bing.com" fullword ascii
		$s6 = "%s: http://%s%s" fullword ascii
		$s7 = "/javascript/view.php" fullword ascii
		$s8 = "Task %d failed %s,%d" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE %d.0; " fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) or 6 of ($s*) ) )
		or ( 10 of them )
}

rule Turla_Mal_Script_Jan18_1 {
   meta:
      description = "Detects Turla malicious script"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://ghostbin.com/paste/jsph7"
      date = "2018-01-19"
      hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
   strings:
      $s1 = ".charCodeAt(i % " ascii
      $s2 = "{WScript.Quit();}" fullword ascii
      $s3 = ".charAt(i)) << 10) |" ascii
      $s4 = " = WScript.Arguments;var " ascii
      $s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii
   condition:
      filesize < 200KB and 2 of them
}
rule Turla_KazuarRAT {
   meta:
      description = "Detects Turla Kazuar RAT described by DrunkBinary"
      author = "Markus Neis / Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
      date = "2018-04-08"
      hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
      hash2 = "7594fab1aadc4fb08fb9dbb27c418e8bc7f08dadb2acf5533dc8560241ecfc1d"
      hash3 = "4e5a86e33e53931afe25a8cb108f53f9c7e6c6a731b0ef4f72ce638d0ea5c198"
   strings:
      $x1 = "~1.EXE" wide
      $s2 = "dl32.dll" fullword ascii
      $s3 = "HookProc@" ascii
      $s4 = "0`.wtf" fullword ascii
   condition:
      uint16(0) == 0x5a4d and  filesize < 20KB and (
         pe.imphash() == "682156c4380c216ff8cb766a2f2e8817" or
         2 of them )
}
rule MAL_Turla_Agent_BTZ {
   meta:
      description = "Detects Turla Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
      date = "2018-04-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8"
   strings:
      $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
      $x3 = "mstotreg.dat" fullword ascii
      $x4 = "Bisuninst.bin" fullword ascii
      $x5 = "mfc42l00.pdb" fullword ascii
      $x6 = "ielocal~f.tmp" fullword ascii

      $s1 = "%s\\1.txt" fullword ascii
      $s2 = "%windows%" fullword ascii
      $s3 = "%s\\system32" fullword ascii
      $s4 = "\\Help\\SYSTEM32\\" ascii
      $s5 = "%windows%\\mfc42l00.pdb" ascii
      $s6 = "Size of log(%dB) is too big, stop write." fullword ascii
      $s7 = "Log: Size of log(%dB) is too big, stop write." fullword ascii
      $s8 = "%02d.%02d.%04d Log begin:" fullword ascii
      $s9 = "\\system32\\win.com" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         1 of ($x*) or
         4 of them
      )
}
rule MAL_Turla_Sample_May18_1 {
   meta:
      description = "Detects Turla samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/omri9741/status/991942007701598208"
      date = "2018-05-03"
      hash1 = "4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038"
      hash2 = "77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f"
   strings:
      $x1 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" fullword ascii
      $x2 = "cmd.exe /c start %%SystemRoot%%\\%s" fullword ascii
      $x3 = "cmd.exe /c %s\\%s -s %s:%s:%s -c \"%s %s /wait 1\">>%s" fullword ascii
      $x4 = "Read InjectLog[%dB]********************************" fullword ascii
      $x5 = "%s\\System32\\011fe-3420f-ff0ea-ff0ea.tmp" fullword ascii
      $x6 = "**************************** Begin ini %s [%d]***********************************************" fullword ascii
      $x7 = "%s -o %s -i %s -d exec2 -f %s" fullword ascii
      $x8 = "Logon to %s failed: code %d(User:%s,Pass:%s)" fullword ascii
      $x9 = "system32\\dxsnd32x.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}
rule APT_MAL_LNX_Turla_Apr20_1 {
   meta:
      description = "Detects Turla Linux malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/Int2e_/status/1246115636331319309"
      date = "2020-04-05"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
   strings:
      $s1 = "/root/.hsperfdata" ascii fullword
      $s2 = "Desc|     Filename     |  size  |state|" ascii fullword
      $s3 = "IPv6 address %s not supported" ascii fullword
      $s4 = "File already exist on remote filesystem !" ascii fullword
      $s5 = "/tmp/.sync.pid" ascii fullword
      $s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword
   condition:
      uint16(0) == 0x457f and
      filesize < 5000KB and
      4 of them
}
rule APT_MAL_TinyTurla_Sep21_1 {
	meta:
		author = "Cisco Talos"
		description = "Detects Tiny Turla backdoor DLL"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"
		date = "2021-09-21"
	strings:
		$a = "Title: " fullword wide
		$b = "Hosts" fullword wide
		$c = "Security" fullword wide
		$d = "TimeLong" fullword wide
		$e = "TimeShort" fullword wide
		$f = "MachineGuid" fullword wide
		$g = "POST" fullword wide
		$h = "WinHttpSetOption" fullword ascii
		$i = "WinHttpQueryDataAvailable" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}
rule apt_RU_Turla_Kazuar_DebugView_peFeatures
{
	meta:
		description = "Turla mimicking SysInternals Tools- peFeatures"
        reference = "https://www.epicturla.com/blog/sysinturla"
		version = "2.0"
		author = "JAG-S"
        score = 85
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	condition:
		uint16(0) == 0x5a4d
		and
		(
			pe.version_info["LegalCopyright"] == "Test Copyright" 
			and
			(
				(
				pe.version_info["ProductName"] == "Sysinternals DebugView"
				and
				pe.version_info["Description"] == "Sysinternals DebugView"
				)
			or
				(
				pe.version_info["FileVersion"] == "4.80.0.0"
				and
				pe.version_info["Comments"] == "Sysinternals DebugView"
				)
			or
				(
				pe.version_info["OriginalName"] contains "DebugView.exe"
				and
				pe.version_info["InternalName"] contains "DebugView.exe"
				)
			or
				(
				pe.version_info["OriginalName"] == "Agent.exe"
				and
				pe.version_info["InternalName"] == "Agent.exe"
				)
			)
		)
}

rule APT_MAL_RU_Turla_Kazuar_May20_1 {
   meta:
      description = "Detects Turla Kazuar malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.epicturla.com/blog/sysinturla"
      date = "2020-05-28"
      hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
      hash2 = "1fca5f41211c800830c5f5c3e355d31a05e4c702401a61f11e25387e25eeb7fa"
      hash3 = "2d8151dabf891cf743e67c6f9765ee79884d024b10d265119873b0967a09b20f"
      hash4 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"
   strings:
      $s1 = "Sysinternals" ascii fullword
	  $s2 = "Test Copyright" wide fullword

      $op1 = { 0d 01 00 08 34 2e 38 30 2e 30 2e 30 00 00 13 01 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and
      all of them
}
rule WaterBug_turla_dropper {
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla Dropper"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
	condition:
		all of them
}
rule WaterBug_turla_dll {
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla DLL"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
	condition:
		pe.exports("ee") and $a
}
rule turla_png_dropper {
    meta:
        author = "Ben Humphrey"
        description = "Detects the PNG Dropper used by the Turla group"
        reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
        date = "2018/11/23"
        hash1 = "6ed939f59476fd31dc4d99e96136e928fbd88aec0d9c59846092c0e93a3c0e27"
    strings:
        $api0 = "GdiplusStartup"
        $api1 = "GdipAlloc"
        $api2 = "GdipCreateBitmapFromStreamICM"
        $api3 = "GdipBitmapLockBits"
        $api4 = "GdipGetImageWidth"
        $api5 = "GdipGetImageHeight"
        $api6 = "GdiplusShutdown"
        $code32 = {
            8B 46 3C               // mov     eax, [esi+3Ch]
            B9 0B 01 00 00         // mov     ecx, 10Bh
            66 39 4C 30 18         // cmp     [eax+esi+18h], cx
            8B 44 30 28            // mov     eax, [eax+esi+28h]
            6A 00                  // push    0
            B9 AF BE AD DE         // mov     ecx, 0DEADBEAFh
            51                     // push    ecx
            51                     // push    ecx
            03 C6                  // add     eax, esi
            56                     // push    esi
            FF D0                  // call eax
        }

        $code64 = {
            48 63 43 3C            // movsxd rax, dword ptr [rbx+3Ch]
            B9 0B 01 00 00         // mov ecx, 10Bh
            BA AF BE AD DE         // mov edx, 0DEADBEAFh
            66 39 4C 18 18         // cmp [rax+rbx+18h], cx
            8B 44 18 28            // mov eax, [rax+rbx+28h]
            45 33 C9               // xor r9d, r9d
            44 8B C2               // mov r8d, edx
            48 8B CB               // mov rcx, rbx
            48 03 C3               // add rax, rbx
            FF D0                  // call rax
        }
        condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and
        all of ($api*) and
        1 of ($code*)
}

rule turla_png_reg_enum_payload {
    meta:
        author = "Ben Humphrey"
        description = "Payload that has most recently been dropped by the Turla PNG Dropper"
        reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
        date = "2018/11/23"
        hash1 = "fea27eb2e939e930c8617dcf64366d1649988f30555f6ee9cd09fe54e4bc22b3"
    strings:
        $crypt00 = "Microsoft Software Key Storage Provider" wide
        $crypt01 = "ChainingModeCBC" wide
        /* $crypt02 = "AES" wide */ /* disabled due to performance reasons */
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and
        pe.imports("advapi32.dll", "StartServiceCtrlDispatcherA") and
        pe.imports("advapi32.dll", "RegEnumValueA") and
        pe.imports("advapi32.dll", "RegEnumKeyExA") and
        pe.imports("ncrypt.dll", "NCryptOpenStorageProvider") and
        pe.imports("ncrypt.dll", "NCryptEnumKeys") and
        pe.imports("ncrypt.dll", "NCryptOpenKey") and
        pe.imports("ncrypt.dll", "NCryptDecrypt") and
        pe.imports("ncrypt.dll", "BCryptGenerateSymmetricKey") and
        pe.imports("ncrypt.dll", "BCryptGetProperty") and
        pe.imports("ncrypt.dll", "BCryptDecrypt") and
        pe.imports("ncrypt.dll", "BCryptEncrypt") and
        all of them
}
rule PenquinTurla {
	meta:
		Author = "Intezer Analyze"
		Reference = "https://apt-ecosystem.com"

	strings:
		$block_0 = { 89 ?? ?? BE ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? 0F 84 }
		$block_1 = { 89 ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 89 ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_2 = { 83 ?? ?? ?? 89 ?? 89 ?? C1 ?? ?? 8B ?? ?? C1 ?? ?? 30 ?? 0F B6 ?? 0F B6 ?? ?? 0F B6 ?? 39 ?? 74 }
		$block_3 = { 5? 31 ?? B9 ?? ?? ?? ?? 5? 5? 83 ?? ?? 8D ?? ?? ?? FC 8B ?? ?? ?? F3 ?? A1 ?? ?? ?? ?? 85 ?? 75 }
		$block_4 = { C7 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 31 ?? 85 ?? 0F 84 }
		$block_5 = { 0F B7 ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 81 E? ?? ?? ?? ?? 83 ?? ?? 3D ?? ?? ?? ?? 66 ?? ?? ?? ?? 7E }
		$block_6 = { 89 ?? 89 ?? 8B ?? D3 ?? 83 ?? ?? 0F B6 ?? ?? ?? 89 ?? D3 ?? 09 ?? 89 ?? 83 ?? ?? FF 4? ?? ?? 75 }
		$block_7 = { 5? 89 ?? 5? 31 ?? 5? 31 ?? 5? 83 ?? ?? 89 ?? 89 ?? ?? 4? 8D ?? ?? C6 ?? ?? ?? 0F BE ?? 85 ?? 74 }
		$block_8 = { 01 ?? 8D ?? ?? 01 ?? 89 ?? ?? 8D ?? ?? 89 ?? ?? 89 ?? ?? ?? FF 5? ?? BA ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_9 = { 89 ?? ?? 8D ?? ?? ?? ?? ?? ?? 89 ?? 83 ?? ?? 31 ?? 29 ?? 8B ?? 8D ?? ?? ?? 89 ?? ?? 85 ?? 0F 84 }
		$block_10 = { 89 ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 88 }
		$block_11 = { FF 4? ?? 89 ?? 89 ?? C1 ?? ?? 8B ?? ?? C1 ?? ?? 30 ?? 0F B6 ?? 0F B6 ?? ?? 0F B6 ?? 39 ?? 0F 84 }
		$block_12 = { E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 0F B7 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? E9 }
		$block_13 = { 8B ?? ?? ?? ?? ?? 8D ?? ?? 8B ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? 0F 86 }
		$block_14 = { F6 ?? ?? ?? ?? ?? ?? 89 ?? 8B ?? ?? ?? 8B ?? ?? ?? 89 ?? ?? 8B ?? ?? ?? 89 ?? ?? 89 ?? ?? 0F 85 }
		$block_15 = { 0F B7 ?? ?? C1 ?? ?? 25 ?? ?? ?? ?? 0F 95 ?? ?? ?? ?? ?? 89 ?? 80 8? ?? ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_16 = { 8B ?? ?? 88 ?? 80 E? ?? 0F B6 ?? ?? ?? ?? ?? 24 ?? 08 ?? 88 ?? ?? ?? ?? ?? 0F B6 ?? 88 ?? ?? E9 }
		$block_17 = { 0F B6 ?? ?? ?? 89 ?? 4? 30 ?? ?? ?? ?? ?? 31 ?? 81 F? ?? ?? ?? ?? 0F 9D ?? 4? 4? 21 ?? 39 ?? 7C }
		$block_18 = { 8B ?? ?? FF 4? ?? 8B ?? ?? 89 ?? ?? 0F B6 ?? 88 ?? ?? ?? 8B ?? ?? 4? 8B ?? ?? 89 ?? ?? 39 ?? 72 }
		$block_19 = { 0F B6 ?? 31 ?? 31 ?? 89 ?? ?? ?? 31 ?? 4? 89 ?? ?? ?? 31 ?? BD ?? ?? ?? ?? 89 ?? ?? ?? 88 ?? E9 }
		$block_20 = { FF 8? ?? ?? ?? ?? 31 ?? 8B ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 0F 95 ?? 85 ?? 8D ?? ?? ?? 0F 84 }
		$block_21 = { C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F B6 ?? ?? ?? ?? ?? 41 ?? ?? ?? 75 }
		$block_22 = { 48 ?? ?? ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$block_23 = { 41 ?? 5? 5? 48 ?? ?? BE ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_24 = { 64 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 83 ?? ?? ?? ?? ?? ?? 0F 84 }
		$block_25 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$block_26 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_27 = { 48 ?? ?? E8 ?? ?? ?? ?? 29 ?? 8D ?? ?? 83 ?? ?? 41 ?? ?? 44 ?? ?? ?? 41 ?? ?? ?? 4D ?? ?? 0F 84 }
		$block_28 = { 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 ?? ?? F3 ?? B9 ?? ?? ?? ?? 0F 97 ?? 0F 92 ?? 38 ?? 0F 84 }
		$block_29 = { 48 ?? 49 ?? ?? FF C? 48 ?? ?? ?? ?? ?? ?? 89 ?? 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 0F 85 }
		$block_30 = { BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? 89 ?? ?? ?? ?? ?? 0F 88 }
		$block_31 = { 48 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 0F 05 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 89 }
		$block_32 = { 4C ?? ?? 48 ?? ?? 41 ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 0F 05 48 ?? ?? ?? ?? ?? 76 }
		$block_33 = { 0F BE ?? 83 ?? ?? 8D ?? ?? ?? ?? ?? ?? 8D ?? ?? 40 ?? ?? ?? 8D ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? 74 }
		$block_34 = { C7 ?? ?? ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? 89 ?? 39 ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 0F 84 }
		$block_35 = { 89 ?? ?? ?? 8B ?? ?? ?? B9 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? 0F 84 }
		$block_36 = { 89 ?? ?? 31 ?? 31 ?? 89 ?? ?? ?? B9 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? FF 5? ?? 85 ?? 0F 84 }
		$block_37 = { 8B ?? ?? ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? ?? 0F 84 }
		$block_38 = { C7 ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_39 = { C7 ?? ?? ?? ?? ?? ?? 31 ?? 89 ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 89 }
		$block_40 = { 5? 5? 5? 5? 83 ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? ?? 85 ?? 0F 84 }
		$block_41 = { 89 ?? ?? B9 ?? ?? ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? 29 ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 88 }
		$block_42 = { 89 ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_43 = { C7 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_44 = { 89 ?? ?? ?? 8B ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? 0F 84 }
		$block_45 = { 8B ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_46 = { 8D ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 31 ?? 8B ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? 39 ?? ?? ?? 0F 8D }
		$block_47 = { 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? 89 ?? ?? ?? 89 ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_48 = { 8D ?? ?? 89 ?? 89 ?? ?? 0F B7 ?? ?? 66 ?? ?? ?? 0F B7 ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? 0F 86 }
		$block_49 = { 8B ?? ?? ?? BE ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? ?? 85 ?? 0F 88 }
		$block_50 = { 89 ?? ?? 8D ?? ?? ?? ?? ?? 89 ?? ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_51 = { FF 4? ?? 4? 0F BE ?? 0F B6 ?? 83 ?? ?? 89 ?? ?? 0F BE ?? 8D ?? ?? 88 ?? 88 ?? 2C ?? 3C ?? 77 }
		$block_52 = { 8B ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_53 = { 89 ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? 8B ?? ?? ?? ?? ?? 39 ?? ?? 89 ?? ?? 0F 85 }
		$block_54 = { 5? 5? 5? 5? 83 ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? 85 ?? 89 ?? 89 ?? ?? 0F 88 }
		$block_55 = { 8B ?? ?? 8D ?? ?? ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 85 ?? 89 ?? ?? ?? ?? ?? 0F 84 }
		$block_56 = { 8B ?? ?? ?? ?? ?? ?? 89 ?? 29 ?? 8B ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? 85 ?? 0F 84 }
		$block_57 = { 89 ?? ?? B8 ?? ?? ?? ?? 89 ?? ?? ?? 8D ?? ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_58 = { 48 ?? ?? E8 ?? ?? ?? ?? 89 ?? 48 ?? ?? ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_59 = { 41 ?? 49 ?? ?? 5? 48 ?? ?? ?? 5? 8B ?? ?? 48 ?? ?? C6 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 87 }
		$block_60 = { 44 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 85 ?? 0F 85 }
		$block_61 = { 41 ?? 4C ?? ?? ?? 5? 48 ?? ?? 5? 8B ?? ?? 48 ?? ?? C6 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 87 }
		$block_62 = { 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 ?? F0 ?? ?? ?? 89 ?? 8B ?? ?? ?? ?? ?? 48 ?? ?? 0F 83 }
		$block_63 = { 44 ?? ?? BA ?? ?? ?? ?? FC 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? F3 ?? ?? 40 ?? ?? ?? 74 }
		$block_64 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 44 ?? ?? E8 ?? ?? ?? ?? 89 ?? 8B ?? ?? ?? 85 ?? 0F 84 }
		$block_65 = { 48 ?? ?? ?? ?? ?? 0F 94 ?? ?? ?? 48 ?? ?? ?? ?? ?? 0F B6 ?? ?? ?? 41 ?? ?? ?? 44 ?? ?? 0F 84 }
		$block_66 = { 49 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 41 ?? ?? 41 ?? ?? 0F 84 }
		$block_67 = { C6 ?? ?? BF ?? ?? ?? ?? 89 ?? ?? 89 ?? E8 ?? ?? ?? ?? C6 ?? ?? B9 ?? ?? ?? ?? FC F3 ?? 74 }
		$block_68 = { FC 89 ?? C1 ?? ?? 89 ?? F3 ?? 8B ?? ?? ?? ?? ?? 80 8? ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? E9 }
		$block_69 = { 5? 89 ?? 5? 89 ?? 5? 5? 83 ?? ?? 8B ?? ?? 89 ?? ?? 8B ?? ?? ?? ?? ?? 85 ?? 89 ?? ?? 0F 84 }
		$block_70 = { C7 ?? ?? ?? ?? ?? ?? 8D ?? ?? 8D ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_71 = { 8B ?? 83 ?? ?? 89 ?? 8B ?? ?? ?? 8B ?? 83 ?? ?? 89 ?? ?? ?? 89 ?? 8B ?? ?? ?? 85 ?? 0F 84 }
		$block_72 = { 5? 31 ?? 5? 5? 5? 81 E? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? 85 ?? 0F 8E }
		$block_73 = { 8B ?? ?? 8B ?? 89 ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 95 ?? 0F B6 ?? 4? 21 ?? ?? 9? }
		$block_74 = { 8D ?? ?? 8D ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? 0F 84 }
		$block_75 = { C7 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 85 ?? 0F 85 }
		$block_76 = { 89 ?? ?? ?? 31 ?? 8D ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_77 = { B8 ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? 0F 84 }
		$block_78 = { 8B ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? ?? 85 ?? 0F 84 }
		$block_79 = { 4C ?? ?? ?? ?? 4D ?? ?? 4C ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? FF D? 83 ?? ?? 0F 84 }
		$block_80 = { 4C ?? ?? 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 4A ?? ?? ?? 48 ?? ?? 48 ?? ?? 49 ?? ?? 0F 89 }
		$block_81 = { 44 ?? ?? 44 ?? ?? 41 ?? ?? B9 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 0F 84 }
		$block_82 = { 8B ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 80 3? ?? 0F 84 }
		$block_83 = { 48 ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 49 ?? ?? ?? 48 ?? ?? ?? ?? 0F 85 }
		$block_84 = { 0F B7 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 0F 84 }
		$block_85 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 49 ?? ?? ?? 0F 88 }
		$block_86 = { 89 ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 0F 84 }
		$block_87 = { 4D ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 41 ?? ?? ?? 0F 8F }
		$block_88 = { 4C ?? ?? 4C ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F 87 }
		$block_89 = { 48 ?? ?? ?? ?? 49 ?? ?? 89 ?? 4C ?? ?? 44 ?? ?? E8 ?? ?? ?? ?? 0F BE ?? 83 ?? ?? 0F 84 }
		$block_90 = { 8B ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 01 ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 0F 87 }
		$block_91 = { 8B ?? ?? 48 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 89 ?? ?? ?? ?? ?? 0F 84 }
		$block_92 = { BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? 41 ?? ?? ?? 0F 84 }
		$block_93 = { BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? 41 ?? ?? ?? 0F 85 }
		$block_94 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 89 ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? 81 F? ?? ?? ?? ?? 0F 84 }
		$block_95 = { FF 4? ?? 48 ?? ?? ?? 48 ?? ?? ?? 4D ?? ?? 48 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? FF C? 0F 84 }
		$block_96 = { 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 8B ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? C9 C3 }
		$block_97 = { 49 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 4C ?? ?? 83 ?? ?? ?? ?? ?? ?? 0F 8E }
		$block_98 = { 8B ?? ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 89 ?? ?? ?? 0F 84 }
		$block_99 = { 48 ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 41 ?? ?? 0F 85 }

	condition:
		hash.sha256(0, filesize) == "1eee1d0f736f3b796ab8da66bb16a68c7600e9a0c0cc8de0b640bc53beb9a90a" or
		hash.sha256(0, filesize) == "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" or
		hash.sha256(0, filesize) == "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" or
		hash.sha256(0, filesize) == "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" or
		hash.sha256(0, filesize) == "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0" or
		hash.sha256(0, filesize) == "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" or
		12 of them
}
rule turla {
    strings:
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x084680
        $xor_loop = { 8d4a05 328a ???????? 888a ???????? 42 83fa08 76eb }
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x80c2660
        $enc_string = { 2D72647852323138502E2930216A76 }

    condition:
        any of them
}
rule apt_turla_pdb
{
	 meta:

		 description = "Rule to detect a component of the APT Turla"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2017-05-31"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Turla"
       	 actor_type = "Apt"
      	 actor_group = "Unknown"
		 reference = "https://attack.mitre.org/groups/G0010/"
		 hash = "3b8bd0a0c6069f2d27d759340721b78fd289f92e0a13965262fea4e8907af122"
	 
	 strings:

	 	$pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

	 condition:
	 
	 	uint16(0) == 0x5a4d and
 		filesize < 650KB and
 		any of them
}
