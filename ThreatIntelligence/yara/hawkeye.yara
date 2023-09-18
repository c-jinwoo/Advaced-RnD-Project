rule hawkeye {
    // File 6597A865EBE0D0F6D34B30B32814F79D
    strings:
        $stringset = { 68007400740070003A002F002F007700770077002E0000002E0063006F006D00000046006F0072006D003100000053006100760065000000700061006E0065006C003100000062007500740074006F006E00310000004E0061007600690067006100740065000000420072006F007700730065007200000062007500740074006F006E0032000000770065006200420072006F007700730065007200310000 }

    condition:
        IsPeFile and $stringset
}
rule Hawkeye {
          meta:
            description = "detect HawkEye in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $hawkstr1 = "HawkEye Keylogger" wide
            $hawkstr2 = "Dear HawkEye Customers!" wide
            $hawkstr3 = "HawkEye Logger Details:" wide

          condition: all of them
}
rule RAT_HawkEye{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.06.2015"
		description = "Detects HawkEye RAT"
		reference = "http://malwareconfig.com/stats/HawkEye"
		maltype = "KeyLogger"
		filetype = "exe"

	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
		$string5 = "<!-- do not script -->" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "BSPLIT" wide

	condition:
		$key and $salt and all of ($string*)
}
rule HawkEye_Keylogger_Feb18_1 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
      date = "2018-02-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
   strings:
      $s1 = "UploadReportLogin.asmx" fullword wide
      $s2 = "tmp.exe" fullword wide
      $s3 = "%appdata%\\" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" ascii
      $s3 = "_PasswordStealer" ascii
   condition:
      2 of them
}
rule HawkEye_PHP_Panel {
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/12/14"
		score = 60
	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii
	condition:
		all of ($s*) and filesize < 600
}