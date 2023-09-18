rule webshell_php_by_string_obfuscation : FILE {
	meta:
		description = "PHP file containing obfuscation strings. Might be legitimate code obfuscated for whatever reasons, a webshell or can be used to insert malicious Javascript for credit card skimming"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2021/01/09"
		modified = "2022-10-25"
		hash = "e4a15637c90e8eabcbdc748366ae55996dbec926382220c423e754bd819d22bc"
	strings:
		$opbs13 = "{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" wide ascii
		$opbs14 = "/*-/*-*/\"" wide ascii
		$opbs16 = "'ev'.'al'" wide ascii
		$opbs17 = "'e'.'val'" wide ascii
		$opbs18 = "e'.'v'.'a'.'l" wide ascii
		$opbs19 = "bas'.'e6'." wide ascii
		$opbs20 = "ba'.'se6'." wide ascii
		$opbs21 = "as'.'e'.'6'" wide ascii
		$opbs22 = "gz'.'inf'." wide ascii
		$opbs23 = "gz'.'un'.'c" wide ascii
		$opbs24 = "e'.'co'.'d" wide ascii
		$opbs25 = "cr\".\"eat" wide ascii
		$opbs26 = "un\".\"ct" wide ascii
		$opbs27 = "'c'.'h'.'r'" wide ascii
		$opbs28 = "\"ht\".\"tp\".\":/\"" wide ascii
		$opbs29 = "\"ht\".\"tp\".\"s:" wide ascii
		$opbs31 = "'ev'.'al'" nocase wide ascii
		$opbs32 = "eval/*" nocase wide ascii
		$opbs33 = "eval(/*" nocase wide ascii
		$opbs34 = "eval(\"/*" nocase wide ascii
		$opbs36 = "assert/*" nocase wide ascii
		$opbs37 = "assert(/*" nocase wide ascii
		$opbs38 = "assert(\"/*" nocase wide ascii
		$opbs40 = "'ass'.'ert'" nocase wide ascii
		$opbs41 = "${'_'.$_}['_'](${'_'.$_}['__'])" wide ascii
		$opbs44 = "'s'.'s'.'e'.'r'.'t'" nocase wide ascii
		$opbs45 = "'P'.'O'.'S'.'T'" wide ascii
		$opbs46 = "'G'.'E'.'T'" wide ascii
		$opbs47 = "'R'.'E'.'Q'.'U'" wide ascii
		$opbs48 = "se'.(32*2)" nocase
		$opbs49 = "'s'.'t'.'r_'" nocase
		$opbs50 = "'ro'.'t13'" nocase
		$opbs51 = "c'.'od'.'e" nocase
		$opbs53 = "e'. 128/2 .'_' .'d"
        // move malicious code out of sight if line wrapping not enabled
		$opbs54 = "<?php                                                                                                                                                                                " //here I end
		$opbs55 = "=chr(99).chr(104).chr(114);$_"
		$opbs56 = "\\x47LOBAL"
		$opbs57 = "pay\".\"load"
		$opbs58 = "bas'.'e64"
		$opbs59 = "dec'.'ode"
		$opbs60 = "fla'.'te"
        // rot13 of eval($_POST
		$opbs70 = "riny($_CBFG["
		$opbs71 = "riny($_TRG["
		$opbs72 = "riny($_ERDHRFG["
		$opbs73 = "eval(str_rot13("
		$opbs74 = "\"p\".\"r\".\"e\".\"g\""
		$opbs75 = "$_'.'GET"
		$opbs76 = "'ev'.'al("
        // eval( in hex
		$opbs77 = "\\x65\\x76\\x61\\x6c\\x28" wide ascii nocase

		//strings from private rule capa_php_old_safe
		$php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"

		// of course the new tags should also match
        // already matched by "<?"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

		$fp1 = "NanoSpell TinyMCE Spellchecker for PHP" ascii fullword
	condition:
		filesize < 500KB and (
			(
				(
						$php_short in (0..100) or
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			)
			or any of ( $php_new* )
		)
		and any of ( $opbs* )
		and not 1 of ($fp*)
      and not filepath contains "\\Cache\\" /* generic cache e.g. for Chrome: \User Data\Default\Cache\ */
      and not filepath contains "\\User Data\\Default\\Extensions\\" // chrome extensions
      and not filepath contains "\\cache2\\" // FF cache
      and not filepath contains "\\Microsoft\\Windows\\INetCache\\IE\\" // old IE
      and not filepath contains "/com.apple.Safari/WebKitCache/"
      and not filepath contains "\\Edge\\User Data\\" // some uncommon Edge path
}
rule Acrotray_Anomaly {
	meta:
		description = "Detects an acrotray.exe that does not contain the usual strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 75
	strings:
		$s1 = "PDF/X-3:2002" fullword wide
		$s2 = "AcroTray - Adobe Acrobat Distiller helper application" fullword wide
		$s3 = "MS Sans Serif" fullword wide
		$s4 = "COOLTYPE.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB
		and ( filename == "acrotray.exe" or filename == "AcroTray.exe" )
		and not all of ($s*)
}
rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
	meta:
		description = "Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
	strings:
		$s1 = "VMware, Inc." wide fullword
		$s2 = "Virtual hardware upgrade helper service" fullword wide
		$s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		filename == "VmUpgradeHelper.exe" and
		not all of ($s*)
}
rule IronTiger_Gh0stRAT_variant{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Game Over Good Luck By Wind" nocase wide ascii
		$str2 = "ReleiceName" nocase wide ascii
		$str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
		$str4 = "Winds Update" nocase wide ascii fullword
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
		and not filename == "UpdateSystemMib.exe"
}
rule OpCloudHopper_Cloaked_PSCP {
   meta:
      description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}
rule msi_dll_Anomaly {
   meta:
      description = "Detetcs very small and supicious msi.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
   strings:
      $x1 = "msi.dll.eng" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 15KB and filename == "msi.dll" and $x1
}
rule PoS_Malware_MalumPOS_Config{
    meta:
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        date = "2015-06-25"
        description = "MalumPOS Config File"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"
    strings:
        $s1 = "[PARAMS]"
        $s2 = "Name="
        $s3 = "InterfacesIP="
        $s4 = "Port="
    condition:
        all of ($s*) and filename == "log.ini" and filesize < 20KB
}
rule Malware_QA_update_test {
	meta:
		description = "VT Research QA uploaded malware - file update_.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "3b3392bc730ded1f97c51e23611740ff8b218abf0a1100903de07819eeb449aa"
	strings:
		$s1 = "test.exe" fullword ascii
		$s2 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGP" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them and filename == "update.exe"
}
rule SysInterals_PipeList_NameChanged {
	meta:
		description = "Detects NirSoft PipeList"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
	strings:
		$s1 = "PipeList" ascii fullword
		$s2 = "Sysinternals License" ascii fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 170KB and all of them
		and not filename contains "pipelist.exe"
		and not filename contains "PipeList.exe"
}
rule SCT_Scriptlet_in_Temp_Inet_Files {
	meta:
		description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
	strings:
		$s1 = "<scriptlet>" fullword ascii nocase
		$s2 = "ActiveXObject(\"WScript.Shell\")" ascii
	condition:
		( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
		and $s1 and $s2
		and filepath contains "Temporary Internet Files"
}
rule HackTool_Producers {
   meta:
      description = "Hacktool Producers String"
      threat_level = 5
      score = 50
      nodeepdive = 1
   strings:
      $a1 = "www.oxid.it"
      $a2 = "www.analogx.com"
      $a3 = "ntsecurity.nu"
      $a4 = "gentilkiwi.com"
      $a6 = "Marcus Murray"
      $a7 = "Nsasoft US LLC0"
      $a8 = " Nir Sofer"
   condition:
      uint16(0) == 0x5a4d and 1 of ($a*) and
      not extension contains ".ini" and
      not extension contains ".xml" and
      not extension contains ".sqlite"
}
rule Exe_Cloaked_as_ThumbsDb{
    meta:
        description = "Detects an executable cloaked as thumbs.db - Malware"
        date = "2014-07-18"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 50
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}
rule Fake_AdobeReader_EXE{
    meta:
      description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
      date = "2014-09-11"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      nodeepdive = 1
      nodeepdive = 1
    strings:
      $s1 = "Adobe Systems" ascii

      $fp1 = "Adobe Reader" ascii wide
      $fp2 = "Xenocode Virtual Appliance Runtime" ascii wide
    condition:
      uint16(0) == 0x5a4d and
      filename matches /AcroRd32.exe/i and
      not $s1 in (filesize-2500..filesize)
      and not 1 of ($fp*)
}
rule mimikatz_lsass_mdmp{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
   strings:
      $lsass         = "System32\\lsass.exe"   wide nocase
   condition:
      (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}
rule lsadump {
   meta:
      description      = "LSA dump programe (bootkey/syskey) - pwdump and others"
      author         = "Benjamin DELPY (gentilkiwi)"
      score         = 80
      nodeepdive = 1
   strings:
      $str_sam_inc   = "\\Domains\\Account" ascii nocase
      $str_sam_exc   = "\\Domains\\Account\\Users\\Names\\" ascii nocase
      $hex_api_call   = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
      $str_msv_lsa   = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
      $hex_bkey      = { 4b 53 53 4d [20-70] 05 00 01 00}

      $fp1 = "Sysinternals" ascii
      $fp2 = "Apple Inc." ascii wide
      $fp3 = "Kaspersky Lab" ascii fullword
      $fp4 = "ESET Security" ascii
      $fp5 = "Disaster Recovery Module" wide
      $fp6 = "Bitdefender" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      (($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not 1 of ($fp*)
      and not filename contains "Regdat"
      and not filetype == "EXE"
      and not filepath contains "Dr Watson"
      and not extension == "vbs"
}
rule SUSP_ServU_SSH_Error_Pattern_Jul21_1 {
   meta:
      description = "Detects suspicious SSH component exceptions that could be an indicator of exploitation attempts as described in advisory addressing CVE-2021-35211 in ServU services"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
   strings:
      $s1 = "EXCEPTION: C0000005;" ascii
      $s2 = "CSUSSHSocket::ProcessReceive();" ascii
   condition:
      filename == "DebugSocketlog.txt"
      and all of ($s*)
}
rule SUSP_ServU_Known_Mal_IP_Jul21_1 {
   meta:
      description = "Detects suspicious IP addresses used in exploitation of ServU services CVE-2021-35211 and reported by Solarwinds"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
   strings:
      $xip1 = "98.176.196.89" ascii fullword 
      $xip2 = "68.235.178.32" ascii fullword
      $xip3 = "208.113.35.58" ascii fullword
      $xip4 = "144.34.179.162" ascii fullword
      $xip5 = "97.77.97.58" ascii fullword
   condition:
      filename == "DebugSocketlog.txt"
      and 1 of them
}
rule SUSP_EXPL_Confluence_RCE_CVE_2021_26084_Indicators_Sep21 {
   meta:
      description = "Detects ELF binaries owner by the confluence user but outside usual confluence directories"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://attackerkb.com/topics/Eu74wdMbEL/cve-2021-26084-confluence-server-ognl-injection/rapid7-analysis"
      date = "2021-09-01"
      score = 55
   condition:
      uint32be(0) == 0x7f454c46 /* ELF binary */
      and owner == "confluence"
      and not filepath contains "/confluence/"
}
rule SUSP_Blocked_Download_Proxy_Replacement_Jan23_1 {
   meta:
      description = "Detects a file that has been replaced with a note by a security solution like an Antivirus or a filtering proxy server"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/gui/search/filename%253A*.exe%2520tag%253Ahtml%2520size%253A10kb-%2520size%253A2kb%252B/files"
      date = "2023-01-28"
      score = 60
   strings:
      $x01 = "Web Filter Violation"
      $x02 = "Google Drive can't scan this file for viruses."
      $x03 = " target=\"_blank\">Cloudflare <img "
      $x04 = "Sorry, this file is infected with a virus.</p>"
      $x05 = "-- Sophos Warn FileType Page -->"
      $x06 = "<p>Certain Sophos products may not be exported for use by government end-users" // accept EULA 
      $x07 = "<p class=\"content-list\">Bitly displays this warning when a link has been flagged as suspect. There are many"
      $x08 = "Something went wrong. Don't worry, your files are still safe and the Dropbox team has been notified."
      $x09 = "<p>sinkhole</p>"
      $x10 = "The requested short link is blocked by website administration due to violation of the website policy terms."
      $x11 = "<img src=\"https://www.malwarebytes.com/images/"
      $x12 = "<title>Malwarebytes</title>"
      $x13 = "<title>Blocked by VIPRE</title>"
      $x14 = "<title>Your request appears to be from an automated process</title>"
      $x15 = "<p>Advanced Security blocked access to"
      $x16 = "<title>Suspected phishing site | Cloudflare</title>"
      $x17 = ">This link has been flagged "
      $x18 = "<h1>Trend Micro Apex One</h1>"
      $x19 = "Hitachi ID Identity and Access Management Suite"
      $x20 = ">http://www.fortinet.com/ve?vn="
      $x21 = "access to URL with fixed IP not allowed" // FritzBox
      $x23 = "<title>Web Page Blocked</title>"
      $x24 = "<title>Malicious Website Blocked</title>"
      $x25 = "<h2>STOPzilla has detected"
      $x26 = ">Seqrite Endpoint Security</span>"
      $x27 = "<TITLE>K7 Safe Surf</TITLE>"
      $x28 = "<title>Blocked by VIPRE</title>"

      $g01 = "blocked access" fullword
      $g02 = "policy violation" fullword
      $g03 = "violation of " 
      $g04 = "blocked by" fullword
      $g05 = "Blocked by" fullword
      $g07 = "Suspected Phishing"
      $g08 = "ile quarantined"
      $g09 = " is infected "
      $g10 = "Blocked</title>"
      $g11 = "site blocked" fullword
      $g12 = "Site Blocked" fullword
      $g13 = "blocked for" fullword
      $g14 = "is blocked" fullword
      $g15 = "potentially harmful"
      $g16 = "Page Blocked" fullword
      $g17 = "page blocked" fullword
   condition:
      extension == ".exe" and not uint16(0) == 0x5a4d and 1 of them
      or (
         extension == ".rar" or 
         extension == ".ps1" or 
         extension == ".vbs" or
         extension == ".bat"
      )
      and 1 of ($x*)
}
rule SUSP_APT_3CX_Regtrans_Anomaly_Apr23 : METARULE {
   meta:
      description = "Detects suspicious .regtrans-ms files with suspicious size or contents"
      author = "Florian Roth"
      reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
      date = "2023-04-12"
      score = 60
   strings:
      $fp1 = "REGISTRY" wide
   condition:
      extension == ".regtrans-ms" and (
         filesize < 100KB
         and not 1 of ($fp*)
      )
}
rule VULN_Linux_Sudoers_Commands {
	meta:
		description = "Detects sudoers config with commands which might allow privilege escalation to root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		reference = "https://wiki.archlinux.org/title/sudo"
		date = "2022-11-22"
		modified = "2023-02-18"
		score = 50
	strings:
		$command1 = "/sh " ascii
		$command2 = "/bash " ascii
		$command3 = "/ksh " ascii
		$command4 = "/csh " ascii
		$command5 = "/tcpdump " ascii
		$command6 = "/cat " ascii
		$command7 = "/head " ascii
		$command8 = "/nano " ascii
		$command9 = "/pico " ascii
		$command10 = "/rview " ascii
		$command11 = "/vi " ascii
		$command12 = "/vim " ascii
		$command13 = "/rvi " ascii
		$command14 = "/rvim " ascii
		$command15 = "/more " ascii
		$command16 = "/less " ascii
		$command17 = "/dd " ascii
		/* $command18 = "/mount " ascii prone to FPs */ 

	condition:
		( filename == "sudoers" or filepath contains "/etc/sudoers.d" ) and 
		any of ($command*)
}
rule VULN_Linux_NFS_Exports {
	meta:
		description = "Detects insecure /etc/exports NFS config which might allow privilege escalation to root or other users. The parameter insecure allows any non-root user to mount NFS shares via e.g. an SSH-tunnel. With no_root_squash SUID root binaries are allowed."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.errno.fr/nfs_privesc.html"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
	strings:
		// line has to start with / to avoid triggering on #-comment lines
		$conf1 = /\n\/.{2,200}?\binsecure\b/ ascii
		$conf2 = /\n\/.{2,200}?\bno_root_squash\b/ ascii

	condition:
		filename == "exports" and 
		filepath contains "/etc" and 
		any of ($conf*)
}
rule SUSP_AES_Key_in_MySql_History {
	meta:
		description = "Detects AES key outside of key management in .mysql_history"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
	strings:
		$c1 = /\bAES_(DE|EN)CRYPT\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii
		$c2 = /\baes_(de|en)crypt\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii

	condition:
		filename == ".mysql_history" and 
		any of ($c*)
}
rule VULN_Slapd_Conf_with_Default_Password {
	meta:
		description = "Detects an openldap slapd.conf with the default password test123"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		reference = "https://www.openldap.org/doc/admin21/slapdconfig.html"
		score = 70
	strings:
		/* \nrootpw \{SSHA\}fsAEyxlFOtvZBwPLAF68zpUhth8lERoR */
		$c1 = { 0A 72 6f 6f 74 70 77 20 7b 53 53 48 41 7d 66 73 41 45 79 78 6c 46 4f 74 76 5a 42 77 50 4c 41 46 36 38 7a 70 55 68 74 68 38 6c 45 52 6f 52 }

	condition:
		filename == "slapd.conf" and 
		any of ($c*)
}
rule VULN_Unencrypted_SSH_Private_Key : T1552_004 {
    meta:
        description = "Detects unencrypted SSH private keys with DSA, RSA, ECDSA and ED25519 of openssh or Putty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2023-01-06"
        reference = "https://attack.mitre.org/techniques/T1552/004/"
        score = 50
    strings:
        /*
            -----BEGIN RSA PRIVATE KEY-----
            MII
        */
        $openssh_rsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 }

        /*
            -----BEGIN DSA PRIVATE KEY-----
            MIIBvAIBAAKBgQ
        */
        $openssh_dsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 42 76 41 49 42 41 41 4b 42 67 51 }

        /*
            -----BEGIN EC PRIVATE KEY-----
            M
        */
        $openssh_ecdsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 45 43 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d }

        /*
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmU

            base64 contains: openssh-key-v1.....none
        */
        $openssh_ed25519 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 62 33 42 6c 62 6e 4e 7a 61 43 31 72 5a 58 6b 74 64 6a 45 41 41 41 41 41 42 47 35 76 62 6d 55 }

        $putty_start = "PuTTY-User-Key-File" ascii
        $putty_noenc = "Encryption: none" ascii

    condition:
        /*
            limit to folders and filenames which are known to contain ssh keys to avoid triggering on all those
            private keys for SSL, signing, ... which might be important but aren't usually used for lateral
            movement => bad signal noise ratio
        */
        (
            filepath contains "ssh" or
            filepath contains "SSH" or
            filepath contains "utty" or
            filename contains "ssh" or
            filename contains "SSH" or
            filename contains "id_" or
            filename contains "id2_" or
            filename contains ".ppk" or
            filename contains ".PPK" or
            filename contains "utty"
        )
        and
        (
            $openssh_dsa     at 0 or
            $openssh_rsa     at 0 or
            $openssh_ecdsa   at 0 or
            $openssh_ed25519 at 0 or
            (
                $putty_start at 0 and
                $putty_noenc
            )
        )
        and not filepath contains "/root/"
        and not filename contains "ssh_host_"
}
rule VULN_Unencrypted_SSH_Private_Key_Root_Folder : T1552_004 {
    meta:
        description = "Detects unencrypted SSH private keys with DSA, RSA, ECDSA and ED25519 of openssh or Putty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2023-01-06"
        reference = "https://attack.mitre.org/techniques/T1552/004/"
        score = 65
    strings:
        /*
            -----BEGIN RSA PRIVATE KEY-----
            MII
        */
        $openssh_rsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 }

        /*
            -----BEGIN DSA PRIVATE KEY-----
            MIIBvAIBAAKBgQ
        */
        $openssh_dsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 42 76 41 49 42 41 41 4b 42 67 51 }

        /*
            -----BEGIN EC PRIVATE KEY-----
            M
        */
        $openssh_ecdsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 45 43 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d }

        /*
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmU

            base64 contains: openssh-key-v1.....none
        */
        $openssh_ed25519 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 62 33 42 6c 62 6e 4e 7a 61 43 31 72 5a 58 6b 74 64 6a 45 41 41 41 41 41 42 47 35 76 62 6d 55 }

        $putty_start = "PuTTY-User-Key-File" ascii
        $putty_noenc = "Encryption: none" ascii

    condition:
        /*
            limit to folders and filenames which are known to contain ssh keys to avoid triggering on all those
            private keys for SSL, signing, ... which might be important but aren't usually used for lateral
            movement => bad signal noise ratio
        */
        (
            filepath contains "ssh" or
            filepath contains "SSH" or
            filepath contains "utty" or
            filename contains "ssh" or
            filename contains "SSH" or
            filename contains "id_" or
            filename contains "id2_" or
            filename contains ".ppk" or
            filename contains ".PPK" or
            filename contains "utty"
        )
        and
        (
            $openssh_dsa     at 0 or
            $openssh_rsa     at 0 or
            $openssh_ecdsa   at 0 or
            $openssh_ed25519 at 0 or
            (
                $putty_start at 0 and
                $putty_noenc
            )
        )
        and filepath contains "/root/"
        and not filename contains "ssh_host_"
}
rule SUSP_Known_Type_Cloaked_as_JPG {
   meta:
      description = "Detects a non-JPEG file type cloaked as .jpg"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - replacement for Cloaked_as_JPG rule"
      date = "2022-09-16"
      score = 60
   condition:
      ( extension == ".jpg" or extension == ".jpeg" ) and ( 
         filetype == "EXE" or
         filetype == "ELF" or
         filetype == "MACH-O" or
         filetype == "VBS" or
         filetype == "PHP" or
         filetype == "JSP" or
         filetype == "Python" or
         filetype == "LSASS Dump File" or
         filetype == "ASP" or
         filetype == "BATCH" or
         filetype == "RTF" or
         filetype == "MDMP" or

         filetype contains "PowerShell" or
         filetype contains "Base64"
      )
}
rule Suspicious_Size_explorer_exe {
   meta:
      description = "Detects uncommon file size of explorer.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-04-27"
      noarchivescan = 1
   strings:
      $fp = "Wine placeholder DLL"
   condition:
      uint16(0) == 0x5a4d
      and filename == "explorer.exe"
      and not filepath contains "teamviewer"
      and not filepath contains "/lib/wine/fakedlls"
      and ( filesize < 800KB or filesize > 6500KB )
      and not $fp
}
rule Suspicious_Size_chrome_exe {
    meta:
      description = "Detects uncommon file size of chrome.exe"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-09-15"
      noarchivescan = 1
    strings:
      $fp1 = "HP Sure Click Chromium Launcher" wide
      $fp2 = "BrChromiumLauncher.exe" wide fullword
    condition:
      uint16(0) == 0x5a4d
      and filename == "chrome.exe"
      and ( filesize < 500KB or filesize > 5000KB )
      and not 1 of ($fp*)
}
rule Suspicious_Size_csrss_exe {
    meta:
        description = "Detects uncommon file size of csrss.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        modified = "2022-01-28"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "csrss.exe"
        and ( filesize > 50KB )
}
rule Suspicious_Size_iexplore_exe {
    meta:
        description = "Detects uncommon file size of iexplore.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "iexplore.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 75KB or filesize > 910KB )
}
rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and ( filesize < 265KB or filesize > 910KB )
}
rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "java.exe"
        and ( filesize < 30KB or filesize > 900KB )
}
rule Suspicious_Size_lsass_exe {
    meta:
        description = "Detects uncommon file size of lsass.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "lsass.exe"
        and ( filesize < 10KB or filesize > 100KB )
}
rule Suspicious_Size_svchost_exe {
    meta:
        description = "Detects uncommon file size of svchost.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "svchost.exe"
        and ( filesize < 14KB or filesize > 100KB )
}
rule Suspicious_Size_winlogon_exe {
    meta:
        description = "Detects uncommon file size of winlogon.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "winlogon.exe"
        and ( filesize < 279KB or filesize > 970KB )
}
rule Suspicious_Size_igfxhk_exe {
    meta:
        description = "Detects uncommon file size of igfxhk.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-21"
        modified = "2022-03-08"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "igfxhk.exe"
        and ( filesize < 200KB or filesize > 300KB )
}
rule Suspicious_Size_servicehost_dll {
    meta:
        description = "Detects uncommon file size of servicehost.dll"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "servicehost.dll"
        and filesize > 150KB
}
rule Suspicious_Size_rundll32_exe {
    meta:
        description = "Detects uncommon file size of rundll32.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "rundll32.exe"
        and ( filesize < 30KB or filesize > 120KB )
}
rule Suspicious_Size_taskhost_exe {
    meta:
        description = "Detects uncommon file size of taskhost.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "taskhost.exe"
        and ( filesize < 45KB or filesize > 120KB )
}
rule Suspicious_Size_spoolsv_exe {
    meta:
        description = "Detects uncommon file size of spoolsv.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "spoolsv.exe"
        and ( filesize < 50KB or filesize > 1000KB )
}
rule Suspicious_Size_smss_exe {
    meta:
        description = "Detects uncommon file size of smss.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "smss.exe"
        and ( filesize < 40KB or filesize > 5000KB )
}
rule Suspicious_Size_wininit_exe {
    meta:
        description = "Detects uncommon file size of wininit.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "wininit.exe"
        and ( filesize < 90KB or filesize > 800KB )
}
rule WEBSHELL_ASPX_ProxyShell_Aug21_1 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and extension"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
   condition:
      uint32(0) == 0x4e444221 /* PST header: !BDN */
      and extension == ".aspx"
}
rule iexplore_ANOMALY {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Abnormal iexplore.exe - typical strings not found in file"
      date = "23/04/2014"
      score = 55
      nodeepdive = 1
   strings:
      $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
      $win2003_win7_u2 = "Internet Explorer" wide fullword
      $win2003_win7_u3 = "translation" wide fullword nocase
      $win2003_win7_u4 = "varfileinfo" wide fullword nocase
   condition:
      filename == "iexplore.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
      and filepath contains "C:\\"
      and not filepath contains "Package_for_RollupFix"
}
rule svchost_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal svchost.exe - typical strings not found in file"
		date = "23/04/2014"
		score = 55
	strings:
		$win2003_win7_u1 = "svchost.exe" wide nocase
		$win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase
		$win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase
		$win2000 = "Generic Host Process for Win32 Services" wide fullword
		$win2012 = "Host Process for Windows Services" wide fullword
	condition:
		filename == "svchost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}
rule explorer_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal explorer.exe - typical strings not found in file"
		date = "27/05/2014"
		score = 55
	strings:
		$s1 = "EXPLORER.EXE" wide fullword
		$s2 = "Windows Explorer" wide fullword
	condition:
		filename == "explorer.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule sethc_ANOMALY {
	meta:
		description = "Sethc.exe has been replaced - Indicates Remote Access Hack RDP"
		author = "F. Roth"
		reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
		date = "2014/01/23"
		score = 70
	strings:
		$s1 = "stickykeys" fullword nocase
		$s2 = "stickykeys" wide nocase
		$s3 = "Control_RunDLL access.cpl" wide fullword
		$s4 = "SETHC.EXE" wide fullword
	condition:
		filename == "sethc.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule Utilman_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal utilman.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 70
	strings:
		$win7 = "utilman.exe" wide fullword
		$win2000 = "Start with Utility Manager" fullword wide
		$win2012 = "utilman2.exe" fullword wide
	condition:
		( filename == "utilman.exe" or filename == "Utilman.exe" )
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}
rule osk_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal osk.exe (On Screen Keyboard) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$s1 = "Accessibility On-Screen Keyboard" wide fullword
		$s2 = "\\oskmenu" wide fullword
		$s3 = "&About On-Screen Keyboard..." wide fullword
		$s4 = "Software\\Microsoft\\Osk" wide
	condition:
		filename == "osk.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule magnify_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal magnify.exe (Magnifier) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "Microsoft Screen Magnifier" wide fullword
		$win2000 = "Microsoft Magnifier" wide fullword
		$winxp = "Software\\Microsoft\\Magnify" wide
	condition:
		filename =="magnify.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}
rule narrator_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal narrator.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "Microsoft-Windows-Narrator" wide fullword
		$win2000 = "&About Narrator..." wide fullword
		$win2012 = "Screen Reader" wide fullword
		$winxp = "Software\\Microsoft\\Narrator"
		$winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide
	condition:
		filename == "narrator.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}
rule notepad_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal notepad.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
	strings:
		$win7 = "HELP_ENTRY_ID_NOTEPAD_HELP" wide fullword
		$win2000 = "Do you want to create a new file?" wide fullword
		$win2003 = "Do you want to save the changes?" wide
		$winxp = "Software\\Microsoft\\Notepad" wide
		$winxp_de = "Software\\Microsoft\\Notepad" wide
	condition:
		filename == "notepad.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}
rule csrss_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file csrss.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "17542707a3d9fa13c569450fd978272ef7070a77"
	strings:
		$s1 = "Client Server Runtime Process" fullword wide
		$s4 = "name=\"Microsoft.Windows.CSRSS\"" fullword ascii
		$s5 = "CSRSRV.dll" fullword ascii
		$s6 = "CsrServerInitialization" fullword ascii
	condition:
		filename == "csrss.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule conhost_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file conhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "1bd846aa22b1d63a1f900f6d08d8bfa8082ae4db"
	strings:
		$s2 = "Console Window Host" fullword wide
	condition:
		filename == "conhost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule wininit_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file wininit.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "2de5c051c0d7d8bcc14b1ca46be8ab9756f29320"
	strings:
		$s1 = "Windows Start-Up Application" fullword wide
	condition:
		filename == "wininit.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule winlogon_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file winlogon.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "af210c8748d77c2ff93966299d4cd49a8c722ef6"
	strings:
		$s1 = "AuthzAccessCheck failed" fullword
		$s2 = "Windows Logon Application" fullword wide
	condition:
		filename == "winlogon.exe"
      and not 1 of ($s*)
      and uint16(0) == 0x5a4d
		and not WINDOWS_UPDATE_BDC
		and not filepath contains "Malwarebytes"
}
rule SndVol_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file SndVol.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "e057c90b675a6da19596b0ac458c25d7440b7869"
	strings:
		$s1 = "Volume Control Applet" fullword wide
	condition:
		filename == "sndvol.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule doskey_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file doskey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "f2d1995325df0f3ca6e7b11648aa368b7e8f1c7f"
	strings:
		$s3 = "Keyboard History Utility" fullword wide
	condition:
		filename == "doskey.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule lsass_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file lsass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "04abf92ac7571a25606edfd49dca1041c41bef21"
	strings:
		$s1 = "LSA Shell" fullword wide
		$s2 = "<description>Local Security Authority Process</description>" fullword ascii
		$s3 = "Local Security Authority Process" fullword wide
		$s4 = "LsapInitLsa" fullword
	condition:
		filename == "lsass.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}
rule taskmgr_ANOMALY {
   meta:
      description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file taskmgr.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/03/16"
      nodeepdive = 1
      hash = "e8b4d84a28e5ea17272416ec45726964fdf25883"
   strings:
      $s0 = "Windows Task Manager" fullword wide
      $s1 = "taskmgr.chm" fullword
      $s2 = "TmEndTaskHandler::" ascii
      $s3 = "CM_Request_Eject_PC" /* Win XP */
      $s4 = "NTShell Taskman Startup Mutex" fullword wide
   condition:
      ( filename == "taskmgr.exe" or filename == "Taskmgr.exe" ) and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
      and uint16(0) == 0x5a4d
      and filepath contains "C:\\"
      and not filepath contains "Package_for_RollupFix"
}
rule APT_Cloaked_PsExec{
	meta:
		description = "Looks like a cloaked PsExec. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
	strings:
		$s0 = "psexesvc.exe" wide fullword
		$s1 = "Sysinternals PsExec" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1
		and not filename matches /(psexec.exe|PSEXESVC.EXE|PsExec64.exe)$/is
		and not filepath matches /RECYCLE.BIN\\S-1/
}
rule APT_Cloaked_SuperScan
	{
	meta:
		description = "Looks like a cloaked SuperScan Port Scanner. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
	strings:
		$s0 = "SuperScan4.exe" wide fullword
		$s1 = "Foundstone Inc." wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and not filename contains "superscan"
}
rule APT_Cloaked_ScanLine
	{
	meta:
		description = "Looks like a cloaked ScanLine Port Scanner. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
	strings:
		$s0 = "ScanLine" wide fullword
		$s1 = "Command line port scanner" wide fullword
		$s2 = "sl.exe" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and $s2 and not filename == "sl.exe"
}
rule SAM_Hive_Backup{
	meta:
		description = "Detects a SAM hive backup file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump"
		score = 60
		date = "2015/03/31"
	strings:
		$s1 = "\\SystemRoot\\System32\\Config\\SAM" wide fullword
	condition:
		uint32(0) == 0x66676572 and $s1 in (0..100) and
			not filename contains "sam.log" and
         not filename contains "SAM.LOG" and
			not filename contains "_sam" and
			not filename == "SAM" and
			not filename == "sam"
}
rule SUSP_Renamed_Dot1Xtray {
   meta:
      description = "Detects a legitimate renamed dot1ctray.exe, which is often used by PlugX for DLL side-loading"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-11-15"
      hash1 = "f9ebf6aeb3f0fb0c29bd8f3d652476cd1fe8bd9a0c11cb15c43de33bbce0bf68"
   strings:
      $a1 = "\\Symantec_Network_Access_Control\\"  ascii
      $a2 = "\\dot1xtray.pdb" ascii
      $a3 = "DOT1X_NAMED_PIPE_CONNECT" fullword wide /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
      and not filename matches /dot1xtray.exe/i
      and not filepath matches /Recycle.Bin/i
}
rule APT_Cloaked_CERTUTIL {
   meta:
      description = "Detects a renamed certutil.exe utility that is often used to decode encoded payloads"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-14"
      modified = "2022-06-27"
   strings:
      $s1 = "-------- CERT_CHAIN_CONTEXT --------" fullword ascii
      $s5 = "certutil.pdb" fullword ascii
      $s3 = "Password Token" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
      and not filename contains "certutil"
      and not filename contains "CertUtil"
      and not filename contains "Certutil"
      and not filepath contains "\\Bromium\\"
}
rule APT_SUSP_Solarwinds_Orion_Config_Anomaly_Dec20 {
   meta:
      description = "Detects a suspicious renamed Afind.exe as used by different attackers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/iisresetme/status/1339546337390587905?s=12"
      date = "2020-12-15"
      score = 70
      nodeepdive = 1
   strings:
      $s1 = "ReportWatcher" fullword wide ascii 
      
      $fp1 = "ReportStatus" fullword wide ascii
   condition:
      filename == "SolarWindows.Orion.Core.BusinessLayer.dll.config"
      and $s1 
      and not $fp1
}
rule PAExec_Cloaked {
   meta:
      description = "Detects a renamed remote access tool PAEXec (like PsExec)"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 70
      hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
   strings:
      $x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
      $x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
      $x3 = "PAExec %s - Execute Programs Remotely" fullword wide
      $x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
      $x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
      $x6 = "%%SystemRoot%%\\%s.exe" fullword wide
      $x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
      $x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of ($x*) )
      and not filename == "paexec.exe"
      and not filename == "PAExec.exe"
      and not filename == "PAEXEC.EXE"
      and not filename matches /Install/
      and not filename matches /uninstall/
}
rule EXE_cloaked_as_TXT {
	meta:
		description = "Executable with TXT extension"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
	condition:
		uint16(0) == 0x5a4d 					// Executable
		and filename matches /\.txt$/is   // TXT extension (case insensitive)
}
rule EXE_extension_cloaking {
	meta:
		description = "Executable showing different extension (Windows default 'hide known extension')"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
	condition:
		filename matches /\.txt\.exe$/is or	// Special file extensions
		filename matches /\.pdf\.exe$/is		// Special file extensions
}
rule Cloaked_RAR_File {
	meta:
		description = "RAR file cloaked by a different extension"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
	condition:
		uint32be(0) == 0x52617221							// RAR File Magic Header
		and not filename matches /(rarnew.dat|\.rar)$/is	// not the .RAR extension
		and not filename matches /\.[rR][\d]{2}$/           // split RAR file
		and not filepath contains "Recycle" 				// not a deleted RAR file in recycler
}
rule Base64_encoded_Executable : FILE {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-28"
		score = 40
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
	condition:
		1 of them
		and not filepath contains "Thunderbird"
      and not filepath contains "Internet Explorer"
      and not filepath contains "Chrome"
      and not filepath contains "Opera"
      and not filepath contains "Outlook"
      and not filepath contains "Temporary Internet Files"
}
include "utility/IsPeFile.yara"
include "utility/IsElfFile.yara"
include "utility/IsZipFile.yara"
include "alphacrypt.yara"
include "appraisel.yara"
include "billgates.yara"
include "conbot.yara"
include "ggupdate.yara"
include "granite_coroner.yara"
include "hawkeye.yara"
include "l_exe.yara"
include "libgcc.yara"
include "mimikatz.yara"
include "regin.yara"
include "scrtest.yara"
include "sqldb.yara"
include "turla.yara"
include "viewweb.yara"
include "wiper.yara"
include "packers/aspack.yara"
include "packers/nkh.yara"
include "packers/rlpack.yara"
include "packers/sogu_packer.yara"
include "packers/upx.yara"
include "packers/vmprotect.yara"
include "features/command_shell.yara"
include "features/virtualbox_detection.yara"
rule ggupdate_windows {
    meta:
        description = "ggupdate.exe keylogger (Windows)"

    strings:
        // 9706A7D1479EB0B5E60535A952E63F1A
        // these strings are located in the packer or are unprotected
        $s1 = "Les Blues"
        $s2 = "lesblues.exe"
        $s3 = "Boodled8"
        $s4 = "Misexplain6"
        $s5 = "lesblues"
        $s6 = "Sniffs5"
        $s7 = "Oneiromancy"
        $s8 = "Lophtcrack" ascii wide

    condition:
        IsPeFile and 3 of them
}
rule ggupdate_linux {
    meta:
        description = "ggupdate keylogger (Linux)"

    strings:
        // 4611DAA8CF018B897A76FBAB51665C62
        $s1 = "%s.Identifier"
        $s2 = "0:%llu:%s;"
        $s3 = "%s%.2d-%.2d-%.4d"
        $s4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

    condition:
        IsElfFile and 3 of them
}
rule EntryPointExample {
	strings:
		$ep = { 55 8b ec }

	condition:
		$ep at entrypoint
}
rule libgcc_backdoor {
    strings:
        // Decode:
        // >>> def sar(value, n):
        //     return  value >> n if (value & 0x80000000) == 0 else (value >> n) | (0xFFFFFFFF << (32-n))
        // >>> def decode(s):
        //     key = 'BB2FA36AAA9541F0'
        //     result = ''
        //     for i in xrange(len(s)):
        //         ecx = i
        //         eax = ecx
        //         eax = sar(eax, 0x1F)
        //         eax &= 0xFFFFFFFF
        //         eax >>= 0x1C
        //         edx = ecx+eax
        //         edx &= 0x0F
        //         edx -= eax
        //         eax = ord(key[edx])
        //         result += chr(ord(s[i]) ^ eax)
        //     return result

        // File EAF2CF628D1DBC78B97BAFD7A9F4BEE4
        $decode_fn = { 89C8C1F81FC1E81C8D140183E20F29C20FB682????????30041983C10139F175DF }
        $decryption_key = "BB2FA36AAA9541F0"
        $function1 = "exec_packet"
        $function2 = "build_udphdr"
        $function3 = "build_tcphdr"
        $function4 = "http_download_mem"
        $function5 = "daemon_get_kill_process"


    condition:
        IsElfFile and ($decode_fn or $decryption_key or all of ($function*))
}
rule billgates {
    strings:
        // D66EA6D84F04358925DC220003997BD8 @ 0804B4B6
        $decrypt = { 5589E583EC10C745FC00000000EB378B45FC83E00184C074158B45FC89C20355088B45FC0345108A00408802EB138B45FC89C20355088B45FC0345108A004888028D45FCFF008B45FC3B45147D148B45FC3B450C7D0C8B45FC0345108A0084C075ADC9C3 }

        // BDA324786F1E8212A11F6AC5C612FB1E
        $source_file1 = "AmpResource.cpp"
        $source_file2 = "Attack.cpp"
        $source_file3 = "AutoLock.cpp"
        $source_file4 = "CmdMsg.cpp"
        $source_file5 = "ExChange.cpp"
        $source_file6 = "MiniHttpHelper.cpp"
        $source_file7 = "NetBase.cpp"
        $source_file8 = "ProtocolUtil.cpp"
        $source_file9 = "ProvinceDns.cpp"
        $source_file10 = "RSA.cpp"
        $source_file11 = "StatBase.cpp"
        $source_file12 = "ThreadAtk.cpp"
        $source_file13 = "ThreadClientStatus.cpp"
        $source_file14 = "ThreadFakeDetect.cpp"
        $source_file15 = "ThreadHttpGet.cpp"
        $source_file16 = "ThreadLoopCmd.cpp"
        $source_file17 = "ThreadMonGates.cpp"
        $source_file18 = "ThreadMutex.cpp"
        $source_file19 = "ThreadShell.cpp"
        $source_file20 = "UserAgent.cpp"
        $source_file21 = "WinDefSVC.cpp"

        $string1 = "AppleWebKit"
        $string2 = "/etc/rc%d.d/S%d%s"
        $string3 = "/tmp/gates.lock"
        $string4 = "chmod 0755 %s"
        $string5 = "%7s %llu %lu %lu %lu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu %lu"
        $string6 = "cpu %llu %llu %llu %llu"
        $string7 = "libamplify.so"
        $string8 = "/tmp/moni.lock"
        $string9 = "/usr/bin/.sshd"
        
    condition:
        IsElfFile and ($decrypt or 10 of ($source_file*) or 7 of ($string*))
}
private rule IsPeFile {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550
}

rule HackTool_MSIL_Rubeus_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
rule Trojan_Raw_Generic_4{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}
rule HackTool_Win32_AndrewSpecial_1{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "e89efa88e3fda86be48c0cc8f2ef7230"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $dump = { 6A 00 68 FF FF 1F 00 FF 15 [4] 89 45 ?? 83 [2] 00 [1-50] 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 10 68 [4] FF 15 [4] 89 45 [10-70] 6A 00 6A 00 6A 00 6A 02 8B [2-4] 5? 8B [2-4] 5? 8B [2-4] 5? E8 [4-20] FF 15 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
        $shellcode_x86_inline = { C6 45 ?? B8 C6 45 ?? 3C C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 33 C6 45 ?? C9 C6 45 ?? 8D C6 45 ?? 54 C6 45 ?? 24 C6 45 ?? 04 C6 45 ?? 64 C6 45 ?? FF C6 45 ?? 15 C6 45 ?? C0 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 83 C6 45 ?? C4 C6 45 ?? 04 C6 45 ?? C2 C6 45 ?? 14 C6 45 ?? 00 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and $dump and any of ($shellcode*)
}
rule APT_Backdoor_Win_GORAT_3{
    meta:
        description = "This rule uses the same logic as FE_APT_Trojan_Win_GORAT_1_FEBeta with the addition of one check, to look for strings that are known to be in the Gorat implant when a certain cleaning script is not run against it."
        md5 = "995120b35db9d2f36d7d0ae0bfc9c10d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $dirty1 = "fireeye" ascii nocase wide
        $dirty2 = "kulinacs" ascii nocase wide
        $dirty3 = "RedFlare" ascii nocase wide
        $dirty4 = "gorat" ascii nocase wide
        $dirty5 = "flare" ascii nocase wide
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000 and any of ($dirty*)
}
rule CredTheft_Win_EXCAVATOR_1{
    meta:
        description = "This rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes2 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes3 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
        $bytes4 = { 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8D 6C 24 ?? 48 81 EC 20 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 ?? 48 8D 0D ?? ?? ?? ?? 4C 89 74 24 ?? 0F 11 45 ?? 41 8B FE 4C 89 74 24 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? FF 15 ?? ?? ?? ?? 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 66 0F 1F 84 00 ?? ?? 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 ?? 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 01 00 48 8D 05 ?? ?? ?? ?? B9 C8 05 00 00 90 F3 0F 6F 40 ?? 48 8D 40 ?? 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? F3 0F 6F 40 ?? 66 0F EF C2 F3 0F 7F 40 ?? 48 83 E9 01 75 ?? FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 45 ?? 41 B9 02 00 00 00 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 02 00 00 00 41 8D 51 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 4C 8B 44 24 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 48 8B C8 41 8D 50 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 ?? 4C 8D 4C 24 ?? 4C 89 74 24 ?? 33 D2 41 B8 00 00 02 00 48 C7 44 24 ?? 08 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 45 ?? 48 89 7D ?? 48 89 44 24 ?? 45 33 C9 4C 89 74 24 ?? 33 D2 4C 89 74 24 ?? C7 44 24 ?? 04 00 08 00 44 89 74 24 ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 8B 5D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA FF FF FF FF 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 C0 48 8B 9C 24 ?? ?? ?? ?? 48 8B 4D ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 73 ?? 49 8B 7B ?? 4D 8B 73 ?? 49 8B E3 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}
rule APT_Loader_Win64_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "f20824fa6e5c81e3804419f108445368"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Raw64_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}
rule HackTool_MSIL_SHARPZEROLOGON_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'sharpzerologon' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_CoreHound_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CoreHound' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "1fff2aee-a540-4613-94ee-4f208b30c599" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_NETAssemblyInject_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "af09c8c3-b271-4c6c-8f48-d5f0e1d1cac6" ascii nocase wide
        $typelibguid1 = "c5e56650-dfb0-4cd9-8d06-51defdad5da1" ascii nocase wide
        $typelibguid2 = "e8fa7329-8074-4675-9588-d73f88a8b5b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Hunting_GadgetToJScript_1{
    meta:
        description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
        $s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
        $s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"
    condition:
        any of them
}
rule Trojan_MSIL_GORAT_Plugin_DOTNET_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "cd9407d0-fc8d-41ed-832d-da94daa3e064" ascii nocase wide
        $typelibguid1 = "fc3daedf-1d01-4490-8032-b978079d8c2d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Dropper_Win64_MATRYOSHKA_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
        $sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_MSIL_SHARPGOPHER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_KeeFarce_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeeFarce' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "17589ea6-fcc9-44bb-92ad-d5b3eea6af03" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Backdoor_Win_GORAT_1{
    meta:
        description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
        md5 = "66cdaa156e4d372cfa3dea0137850d20"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "httpComms.dll" ascii wide
        $s2 = "Cookie: SID1=%s" ascii wide
        $s3 = "Global\\" ascii wide
        $s4 = "stage0.dll" ascii wide
        $s5 = "runCommand" ascii wide
        $s6 = "getData" ascii wide
        $s7 = "initialize" ascii wide
        $s8 = "Windows NT %d.%d;" ascii wide
        $s9 = "!This program cannot be run in DOS mode." ascii wide
    condition:
        filesize < 50KB and all of them
}
rule APT_Dropper_Win_MATRYOSHKA_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "\x00matryoshka.exe\x00"
        $s2 = "\x00Unable to write data\x00"
        $s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
        $s4 = "\x00.execmdstart/Cfailed to execute process\x00"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_Win_Generic_20{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "5125979110847d35a338caac6bff2aa8"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win32_PGF_2{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "04eb45f8546e052fe348fda2425b058c"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
        $sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
        $sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_REDTEAMMATERIALS_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
        $typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_7{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "NamedPipe"
        $named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Trojan_Win_REDFLARE_8{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "PSRunner.PSRunner" fullword
        $2 = "CorBindToRuntime" fullword
        $3 = "ReportEventW" fullword
        $4 = "InvokePS" fullword wide
        $5 = "runCommand" fullword
        $6 = "initialize" fullword
        $trap = { 03 40 00 80 E8 [4] CC }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_Win_GORAT_5{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "comms.BeaconData" fullword
        $2 = "comms.CommandResponse" fullword
        $3 = "rat.BaseChannel" fullword
        $4 = "rat.Config" fullword
        $5 = "rat.Core" fullword
        $6 = "platforms.AgentPlatform" fullword
        $7 = "GetHostID" fullword
        $8 = "/rat/cmd/gorat_shared/dllmain.go" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_GPOHUNT_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "751a9270-2de0-4c81-9e29-872cd6378303" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_JUSTASK_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_4{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_TITOSPECIAL_1{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
        $ind_s1 = "NtReadVirtualMemory" fullword wide
        $ind_s2 = "WriteProcessMemory" fullword
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($ind*) and any of ($shellcode* )
}
rule Dropper_LNK_LNKSmasher_1{
    meta:
        description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
        md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $drive_serial = { 12 F7 26 BE }
        $file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
        $guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        $header at 0 and all of them
}
rule HackTool_MSIL_SharpSchtask_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpSchtask' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "0a64a5f4-bdb6-443c-bdc7-f6f0bf5b5d6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Controller_Linux_REDFLARE_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "/RedFlare/gorat_server"
        $2 = "RedFlare/sandals"
        $3 = "goratsvr.CommandResponse" fullword
        $4 = "goratsvr.CommandRequest" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}
rule APT_HackTool_MSIL_WMISPY_2{
    meta:
        description = "wql searches"
        md5 = "3651f252d53d2f46040652788499d65a"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $str1 = "root\\cimv2" wide
        $str2 = "root\\standardcimv2" wide
        $str3 = "from MSFT_NetNeighbor" wide
        $str4 = "from Win32_NetworkLoginProfile" wide
        $str5 = "from Win32_IP4RouteTable" wide
        $str6 = "from Win32_DCOMApplication" wide
        $str7 = "from Win32_SystemDriver" wide
        $str8 = "from Win32_Share" wide
        $str9 = "from Win32_Process" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of ($str*)
}
rule HackTool_MSIL_SharPersist_2{
    meta:
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $a1 = "SharPersist.lib"
        $a2 = "SharPersist.exe"
        $b1 = "ERROR: Invalid hotkey location option given." ascii wide
        $b2 = "ERROR: Invalid hotkey given." ascii wide
        $b3 = "ERROR: Keepass configuration file not found." ascii wide
        $b4 = "ERROR: Keepass configuration file was not found." ascii wide
        $b5 = "ERROR: That value already exists in:" ascii wide
        $b6 = "ERROR: Failed to delete hidden registry key." ascii wide
        $pdb1 = "\\SharPersist\\"
        $pdb2 = "\\SharPersist.pdb"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@pdb2[1] < @pdb1[1] + 50) or (1 of ($a*) and 2 of ($b*))
}
rule APT_Loader_Win_MATRYOSHKA_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "ZwQueryInformationProcess" fullword
        $s2 = "WriteProcessMemory" fullword
        $s3 = "CreateProcessW" fullword
        $s4 = "WriteProcessMemory" fullword
        $s5 = "\x00Invalid NT Signature!\x00"
        $s6 = "\x00Error while creating and mapping section. NTStatus: "
        $s7 = "\x00Error no process information - NTSTATUS:"
        $s8 = "\x00Error while erasing pe header. NTStatus: "
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule Builder_MSIL_SinfulOffice_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SinfulOffice' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "9940e18f-e3c7-450f-801a-07dd534ccb9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_SharPy_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharPy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "f6cf1d3b-3e43-4ecf-bb6d-6731610b4866" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_MSIL_WILDCHILD_1{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "6f04a93753ae3ae043203437832363c4"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "\x00QueueUserAPC\x00"
        $s2 = "\x00WriteProcessMemory\x00"
        $sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_Win_Generic_18{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_MSIL_HOLSTER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the a customized version of the 'DUEDLLIGENCE' project."
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_MSIL_TRIMBISHOP_1{
    meta:
        date = "2020-12-03"
        modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}
rule APT_Loader_MSIL_TRIMBISHOP_2{
    meta:
        date = "2020-12-03"
        modified = "2020-12-03"
        md5 = "c0598321d4ad4cf1219cc4f84bad4094"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_Win_DShell_3{
    meta:
        description = "This rule looks for strings specific to the D programming language in combination with sections of an integer array which contains the encoded payload found within DShell"
        md5 = "cf752e9cd2eccbda5b8e4c29ab5554b6"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $dlang1 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang2 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang3 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang6 = "\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang7 = "\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang8 = "\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang9 = "\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang10 = "\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang11 = "Unexpected '\\n' when converting from type const(char)[] to type int" ascii wide
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and filesize < 1500KB and 40 of ($e*) and 1 of ($dlang*)
}
rule APT_HackTool_MSIL_SHARPSTOMP_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = "mscoree.dll" fullword nocase
        $s1 = "timestompfile" fullword nocase
        $s2 = "sharpstomp" fullword nocase
        $s3 = "GetLastWriteTime" fullword
        $s4 = "SetLastWriteTime" fullword
        $s5 = "GetCreationTime" fullword
        $s6 = "SetCreationTime" fullword
        $s7 = "GetLastAccessTime" fullword
        $s8 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPPATCHCHECK_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharppatchcheck' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "528b8df5-6e5e-4f3b-b617-ac35ed2f8975" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SAFETYKATZ_4{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
        md5 = "45736deb14f3a68e88b038183c23e597"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Backdoor_MacOS_GORAT_1{
    meta:
        description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
        md5 = "68acf11f5e456744262ff31beae58526"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "SID1=%s" ascii wide
        $s2 = "http/http.dylib" ascii wide
        $s3 = "Mozilla/" ascii wide
        $s4 = "User-Agent" ascii wide
        $s5 = "Cookie" ascii wide
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}
rule CredTheft_MSIL_ADPassHunt_2{
    meta:
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $pdb1 = "\\ADPassHunt\\"
        $pdb2 = "\\ADPassHunt.pdb"
        $s1 = "Usage: .\\ADPassHunt.exe"
        $s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
        $s3 = "[ADA] Searching for accounts with userpassword attribute"
        $s4 = "[GPP] Searching for passwords now"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@pdb2[1] < @pdb1[1] + 50) or 2 of ($s*)
}
rule APT_Loader_Win64_PGF_4{
    meta:
        date = "2020-11-26"
        modified = "2020-11-26"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
        $sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Win32_PGF_4{
    meta:
        date = "2020-11-26"
        modified = "2020-11-26"
        md5 = "4414953fa397a41156f6fa4f9462d207"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
        $sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule CredTheft_MSIL_ADPassHunt_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
rule HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "a5da1897-29aa-45f4-a924-561804276f08" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_1{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
        $s3 = "cmd_rpc" wide
        $s4 = "costura"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win32_PGF_3{
    meta:
        description = "PGF payload, generated rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
        md5 = "4414953fa397a41156f6fa4f9462d207"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond2 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF B0 EF 3D 6A C7 85 30 F9 FF FF 8C FF 3D 6A 8D 85 34 F9 FF FF 89 28 BA F4 1A 3C 6A 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 B3 A6 00 00 A1 64 A1 41 6A C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B0 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 4E 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 D7 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 4A 0B 01 00 A1 68 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 49 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 E7 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 7A FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 7C AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 62 40 41 6A A1 78 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 6E 40 41 6A 89 04 24 A1 7C A1 41 6A FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 41 6A FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 3C 6A 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 3C 6A 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 55 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 40 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 98 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 F5 BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 6D A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 6E A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond3 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF F0 EF D5 63 C7 85 30 F9 FF FF CC FF D5 63 8D 85 34 F9 FF FF 89 28 BA 28 1B D4 63 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BF A6 00 00 A1 64 A1 D9 63 C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 BC AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 5A 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 E3 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 56 0B 01 00 A1 68 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 55 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 F3 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 86 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 88 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 7E 40 D9 63 A1 7C A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 8A 40 D9 63 89 04 24 A1 80 A1 D9 63 FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 D9 63 FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 D4 63 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 D4 63 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 61 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 4C 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A4 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 01 BC 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 79 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 7A A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
        $cond4 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? 90 EE 01 6D C7 85 ?? ?? ?? ?? 6C FE 01 6D 8D 85 ?? ?? ?? ?? 89 28 BA CC 19 00 6D 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 0C 40 05 6D A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 18 40 05 6D 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 00 6D 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 00 6D 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond5 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? B0 EF 3D 6A C7 85 ?? ?? ?? ?? 8C FF 3D 6A 8D 85 ?? ?? ?? ?? 89 28 BA F4 1A 3C 6A 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 62 40 41 6A A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 6E 40 41 6A 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 3C 6A 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 3C 6A 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
        $cond6 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? F0 EF D5 63 C7 85 ?? ?? ?? ?? CC FF D5 63 8D 85 ?? ?? ?? ?? 89 28 BA 28 1B D4 63 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 7E 40 D9 63 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 8A 40 D9 63 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 D4 63 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 D4 63 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}
rule APT_Loader_Win32_REDFLARE_2{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "4e7e90c7147ee8aa01275894734f4492"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_SHARPSTOMP_2{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $f0 = "mscoree.dll" fullword nocase
        $s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
        $s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
        $s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
        $s3 = "SetCreationTime" fullword
        $s4 = "GetLastAccessTime" fullword
        $s5 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule Loader_MSIL_NetshShellCodeRunner_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NetshShellCodeRunner' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "49c045bc-59bb-4a00-85c3-4beb59b2ee12" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_4{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "44B83A69-349F-4A3E-8328-A45132A70D62" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Backdoor_Win_GoRat_Memory{
    meta:
        description = "Identifies GoRat malware in memory based on strings."
        md5 = "3b926b5762e13ceec7ac3a61e85c93bb"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        /* $murica = "murica" fullword */
        $rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat2 = "rat.(*Core).generateBeacon" fullword
        $rat3 = "rat.gJitter" fullword
        $rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
        $rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
        $rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
        $rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
        $rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
        $rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
        $rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
        $rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
        $winblows = "rat/platforms/win.(*winblows).GetStage" fullword
    condition:
        $winblows or 
        // #murica > 10 or 
        3 of ($rat*)
}
rule Loader_MSIL_AllTheThings_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'AllTheThings' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "542ccc64-c4c3-4c03-abcd-199a11b26754" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win64_PGF_1{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
        $sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
        $sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Trojan_Win_REDFLARE_5{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule CredTheft_MSIL_TitoSpecial_1{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $str1 = "Minidump" ascii wide
        $str2 = "dumpType" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $str4 = "bInheritHandle" ascii wide
        $str5 = "GetProcessById" ascii wide
        $str6 = "SafeHandle" ascii wide
        $str7 = "BeginInvoke" ascii wide
        $str8 = "EndInvoke" ascii wide
        $str9 = "ConsoleApplication1" ascii wide
        $str10 = "getOSInfo" ascii wide
        $str11 = "OpenProcess" ascii wide
        $str12 = "LoadLibrary" ascii wide
        $str13 = "GetProcAddress" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($str*)
}
rule Builder_MSIL_G2JS_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
        md5 = "fa255fdc88ab656ad9bc383f9b322a76"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Loader_Win32_DShell_2{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "590d98bb74879b52b97d8a158af912af"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
        $ss4 = "C:\\Users\\config.ini" fullword
        $ss5 = "Invalid config file" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule HackTool_MSIL_SharPivot_3{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "SharPivot" ascii wide
        $str2 = "ParseArgs" ascii wide
        $str3 = "GenRandomString" ascii wide
        $str4 = "ScheduledTaskExists" ascii wide
        $str5 = "ServiceExists" ascii wide
        $str6 = "lpPassword" ascii wide
        $str7 = "execute" ascii wide
        $str8 = "WinRM" ascii wide
        $str9 = "SchtaskMod" ascii wide
        $str10 = "PoisonHandler" ascii wide
        $str11 = "SCShell" ascii wide
        $str12 = "SchtaskMod" ascii wide
        $str13 = "ServiceHijack" ascii wide
        $str14 = "ServiceHijack" ascii wide
        $str15 = "commandArg" ascii wide
        $str16 = "payloadPath" ascii wide
        $str17 = "Schtask" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule APT_HackTool_MSIL_FLUFFY_2{
    meta:
        date = "2020-12-04"
        modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "\x00Asktgt\x00"
        $s2 = "\x00Kerberoast\x00"
        $s3 = "\x00HarvestCommand\x00"
        $s4 = "\x00EnumerateTickets\x00"
        $s5 = "[*] Action: " wide
        $s6 = "\x00Fluffy.Commands\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_FLUFFY_1{
    meta:
        date = "2020-12-04"
        modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
        $sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
        $ss1 = "\x00Fluffy\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_MSIL_SEATBELT_1{
    meta:
        description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
        md5 = "848837b83865f3854801be1f25cb9f4d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        date = "2020-12-08"
        modified = "2023-01-27"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
        $str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
        $str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
        $str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
        $str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
        $str6 = "*[System/EventID={0}]" ascii nocase wide
        $str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
        $str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
        $str10 = "{0,-23}" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule HackTool_MSIL_INVEIGHZERO_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'inveighzero' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "113ae281-d1e5-42e7-9cc2-12d30757baf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_RURALBISHOP_1{
    meta:
        date = "2020-12-03"
        modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}
rule Loader_MSIL_RURALBISHOP_2{
    meta:
        date = "2020-12-03"
        modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule HackTool_MSIL_PrepShellcode_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'PrepShellcode' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "d16ed275-70d5-4ae5-8ce7-d249f967616c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Downloader_Win32_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "05b99d438dac63a5a993cea37c036673"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule Loader_MSIL_WMIRunner_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIRunner' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "6cc61995-9fd5-4649-b3cc-6f001d60ceda" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharpStomp_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
        md5 = "83ed748cd94576700268d35666bf3e01"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "41f35e79-2034-496a-8c82-86443164ada2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule Tool_MSIL_SharpGrep_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGrep' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "f65d75b5-a2a6-488f-b745-e67fc075f445" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Dropper_HTA_WildChild_1{
    meta:
        description = "This rule looks for strings present in unobfuscated HTAs generated by the WildChild builder."
        md5 = "3e61ca5057633459e96897f79970a46d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "processpath" ascii wide
        $s2 = "v4.0.30319" ascii wide
        $s3 = "v2.0.50727" ascii wide
        $s4 = "COMPLUS_Version" ascii wide
        $s5 = "FromBase64Transform" ascii wide
        $s6 = "MemoryStream" ascii wide
        $s7 = "entry_class" ascii wide
        $s8 = "DynamicInvoke" ascii wide
        $s9 = "Sendoff" ascii wide
        $script_header = "<script language=" ascii wide
    condition:
        $script_header at 0 and all of ($s*)
}
rule APT_Builder_PY_REDFLARE_2{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "4410e95de247d7f1ab649aa640ee86fb"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "<510sxxII"
        $s2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
        $s3 = "parsePluginOutput"
    condition:
        all of them and #s2 == 2
}
rule APT_Loader_Win32_DShell_3{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Trojan_Linux_REDFLARE_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "find_applet_by_name" fullword
        $s2 = "bb_basename" fullword
        $s3 = "hk_printf_chk" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}
rule Loader_MSIL_WildChild_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
        md5 = "7e6bc0ed11c2532b2ae7060327457812"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "2e71d5ff-ece4-4006-9e98-37bb724a7780" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule MSIL_Launcher_DUEDLLIGENCE_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
        md5 = "a91bf61cc18705be2288a0f6f125068f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Backdoor_Win_GORAT_2{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and has the Go build ID strings. Then checks for various strings known to be in the Gorat implant including strings used in C2 json, names of methods, and the unique string 'murica' used in C2 comms. A check is done to ensure the string 'rat' appears in the binary over 1000 times as it is the name of the project used by the implant and is present well over 2000 times."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000
}
rule APT_Loader_Win64_REDFLARE_2{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
        $inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule HackTool_MSIL_SharPersist_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}

rule APT_Backdoor_Win_GORAT_4{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and pe.exports("MemoryCallEntryPoint") and pe.exports("MemoryDefaultAlloc") and pe.exports("MemoryDefaultFree") and pe.exports("MemoryDefaultFreeLibrary") and pe.exports("MemoryDefaultGetProcAddress") and pe.exports("MemoryDefaultLoadLibrary") and pe.exports("MemoryFindResource") and pe.exports("MemoryFindResourceEx") and pe.exports("MemoryFreeLibrary") and pe.exports("MemoryGetProcAddress") and pe.exports("MemoryLoadLibrary") and pe.exports("MemoryLoadLibraryEx") and pe.exports("MemoryLoadResource") and pe.exports("MemoryLoadString") and pe.exports("MemoryLoadStringEx") and pe.exports("MemorySizeofResource") and pe.exports("callback") and pe.exports("crosscall2") and pe.exports("crosscall_386")
}
rule APT_HackTool_MSIL_SHARPNFS_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "9f67ebe3-fc9b-40f2-8a18-5940cfed44cf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule CredTheft_MSIL_CredSnatcher_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CredSnatcher' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "370b4d21-09d0-433f-b7e4-4ebdd79948ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SEATBELT_2{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
        md5 = "9f401176a9dd18fa2b5b90b4a2aa1356"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_Loader_Win32_DShell_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Loader_Win32_PGF_1{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "383161e4deaf7eb2ebeda2c5e9c3204c"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
        $sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
        $sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_HackTool_MSIL_SHARPDACL_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPZIPLIBZIPPER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpziplibzipper' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "485ba350-59c4-4932-a4c1-c96ffec511ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Downloader_Win64_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_Loader_Win64_MATRYOSHKA_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
        $sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
        $sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule HackTool_MSIL_WMIspy_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIspy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "5ee2bca3-01ad-489b-ab1b-bda7962e06bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Trojan_Win_REDFLARE_3{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
        $str1 = "CreateCompatibleBitmap" fullword
        $str2 = "BitBlt" fullword
        $str3 = "runCommand" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win_PGF_1{
    meta:
        description = "PDB string used in some PGF DLL samples"
        md5 = "013c7708f1343d684e3571453261b586"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
        $pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
        $pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and any of them
}
rule APT_HackTool_MSIL_SHARPDNS_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "d888cec8-7562-40e9-9c76-2bb9e43bb634" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Loader_MSIL_TrimBishop_1{
    meta:
        description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $msg = "msg" ascii wide
        $msil = "_CorExeMain" ascii wide
        $str1 = "RuralBishop" ascii wide
        $str2 = "KnightKingside" ascii wide
        $str3 = "ReadShellcode" ascii wide
        $str4 = "ReverseString" ascii wide
        $str5 = "DTrim" ascii wide
        $str6 = "QueensGambit" ascii wide
        $str7 = "Messages" ascii wide
        $str8 = "NtQueueApcThread" ascii wide
        $str9 = "NtAlertResumeThread" ascii wide
        $str10 = "NtQueryInformationThread" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and #msg > 60 and all of ($str*)
}
rule Loader_Win_Generic_17{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "562ecbba043552d59a0f23f61cea0983"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Loader_Win64_PGF_3{
    meta:
        description = "PGF payload, generated rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond2 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 ?? ?? ?? ?? FF D0 48 89 C1 48 8D 85 ?? ?? ?? ?? 41 B8 04 01 00 00 48 89 C2 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8D 4D ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 49 89 C8 48 89 C1 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 89 C2 B9 08 00 00 00 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 38 04 00 00 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 48 8D 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 41 B8 00 00 00 00 48 89 C1 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 95 C0 84 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? EB ?? 48 8B 45 ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 48 8D 15 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 89 45 ?? 48 89 E8 48 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 C7 45 ?? 00 00 00 00 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 39 C2 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 73 ?? 48 8B 45 ?? 48 8B 00 48 8B 55 ?? 48 81 C2 00 10 00 00 48 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 8B 4D ?? 48 8B 55 ?? 48 01 CA 48 39 D0 0F 83 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8B 45 ?? 48 8B 00 48 8D 95 ?? ?? ?? ?? 41 B8 30 00 00 00 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 48 8B 45 ?? 48 8B 00 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 00 00 00 00 EB ?? 90 EB ?? 90 48 83 45 ?? 08 E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 48 63 D0 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 89 C2 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 01 00 00 00 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 FB 01 EB ?? 48 89 C3 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond3 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 C1 7C 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 33 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 B2 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 75 96 01 00 48 8D 45 AF 48 89 C1 E8 B9 FE 00 00 48 8B 05 66 7C 06 00 FF D0 89 C2 B9 08 00 00 00 E8 3C B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 83 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 2A F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 28 B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 69 7B 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 11 B9 05 00 48 8B 05 A2 7B 06 00 FF D0 48 8D 15 0D B9 05 00 48 89 C1 48 8B 05 97 7B 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 5A 7B 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 22 7B 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 59 FB FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 00 FB FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 94 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 00 FC 00 00 48 89 D8 48 89 C1 E8 45 AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 63 9C 01 00 48 89 D8 48 89 C1 E8 28 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
        $cond4 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 D3 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 65 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 EC FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AF 96 01 00 48 8D 45 AF 48 89 C1 E8 F3 FE 00 00 48 8B 05 78 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6E B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 B5 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 64 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 5A B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 73 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 45 C8 05 00 48 8B 05 B4 8A 06 00 FF D0 48 8D 15 41 C8 05 00 48 89 C1 48 8B 05 A9 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 6C 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 54 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 33 FA FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 DA F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CE 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 3A FC 00 00 48 89 D8 48 89 C1 E8 4F AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9D 9C 01 00 48 89 D8 48 89 C1 E8 32 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}
rule HackTool_PY_ImpacketObfuscation_1{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        description = "smbexec"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}
rule APT_HackTool_Win64_EXCAVATOR_2{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "4fd62068e591cbd6f413e1c2b8f75442"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
        $enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule APT_Loader_Raw32_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}
rule APT_Loader_Win64_PGF_2{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
        $sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
        $sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_MSIL_SHARPTEMPLATE_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharptemplate' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "e9e452d4-9e58-44ff-ba2d-01b158dda9bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
        md5 = "db0eaad52465d5a2b86fdd6a6aa869a5"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win32_PGF_5{
    meta:
        description = "PGF payload, generated rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
        md5 = "8c91a27bbdbe9fb0877daccd28bd7bb5"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond2 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 20 33 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 58 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 2C 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
        $cond3 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 68 03 01 00 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 ?? 00 00 00 00 C6 45 ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 9C 10 00 10 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 6A 14 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 ?? 8B 45 ?? 8A 48 ?? 88 4D ?? 8B 55 ?? 83 C2 0C 8B 45 ?? 8B 0A 89 08 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 52 ?? 89 50 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 83 C0 01 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 14 7D ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 11 0F B6 45 ?? 33 D0 8B 4D ?? 03 8D ?? ?? ?? ?? 88 11 EB ?? 8B 55 ?? 8B 42 ?? 89 45 ?? 6A 40 68 00 30 00 00 8B 4D ?? 51 6A 00 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 55 ?? 52 8B 45 ?? 83 C0 20 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 83 C2 01 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 09 8B 85 ?? ?? ?? ?? 99 BE 14 00 00 00 F7 FE 8B 45 ?? 0F B6 14 10 33 CA 8B 45 ?? 03 85 ?? ?? ?? ?? 88 08 EB ?? 8B 4D ?? 89 4D ?? FF 55 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
        $cond4 = { 8B FF 55 8B EC 81 EC 3? ?1 ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 E0 56 C7 45 F8 ?? ?? ?? ?? C6 85 D8 FE FF FF ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 D9 FE FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 F4 ?? ?? ?? ?? C6 45 E7 ?? C7 45 E8 ?? ?? ?? ?? C7 45 EC ?? ?? ?? ?? C7 45 FC ?? ?? ?? ?? C7 45 F? ?? ?? ?? ?0 6A ?? 6A ?? 8D 8D D8 FE FF FF 51 6A ?? 68 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 F8 6A ?? FF ?? ?? ?? ?? ?? 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 ?? ?? 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF ?? ?? ?? ?? EB ?? 8B 85 D4 FE FF FF 83 C? ?1 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D ?? 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB ?? 8B 55 F8 8B 42 08 89 45 FC 6A ?? 68 ?? ?? ?? ?? 8B 4D FC 51 6A ?? FF ?? ?? ?? ?? ?? 89 45 EC 8B 55 FC 52 8B 45 F8 83 ?? ?? 50 8B 4D EC 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 D0 FE FF FF ?? ?? ?? ?? EB ?? 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 ?? 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE ?? ?? ?? ?? F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB ?? 8B 4D EC 89 4D F0 FF ?? ?? 5E 8B 4D E0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and any of them
}
rule APT_HackTool_MSIL_LUALOADER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "8b546b49-2b2c-4577-a323-76dc713fe2ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PXELOOT_2{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
        md5 = "d93100fe60c342e9e3b13150fd91c7d8"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        date = "2020-12-08"
        modified = "2023-01-27"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str2 = "InvestigateRPC" ascii nocase wide
        $str3 = "DhcpRecon" ascii nocase wide
        $str4 = "UnMountWim" ascii nocase wide
        $str5 = "remote WIM image" ascii nocase wide
        $str6 = "DISMWrapper" ascii nocase wide
        $str7 = "findTFTPServer" ascii nocase wide
        $str8 = "DHCPRequestRecon" ascii nocase wide
        $str9 = "DHCPDiscoverRecon" ascii nocase wide
        $str10 = "GoodieFile" ascii nocase wide
        $str11 = "InfoStore" ascii nocase wide
        $str12 = "execute" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}
rule APT_HackTool_MSIL_PRAT_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "7d1219fb-a954-49a7-96c9-df9e6429a8c7" ascii nocase wide
        $typelibguid1 = "bc1157c2-aa6d-46f8-8d73-068fc08a6706" ascii nocase wide
        $typelibguid2 = "c602fae2-b831-41e2-b5f8-d4df6e3255df" ascii nocase wide
        $typelibguid3 = "dfaa0b7d-6184-4a9a-9eeb-c08622d15801" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPNATIVEZIPPER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win32_REDFLARE_1{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "01d68343ac46db6065f888a094edfe4f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule APT_Loader_MSIL_PGF_1{
    meta:
        date = "2020-11-24"
        modified = "2020-11-24"
        description = "base.cs"
        md5 = "a495c6d11ff3f525915345fb762f8047"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule CredTheft_Win_EXCAVATOR_2{
    meta:
        description = "This rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
        md5 = "6a9a114928554c26675884eeb40cc01b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }
        $bytes2 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes3 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes4 = { 4C 89 74 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC A0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? BA 50 00 00 00 C7 05 ?? ?? ?? ?? 43 00 3A 00 66 89 15 ?? ?? 01 00 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 5C 00 57 00 33 C9 C7 05 ?? ?? ?? ?? 69 00 6E 00 C7 05 ?? ?? ?? ?? 64 00 6F 00 C7 05 ?? ?? ?? ?? 77 00 73 00 C7 05 ?? ?? ?? ?? 5C 00 4D 00 C7 05 ?? ?? ?? ?? 45 00 4D 00 C7 05 ?? ?? ?? ?? 4F 00 52 00 C7 05 ?? ?? ?? ?? 59 00 2E 00 C7 05 ?? ?? ?? ?? 44 00 4D 00 C7 05 ?? ?? ?? ?? 53 00 65 00 C7 05 ?? ?? ?? ?? 44 00 65 00 C7 05 ?? ?? ?? ?? 42 00 75 00 C7 05 ?? ?? ?? ?? 47 00 50 00 C7 05 ?? ?? ?? ?? 72 00 69 00 C7 05 ?? ?? ?? ?? 56 00 69 00 C7 05 ?? ?? ?? ?? 4C 00 45 00 C7 05 ?? ?? ?? ?? 67 00 65 00 C7 05 ?? ?? ?? ?? 6C 73 61 73 C7 05 ?? ?? ?? ?? 73 2E 65 78 C6 05 ?? ?? ?? ?? 65 FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 ?? 48 89 44 24 ?? C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 02 00 00 00 FF 15 ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 ?? 41 8D 56 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 44 24 ?? 4C 89 74 24 ?? 45 33 C9 33 D2 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 0F 1F 44 00 ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 41 B9 04 01 00 00 33 D2 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 ?? 48 89 BC 24 ?? ?? ?? ?? BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 74 24 ?? C7 44 24 ?? 80 00 00 00 48 8D 0D ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 01 00 00 00 BA 00 00 00 10 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 ?? 41 B9 02 00 00 00 4C 89 74 24 ?? 4C 8B C7 8B D6 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 54 24 ?? 48 8B C8 FF 15 ?? ?? ?? ?? 33 C9 FF 15 ?? ?? ?? ?? CC 48 8B CB FF 15 ?? ?? ?? ?? 48 8B BC 24 ?? ?? ?? ?? 33 C0 48 8B B4 24 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 48 81 C4 A0 01 00 00 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}
rule Builder_MSIL_SharpGenerator_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "3f450977-d796-4016-bb78-c9e91c6a0f08" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HackTool_Win64_AndrewSpecial_1{
    meta:
        description = "Detects AndrewSpecial process dumping tool"
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "4456e52f6f8543c3ba76cb25ea3e9bd2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and $dump and any of ($shellcode*)
}
rule Loader_MSIL_Generic_1{
    meta:
        description = "Detects generic loader"
        md5 = "b8415b4056c10c15da5bba4826a44ffd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
        $str1 = "DllImportAttribute"
        $str2 = "FromBase64String"
        $str3 = "ResumeThread"
        $str4 = "OpenThread"
        $str5 = "SuspendThread"
        $str6 = "QueueUserAPC"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of them
}
rule APT_Keylogger_Win32_REDFLARE_1{
    meta:
        description = "Detects REDFLARE Keylogger"
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
        $keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}
rule Loader_MSIL_InMemoryCompilation_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'In-MemoryCompilation' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "524d2687-0042-4f93-b695-5579f3865205" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_WMISharp_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMISharp' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "3a2421d9-c1aa-4fff-ad76-7fcb48ed4bff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win_PGF_2{
    meta:
        description = "PE rich header matches PGF backdoor"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}
rule Trojan_Win_Generic_101{
    meta:
        description = "Detects FireEye Windows trojan"
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "2e67c62bd0307c04af469ee8dcb220f2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
        $s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
        $s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
        $si1 = "PeekMessageA" fullword
        $si2 = "PostThreadMessageA" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and @s0[1] < @s1[1] and @s1[1] < @s2[1] and all of them
}


rule Loader_MSIL_CSharpSectionInjection_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "d77135da-0496-4b5c-9afe-e1590a4c136a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_HackTool_MSIL_SHARPWEBCRAWLER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "cf27abf4-ef35-46cd-8d0c-756630c686f1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Trojan_Win64_Generic_22{
    meta:
        description = "Detects FireEye's Windows Trojan"
        date = "2020-11-26"
        modified = "2020-11-26"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
        $process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
        $token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule Loader_Win_Generic_19{
    meta:
        description = "Detects generic Windows loader"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "3fb9341fb11eca439b50121c6f7c59c7"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Builder_PY_REDFLARE_1{
    meta:
        description = "Detects FireEye's Python Redflar"
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "LOAD_OFFSET_32 = 0x612"
        $2 = "LOAD_OFFSET_64 = 0x611"
        $3 = "class RC4:"
        $4 = "struct.pack('<Q' if is64b else '<L'"
        $5 = "stagerConfig['comms']['config']"
        $6 = "_x86.dll"
        $7 = "_x64.dll"
    condition:
        all of them and @1[1] < @2[1] and @2[1] < @3[1] and @3[1] < @4[1] and @4[1] < @5[1]
}
rule HackTool_PY_ImpacketObfuscation_2{
    meta:
        description = "Detects FireEye's wmiexec impacket obfuscation"
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "f3dd8aa567a01098a8a610529d892485"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "import random"
        $s2 = "class WMIEXEC" nocase
        $s3 = "class RemoteShell" nocase
        $s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
        $s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
    condition:
        all of them
}
rule APT_Loader_MSIL_PGF_2{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
        md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "\x00ScriptObjectStackTop\x00"
        $ss3 = "\x00Microsoft.JScript\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPSQLCLIENT_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsqlclient' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "13ed03cd-7430-410d-a069-cf377165fbfd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Methodology_OLE_CHARENCODING_2{
    meta:
        description = "Looking for suspicious char encoding"
        md5 = "41b70737fa8dda75d5e95c82699c2e9b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $echo1 = "101;99;104;111;32;111;102;102;" ascii wide
        $echo2 = "101:99:104:111:32:111:102:102:" ascii wide
        $echo3 = "101x99x104x111x32x111x102x102x" ascii wide
        $pe1 = "77;90;144;" ascii wide
        $pe2 = "77:90:144:" ascii wide
        $pe3 = "77x90x144x" ascii wide
        $pk1 = "80;75;3;4;" ascii wide
        $pk2 = "80:75:3:4:" ascii wide
        $pk3 = "80x75x3x4x" ascii wide
    condition:
        (uint32(0) == 0xe011cfd0) and filesize < 10MB and any of them
}
rule HackTool_MSIL_SharpHound_3{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
        md5 = "eeedc09570324767a3de8205f66a5295"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule CredTheft_MSIL_TitoSpecial_2{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
        $typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ($typelibguid1 or $typelibguid2)
}
rule CredTheft_MSIL_WCMDump_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WCMDump' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "21e322f2-4586-4aeb-b1ed-d240e2a79e19" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Builder_Win64_MATRYOSHKA_1{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "Detects builder matryoshka_pe_to_shellcode.rs"
        md5 = "8d949c34def898f0f32544e43117c057"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
        $ss1 = "\x00Stub Size: "
        $ss2 = "\x00Executable Size: "
        $ss3 = "\x00[+] Writing out to file"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule Trojan_Win64_Generic_23{
    meta:
        description = "Detects FireEye's Windows trojan"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "b66347ef110e60b064474ae746701d4a"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
        $process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
        $token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule HackTool_MSIL_KeePersist_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeePersist' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "1df47db2-7bb8-47c2-9d85-5f8d3f04a884" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Tool_MSIL_CSharpUtils_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "2130bcd9-7dd8-4565-8414-323ec533448d" ascii nocase wide
        $typelibguid1 = "319228f0-2c55-4ce1-ae87-9e21d7db1e40" ascii nocase wide
        $typelibguid2 = "4471fef9-84f5-4ddd-bc0c-31f2f3e0db9e" ascii nocase wide
        $typelibguid3 = "5c3bf9db-1167-4ef7-b04c-1d90a094f5c3" ascii nocase wide
        $typelibguid4 = "ea383a0f-81d5-4fa8-8c57-a950da17e031" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Trojan_MSIL_GORAT_Module_PowerShell_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
        $typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PuppyHound_1{
    meta:
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        md5 = "eeedc09570324767a3de8205f66a5295"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Builder_PY_MATRYOSHKA_1{
    meta:
        description = "Detects FireEye's Python MATRYOSHKA tool"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = ".pop(0)])"
        $s2 = "[1].replace('unsigned char buf[] = \"'"
        $s3 = "binascii.hexlify(f.read()).decode("
        $s4 = "os.system(\"cargo build {0} --bin {1}\".format("
        $s5 = "shutil.which('rustc')"
        $s6 = "~/.cargo/bin"
        $s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/
    condition:
        all of them
}

rule APT_HackTool_MSIL_NOAMCI_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
        $typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_PXELOOT_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
        md5 = "82e33011ac34adfcced6cddc8ea56a81"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule APT_HackTool_MSIL_ADPassHunt_2{
    meta:
        description = "Detects FireEye's ADPassHunt tool"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "LDAP://" wide
        $s2 = "[GPP] Searching for passwords now..." wide
        $s3 = "Searching Group Policy Preferences (Get-GPPPasswords + Get-GPPAutologons)!" wide
        $s4 = "possibilities so far)..." wide
        $s5 = "\\groups.xml" wide
        $s6 = "Found interesting file:" wide
        $s7 = "\x00GetDirectories\x00"
        $s8 = "\x00DirectoryInfo\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_ADPassHunt_1{
    meta:
        description = "Detects FireEye's ADPassHunt tool"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
        $sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_SHARPSACK_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "1946808a-1a01-40c5-947b-8b4c3377f742" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Loader_Win64_PGF_5{
    meta:
        description = "PGF payload, generated rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
        md5 = "150224a0ccabce79f963795bf29ec75b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond2 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 A3 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 F6 20 00 00 48 8B 4C 24 40 FF 15 7B FA FF FF B8 01 00 00 00 48 83 C4 38 C3 }
        $cond3 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? 8B 44 24 48 89 44 24 20 83 7C 24 2? ?1 74 ?? EB ?? 48 8B 44 24 40 48 ?? ?? ?? ?? ?? ?? 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? 48 83 C4 38 C3 }
        $cond4 = { 4C 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC 38 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? 01 74 ?? EB ?? 48 8B 44 24 ?? 48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 38 C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and any of them
}
rule APT_Trojan_Win_REDFLARE_2{
    meta:
        description = "Detects FireEye's REDFLARE tool"
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "Cookie: SID1=%s" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_DTRIM_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'dtrim' project, which is a modified version of SharpSploit."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "7760248f-9247-4206-be42-a6952aa46da2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule HackTool_MSIL_SharPivot_2{
    meta:
        description = "Detects FireEye's SharPivot tool"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_HackTool_MSIL_REVOLVER_1{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
        $typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule APT_Keylogger_Win64_REDFLARE_1{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "fbefb4074f1672a3c29c1a47595ea261"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
        $keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}
rule APT_HackTool_Win64_EXCAVATOR_1{
    meta:
        date = "2020-11-30"
        modified = "2020-11-30"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
        $lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}
rule APT_Loader_Win64_MATRYOSHKA_2{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka.rs"
        md5 = "7f8102b789303b7861a03290c79feba0"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
        $sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
        $si1 = "CreateToolhelp32Snapshot" fullword
        $si2 = "Process32Next" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule MAL_Winnti_Sample_May18_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and all of them
}
rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_1 {
   meta:
      description = "Detects Lazarus VHD Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-10-05"
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
   strings:
      $s1 = "HowToDecrypt.txt" wide fullword
      $s2 = "rsa.cpp" wide fullword
      $s3 = "sc stop \"Microsoft Exchange Compliance Service\"" ascii fullword

      $op1 = { 8b 8d bc fc ff ff 8b 94 bd 34 03 00 00 33 c0 50 }
      $op2 = { 8b 8d 98 f9 ff ff 8d 64 24 00 8b 39 3b bc 85 34 }
      $op3 = { 8b 94 85 34 03 00 00 89 11 40 83 c1 04 3b 06 7c }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them
}
rule Destructive_Ransomware_Gen1 {
   meta:
      description = "Detects destructive malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
      date = "2018-02-12"
      hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
   strings:
      $x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
      $x2 = "delete shadows /all /quiet" fullword wide
      $x3 = "delete catalog -quiet" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}
rule Susp_Indicators_EXE {
   meta:
      description = "Detects packed NullSoft Inst EXE with characteristics of NetWire RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/8qaiyPxs"
      date = "2018-01-05"
      score = 60
      hash1 = "6de7f0276afa633044c375c5c630740af51e29b6a6f17a64fbdd227c641727a4"
   strings:
      $s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
      $s2 = "Error! Bad token or internal error" fullword ascii
      $s3 = "CRYPTBASE" fullword ascii
      $s4 = "UXTHEME" fullword ascii
      $s5 = "PROPSYS" fullword ascii
      $s6 = "APPHELP" fullword ascii
   condition:
   uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and filesize < 700KB and all of them
}
rule SUSP_RANSOMWARE_Indicator_Jul20 {
   meta:
      description = "Detects ransomware indicator"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-07-28"
      score = 60
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
   strings:
      $ = "Decrypt.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "Decrypt-Files.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "DECRYPT-FILES.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT_INSTRUCTION.TXT" ascii wide 
      $ = "FILES ENCRYPTED.txt" ascii wide
      $ = "DECRYPT MY FILES" ascii wide 
      $ = "DECRYPT-MY-FILES" ascii wide 
      $ = "DECRYPT_MY_FILES" ascii wide
      $ = "DECRYPT YOUR FILES" ascii wide  
      $ = "DECRYPT-YOUR-FILES" ascii wide 
      $ = "DECRYPT_YOUR_FILES" ascii wide 
      $ = "DECRYPT FILES.txt" ascii wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1400KB and
      1 of them
}
rule MAL_XMR_Miner_May19_1 : HIGHVOL {
   meta:
      description = "Detects Monero Crypto Coin Miner"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 85
      hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"
   strings:
      $x1 = "donate.ssl.xmrig.com" fullword ascii
      $x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii

      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and (
         pe.imphash() == "25d9618d1e16608cd5d14d8ad6e1f98e" or
         1 of ($x*) or
         2 of them
      )
}
rule Methodology_Suspicious_Shortcut_IconNotFromExeOrDLLOrICO{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "IconFile="
    $icon_negate = /[\x0a\x0d]IconFile=[^\x0d]*\.(dll|exe|ico)\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and $icon and not $icon_negate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}
rule MAL_AirdViper_Sample_Apr18_1 {
   meta:
      description = "Detects Arid Viper malware sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-04"
      hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
   strings:
      $x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
      $x2 = "daenerys=%s&" ascii
      $x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii

      $s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
      $s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
      $s3 = "\\TaskWindows.exe" ascii
      $s4 = "MicrosoftOneDrives.exe" fullword ascii
      $s5 = "\\SeanSansom.txt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and (
         1 of ($x*) or
         4 of them
      )
}
rule SUSP_Reversed_Base64_Encoded_EXE : FILE {
   meta:
      description = "Detects an base64 encoded executable with reversed characters"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-04-06"
      reference = "Internal Research"
      score = 80
      hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"
   strings:
      $s1 = "AEAAAAEQATpVT"
      $s2 = "AAAAAAAAAAoVT"
      $s3 = "AEAAAAEAAAqVT"
      $s4 = "AEAAAAIAAQpVT"
      $s5 = "AEAAAAMAAQqVT"

      $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
      $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
      $sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii
   condition:
      filesize < 10000KB and 1 of them
}
rule IMPLANT_10_v2 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $xor = { 34 ?? 66 33 C1 48 FF C1 }
      $nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}
   condition:
      uint16(0) == 0x5A4D and $xor and $nop
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
rule Suspicious_PowerShell_WebDownload_1 : HIGHVOL FILE {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      modified = "2022-07-27"
      nodeepdive = 1
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
      $s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
      $s3 = "system.net.webclient).downloadfile('http" ascii nocase
      $s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
      $s5 = "GetString([Convert]::FromBase64String(" ascii nocase

      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
      $fp3 = " GET /"
      $fp4 = " POST /"
      $fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
      $fp6 = " 404 " /* in web server logs */
      $fp7 = "# RemoteSSHConfigurationScript" ascii /* \.vscode\extensions\ms-vscode-remote.remote-ssh */
      $fp8 = "<helpItems" ascii fullword
      $fp9 = "DownloadFile(\"https://codecov.io/bash" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}
rule Unknown_Packer_Detecton_1{
	meta:
	    description = "Unknown Packer"
	strings:
	    $1 = ".packed"
	condition:
	    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}
rule HvS_APT37_smb_scanner {
   meta:
      description = "Unknown smb login scanner used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
   strings:
      $s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
      $s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
      $s3 = "Load mpr.dll Error " fullword ascii
      $s4 = "Load Netapi32.dll Error " fullword ascii
      $s5 = "%s U/P not Correct! - %d" fullword ascii
      $s6 = "GetNetWorkInfo Version 1.0" fullword wide
      $s7 = "Hello World!" fullword wide
      $s8 = "%s Error: %ld" fullword ascii
      $s9 = "%s U/P Correct!" fullword ascii
      $s10 = "%s --------" fullword ascii
      $s11 = "%s%-30s%I64d" fullword ascii
      $s12 = "%s%-30s(DIR)" fullword ascii
      $s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
      $s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
      $s15 = "Share:              Type:                   Remark:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (10 of them)
}
rule HvS_APT37_cred_tool {
   meta:
      description = "Unknown cred tool used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Markus Poelloth"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "Domain Login" fullword ascii
      $s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "User: %s" fullword ascii
      $s6 = "Pass: %s" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = "E@c:\\u" fullword ascii
   condition:
      filesize < 500KB and 7 of them
}
rule HvS_APT37_RAT_loader {
   meta:
      description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
   condition:
      (pe.version_info["OriginalFilename"] contains "MFC_DLL.dll") and
      (pe.exports("SMain") and pe.exports("SMainW") )
}
rule HvS_APT37_webshell_img_thumbs_asp {
   meta:
      description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
   strings:
      $s1 = "strMsg = \"E : F\"" fullword ascii
      $s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
      $s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""

      $a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $a2 = "Dim tmpPath, workDir" fullword ascii
      $a3 = "Dim objFSO, objTextStream" fullword ascii
      $a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
      $a5 = "InStrRev(workDir, \"/\")" ascii

      $g1 = "WriteFile = 0" fullword ascii
      $g2 = "fileData = Request.Form(\"fp\")" fullword ascii
      $g3 = "fileName = Request.Form(\"fr\")" fullword ascii
      $g4 = "Err.Clear()" fullword ascii
      $g5 = "Option Explicit" fullword ascii
   condition:
      filesize < 2KB and (( 1 of ($s*) ) or (3 of ($a*)) or (5 of ($g*)))
}
rule HvS_APT37_webshell_template_query_asp {
   meta:
      description = "Webshell named template-query.aspimg.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
   strings:
      $g1 = "server.scripttimeout=600" fullword ascii
      $g2 = "response.buffer=true" fullword ascii
      $g3 = "response.expires=-1" fullword ascii
      $g4 = "session.timeout=600" fullword ascii

      $a1 = "redhat hacker" ascii
      $a2 = "want_pre.asp" ascii
      $a3 = "vgo=\"admin\"" ascii
      $a4 = "ywc=false" ascii

      $s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii
   condition:
      filesize > 70KB and filesize < 200KB and (( 1 of ($s*) ) or (2 of ($a*)) or (3 of ($g*)))
}
rule HvS_APT37_webshell_controllers_asp {
   meta:
      description = "Webshell named controllers.asp or inc-basket-offer.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "829462fc6d84aae04a962dfc919d0a392265fbf255eab399980d2b021e385517"
   strings:
      $s0 = "<%@Language=VBScript.Encode" ascii
	// Case permutations of the word SeRvEr encoded with the Microsoft Script Encoder followed by ¡°.scriptrimeOut¡±
      $x1 = { 64 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x2 = { 64 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x3 = { 64 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x4 = { 64 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x5 = { 64 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x6 = { 64 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x7 = { 64 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x8 = { 64 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x9 = { 64 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x10 = { 64 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x11 = { 64 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x12 = { 64 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x13 = { 64 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x14 = { 64 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x15 = { 64 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x16 = { 64 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x17 = { 64 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x18 = { 64 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x19 = { 64 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x20 = { 64 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x21 = { 64 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x22 = { 64 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x23 = { 64 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x24 = { 64 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x25 = { 64 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x26 = { 6A 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x27 = { 6A 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x28 = { 6A 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x29 = { 6A 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x30 = { 6A 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x31 = { 6A 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x32 = { 6A 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x33 = { 6A 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x34 = { 64 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x35 = { 6A 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x36 = { 6A 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x37 = { 6A 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x38 = { 6A 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x39 = { 6A 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x40 = { 6A 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x41 = { 6A 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x42 = { 6A 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x43 = { 6A 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x44 = { 6A 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x45 = { 64 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x46 = { 6A 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x47 = { 6A 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x48 = { 6A 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x49 = { 6A 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x50 = { 6A 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x51 = { 6A 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x52 = { 6A 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x53 = { 6A 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x54 = { 6A 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x55 = { 6A 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x56 = { 64 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x57 = { 6A 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x58 = { 6A 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x59 = { 6A 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x60 = { 6A 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x61 = { 64 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x62 = { 64 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x63 = { 64 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x64 = { 64 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
   condition:
      filesize > 50KB and filesize < 200KB and ( $s0 and 1 of ($x*) )
}
rule MINER_monero_mining_detection {

   meta:

      description = "Monero mining software"
      author = "Trellix ATR team"
      date = "2018-04-05"
      rule_version = "v1"
      malware_type = "miner"
      malware_family = "Ransom:W32/MoneroMiner"
      actor_type = "Cybercrime"
      actor_group = "Unknown"   
      
   strings:

      $1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
      $4 = "--user-agent         set custom user-agent string for pool" fullword ascii
      $5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
      $6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
      $8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
      $9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
      $10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
      $11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
      $12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
      $15 = "-B, --background         run the miner in the background" fullword ascii
      $16 = "* API PORT:     %d" fullword ascii
      $17 = "--api-access-token=T access token for API" fullword ascii
      $18 = "-t, --threads=N          number of miner threads" fullword ascii
      $19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
      $20 = "-u, --user=USERNAME      username for mining server" fullword ascii
   
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 4000KB and
      ( 8 of them )) or
      ( all of them )
}
rule apt_nix_elf_derusbi {

    meta:
        
      description = "Rule to detect the APT Derusbi ELF file"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"
      

    strings:

        $s1 = "LxMain"
        $s2 = "execve"
        $s3 = "kill"
        $s4 = "cp -a %s %s"
        $s5 = "%s &"
        $s6 = "dbus-daemon"
        $s7 = "--noprofile"
        $s8 = "--norc"
        $s9 = "TERM=vt100"
        $s10 = "/proc/%u/cmdline"
        $s11 = "loadso"
        $s12 = "/proc/self/exe"
        $s13 = "Proxy-Connection: Keep-Alive"
        $s14 = "Connection: Keep-Alive"
        $s15 = "CONNECT %s"
        $s16 = "HOST: %s:%d"
        $s17 = "User-Agent: Mozilla/4.0"
        $s18 = "Proxy-Authorization: Basic %s"
        $s19 = "Server: Apache"
        $s20 = "Proxy-Authenticate"
        $s21 = "gettimeofday"
        $s22 = "pthread_create"
        $s23 = "pthread_join"
        $s24 = "pthread_mutex_init"
        $s25 = "pthread_mutex_destroy"
        $s26 = "pthread_mutex_lock"
        $s27 = "getsockopt"
        $s28 = "socket"
        $s29 = "setsockopt"
        $s30 = "select"
        $s31 = "bind"
        $s32 = "shutdown"
        $s33 = "listen"
        $s34 = "opendir"
        $s35 = "readdir"
        $s36 = "closedir"
        $s37 = "rename"

    condition:

        (uint32(0) == 0x4464c457f) and
        filesize < 200KB and
        all of them
}
rule apt_nix_elf_derusbi_kernelModule {

    meta:

      description = "Rule to detect the Derusbi ELK Kernel module"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $s1 = "__this_module"
        $s2 = "init_module"
        $s3 = "unhide_pid"
        $s4 = "is_hidden_pid"
        $s5 = "clear_hidden_pid"
        $s6 = "hide_pid"
        $s7 = "license"
        $s8 = "description"
        $s9 = "srcversion="
        $s10 = "depends="
        $s11 = "vermagic="
        $s12 = "current_task"
        $s13 = "sock_release"
        $s14 = "module_layout"
        $s15 = "init_uts_ns"
        $s16 = "init_net"
        $s17 = "init_task"
        $s18 = "filp_open"
        $s19 = "__netlink_kernel_create"
        $s20 = "kfree_skb"

    condition:

        (uint32(0) == 0x4464c457f) and
        filesize < 200KB and
        all of them
}
rule apt_nix_elf_Derusbi_Linux_SharedMemCreation {

    meta:

      description = "Rule to detect Derusbi Linux Shared Memory creation"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

    condition:

        (uint32(0) == 0x464C457F) and
        filesize < 200KB and
        all of them
}
rule apt_nix_elf_Derusbi_Linux_Strings {

    meta:

      description = "Rule to detect APT Derusbi Linux Strings"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

    strings:

        $a1 = "loadso" wide ascii fullword
        $a2 = "\nuname -a\n\n" wide ascii
        $a3 = "/dev/shm/.x11.id" wide ascii
        $a4 = "LxMain64" wide ascii nocase
        $a5 = "# \\u@\\h:\\w \\$ " wide ascii
        $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
        $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
        $b3 = "ret %d" wide fullword
        $b4 = "uname -a\n\n" wide ascii
        $b5 = "/proc/%u/cmdline" wide ascii
        $b6 = "/proc/self/exe" wide ascii
        $b7 = "cp -a %s %s" wide ascii
        $c1 = "/dev/pts/4" wide ascii fullword
        $c2 = "/tmp/1408.log" wide ascii fullword

    condition:

        uint32(0) == 0x464C457F and
        filesize < 200KB and
        ((1 of ($a*) and
        4 of ($b*)) or
        (1 of ($a*) and
        1 of ($c*)) or
        2 of ($a*) or
        all of ($b*))
}
rule apt_win_exe_trojan_derusbi {

   meta:

      description = "Rule to detect Derusbi Trojan"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-05-31"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:ELF/Derusbi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://attack.mitre.org/software/S0021/"

   strings:

        $sa_1 = "USB" wide ascii
        $sa_2 = "RAM" wide ascii
        $sa_3 = "SHARE" wide ascii
        $sa_4 = "HOST: %s:%d"
        $sa_5 = "POST"
        $sa_6 = "User-Agent: Mozilla"
        $sa_7 = "Proxy-Connection: Keep-Alive"
        $sa_8 = "Connection: Keep-Alive"
        $sa_9 = "Server: Apache"
        $sa_10 = "HTTP/1.1"
        $sa_11 = "ImagePath"
        $sa_12 = "ZwUnloadDriver"
        $sa_13 = "ZwLoadDriver"
        $sa_14 = "ServiceMain"
        $sa_15 = "regsvr32.exe"
        $sa_16 = "/s /u" wide ascii
        $sa_17 = "rand"
        $sa_18 = "_time64"
        $sa_19 = "DllRegisterServer"
        $sa_20 = "DllUnregisterServer"
        $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver
        $sb_1 = "PCC_CMD_PACKET"
        $sb_2 = "PCC_CMD"
        $sb_3 = "PCC_BASEMOD"
        $sb_4 = "PCC_PROXY"
        $sb_5 = "PCC_SYS"
        $sb_6 = "PCC_PROCESS"
        $sb_7 = "PCC_FILE"
        $sb_8 = "PCC_SOCK"
        $sc_1 = "bcdedit -set testsigning" wide ascii
        $sc_2 = "update.microsoft.com" wide ascii
        $sc_3 = "_crt_debugger_hook" wide ascii
        $sc_4 = "ue8G5" wide ascii
        $sd_1 = "NET" wide ascii
        $sd_2 = "\\\\.\\pipe\\%s" wide ascii
        $sd_3 = ".dat" wide ascii
        $sd_4 = "CONNECT %s:%d" wide ascii
        $sd_5 = "\\Device\\" wide ascii
        $se_1 = "-%s-%04d" wide ascii
        $se_2 = "-%04d" wide ascii
        $se_3 = "FAL" wide ascii
        $se_4 = "OK" wide ascii
        $se_5 = "2.03" wide ascii
        $se_6 = "XXXXXXXXXXXXXXX" wide ascii

   condition:
      
      (uint16(0) == 0x5A4D) and
      filesize < 200KB and
      ( (all of ($sa_*)) or
      ((13 of ($sa_*)) and
      ( (5 of ($sb_*)) or
      (3 of ($sc_*)) or
      (all of ($sd_*)) or
      ( (1 of ($sc_*)) and
      (all of ($se_*)) ) ) ) )
}
rule ransom_mespinoza {
   meta:
      description = "rule to detect Mespinoza ransomware"
      author = "Christiaan Beek @ McAfee ATR"
      date = "2020-11-24"
      malware_family = "ransom_Win_Mespinoza"
      hash1 = "e9662b468135f758a9487a1be50159ef57f3050b753de2915763b4ed78839ead"
      hash2 = "48355bd2a57d92e017bdada911a4b31aa7225c0b12231c9cbda6717616abaea3"
      hash3 = "e4287e9708a73ce6a9b7a3e7c72462b01f7cc3c595d972cf2984185ac1a3a4a8"
  
   strings:
      $s1 = "update.bat" fullword ascii
      $s2 = "protonmail.com" fullword ascii
      $s3 = "Every byte on any types of your devices was encrypted." fullword ascii
      $s4 = "To get all your data back contact us:" fullword ascii
      $s5 = "What to do to get all data back?" fullword ascii
      $s6 = "Don't try to use backups because it were encrypted too." fullword ascii

      $op0 = { 83 f8 4b 75 9e 0f be 46 ff 8d 4d e0 ff 34 85 50 }
      $op1 = { c6 05 34 9b 47 00 00 e8 1f 0c 03 00 59 c3 cc cc }
      $op2 = { e8 ef c5 fe ff b8 ff ff ff 7f eb 76 8b 4d 0c 85 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "b5e8bd2552848bb7bf2f28228d014742" and ( 8 of them ) and 2 of ($op*)
      ) or ( all of them )
}
rule kraken_cryptor_ransomware_loader {

   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware loader"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Kraken"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
      hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"

   strings:

      $pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
      $s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
      $s3 = "public_key" fullword ascii
      $s4 = "KRAKEN DECRYPTOR" ascii
      $s5 = "UNIQUE KEY" fullword ascii

   condition:

       uint16(0) == 0x5a4d and 
       filesize < 600KB  and 
       $pdb or 
       all of ($s*)
}
rule ransom_Black_KingDom{

	meta:

	description = "Rule to detect Black Kingdom ransomware that is spread using the latest Exchange vulns"
	author = "McAfee ATR"
	date = "20210326"
	rule_version = "v1"
	malware_type = "ransomware"
	malware_family = "Ransomware:W32/BlackKingdom_March2021"
	actor_type = "Cybercrime"
	actor_group = "Unknown"

	  strings:
	    $0 = {7D3F634F627C5EC4D893189F1731F624A6AD458C3D89E9CB22C69EC4B4B588B1A7307D8963EC294C5B718C3D85692B8EB1A730732F8EB16F65EA5CEC17834A665E}
	    $1 = {3E774F2038FDE77377253CD11BFEB6FB82CF6A03E1B34E134C78A2CFDC1B7CD63AD167EE4E78A227FEF694EE3369143D1B0E84CF7CDAE7C3037C263DD15B979F}
	    $2 = {0C674D0A2427CDDD9B68213EC0B4A5DF94B19D39BEC0C562346FC7A1D32C0FA5BC9D963440910709A2365360650F5A909685912220EEC0F8157B3E2B95EA2CE9}
	    $3 = {7B7251266178C52BA731333F9E8A1C327A239FB81B901BAB2755FCAFD8A753F47991516A5C98A6CAAC9A1D5065DE565D87F120B3519DD91E09D353B7120EF9F2}
	    $4 = {2E233E25767037CA68F9C0F026A5CDDCC08FC0DCE21F61C612F1983A29BD3D986F8239A7692B0EBD478B6C8115564D5B0671346CF7CDDB612247EA7A4FAA7C71}
	    $5 = {2B2C3249094C8A1A9734E7515D10F78FD1B9339DF1902AC1D4ADE70C27C8A2CA7F3416B7B9F0D10E67519D589B8AD64D6435CC2DF4C2092A4BCEF7053B194AE5}
	    $6 = {0B297C7D79ECD339B30E87775B6769909CD886D1FBBAF2041DCC4FB11B5BA777AA626A9E8CAC14F64BEA5299A8E304A22BA25FA4F7AC4B95E8ACC42EC33A3DE4}
	    $7 = {0D46503D4DFD825DED41C94C055E1FCE1134C6F63AD80DCD7427F4BD502FA186077BD22653AB098C96ECDDA26557FB82BBA053CB2067C9DEA7EE0AF6A44C468A}
	    $8 = {2E774F2038FDE77277253CD11BFEB6FB82CB6A03E1B34E134C78A2CFDC1B5CD63AD167EE4E78A227FEF694EE3269143D1B0E84CF7CDAE5C3035C263DD15B979B}
	    $9 = {5C4250510A8DEF3463BF7410DEE0E72759B8A94A4D0544BD9B4FC0846E61844F4E06B779ABF906A450F5A2AC4C57CF761798C539175F092FD2429DC27909E382}
	    $10 = {7C787B386177B4D7F1F6B9E6FE17154FF15BD9E3F1DA94A1E1064654E7500A0B86A20A4AA16BD4E16F19A8733960DE868F10F382CDEEC1F15CE718839241DA10}
	    $11 = {2C3C6F6B2E597AC746FF7664087C7E899ABCC27AC60FA545D9CF4323063896D299F57132FE3E63E567EBFADF296365A1B2C0163DD8A4F3DABA04C77FA39A99CB}
	    $12 = {7B3C5D7C73D34D1A6C66B91990D162CACD89ECEAF591AC56C95AB3151EBAC1687FB749924B7BC27917FE50CA6C1417FEDBCC5BA2B7C03B1AEE4F5732E69DAC14}
	    $13 = {406357775C42584F11A1610D3A8A31F094FA252BC3E10738BD310D536D3A2F9EC5C21996AC4DCF5237AE3A4467D5678EE2983E4282ADFB1FDEA16352109BA7A7}
	    $14 = {2F265663680CACC66731B11AA78D588D7B54AC06C6348905D6B8F52C608D8208B0C6C5F1C11A2F69608D363DFA2A365AA387DAFCC906B486548F3DA8FE36312E}
	    $15 = {2B37480D634C799C468B775404368C7B891ADE3A556DF888566EB8CB3ED6F0171B59C35BB57F3B75D9017B7C9D52D1E87F48795AA58A16695B98BAFEAF66A769}
	    $16 = {0A76372D4F488ED5649A19B42E9E42B1DCC2E62655E7041711A6235B825D791CD6519492309D46964594F78B1DCAD17A5BEA574166B8A8EB76A52CA1052D724A}
	    $17 = {3D0B635F789C6CA6ADAC549548AA509C99D0C8DD823C99704423B90175B062E70EBBA67F937D622FF41B59D21E763A26D36759F3297D12B7454D82676C5B7B4A}
	    $18 = {225B642B7A09E7B06A4D3B95D97927AC46DABAE3ECE93AA4B307259DB9C01361C905B240678DB830EB7E172EB939ECB188ED3504B3709A746772B7BC94C83FB6}
	    $19 = {27465E49761EECAF449A3AB147907CF1C3D5F161D353E236BF9940AEC099EA4AC0352576803626029A15B3E978AB84D0024A1E345FFE58A81CDA2FBD61408971}
	    $20 = {3B7431210BEE4762B447DF044B5D6F41D53824C3E2CD17A35D71029352B47DA3811C60458EAADEBA532F75C54A3DDFC74AB3BEA7A51AF81A4A688F5D7A10378C}
	    $21 = {276C41453F8F2D8279980EAD3328E2478A3D84C55EB668231A12EED150E496622FCB2C04D9CBCE257BD97B9ECE404037589A185573F936A78DA88AD43EFC3948}
	    $22 = {2727495F5B1B4D920E35A52B6A5DB6A7F8B31A26873E20C53388696567D692B4B1F4A0B9267E4BBDA1728A5E883FD69029A07669AC1D0DC22E3157C028705C19}
	    $23 = {3E5552672C26C4F22824AF196F222D370F9EEDBEF119B8C3DD96414CF3529912234CB08AA7B2A034A51635319EAC44D47FA68747BA4B2FD2A884373ADEFB5C84}
	    $24 = {20735E632C6C70375BCA935EE39B7FA508205E9CC034CBD193A0D1C1E3A9A13818B9EB7FEFB11891E71221DB7143286C7D36A91C1FF7615E38F02E5C1BA24AFF}
	    $25 = {0A3D69344860D944AA8A46908019AB085E025AA693D381A34D8DCF116B25B0C62355D93893D1F64B983986C7E956C22303A9AB109680BF4B74460C5B087412AF}
	    $26 = {7C5B79652BC66C9BC36B11730D556FFA1CA1616CA59C0C344FD1F6B50C9C259329D699CDF0B894F1540AFDC4F431957206B0748AB6AE3B9069CD91147E09709B}
	    $27 = {2257442B42DB79A5E6CAD745E9A8D9775E4216C95F6094A05F05D7DAADBB03EC4B3444983DD291C2E32FC39299BCB4D22219386E75DAABB8D2EA93DFC52A248B}
	    $28 = {3C0D4A68792594D2F23F10A465B38B75D272318CA0E532A8A183F8CE5DEE6B45ECFDC96E4FF9158832472ED8CDFA69F92868A503F821D848CBB97B58332D8F84}
	  condition:
	    uint16(0) == 0x5a4d and all of them
}
rule netwalker_ransomware{
        meta:

            description = "Rule to detect Netwalker ransomware"
            author = "McAfee ATR Team"
            date = "2020-03-30"
            rule_version = "v1"
            malware_type = "ransomware"
            reference = "https://www.ccn-cert.cni.es/comunicacion-eventos/comunicados-ccn-cert/9802-publicado-un-informe-de-codigo-danino-sobre-netwalker.html"
            note = "The rule doesn't detect the samples packed with UPX"
            
        strings:

            $pattern = { 8B????8B????89??C7????????????EB??8B????52E8????????83????8B????8B??5DC3CCCCCCCCCCCCCCCCCCCCCCCC558B??83????C7????????????83??????74??83??????72??83??????75??8B????E9????????C7????????????8B????33??B9????????F7??83????89????8B????8B????8D????51E8????????83????89????83??????0F84????????C7????????????C7????????????C6??????C6??????C6??????8B????3B????0F84????????8B????2B????39????73??8B????89????EB??8B????2B????89????8B????89????C7????????????8B????03????8B????2B??89????74??83??????7E??83??????7D??C7????????????8B????03????89????8B????518B????03????528B????03????50E8????????83????8B????03????89????83??????75??6A??8D????528B????03????50E8????????83????8B????83????89????8B????03????89????E9????????8B????8B????89??83??????74??8B????52E8????????83????8B????89??C7????????????8B????8B??5DC3CCCCCCCC558B??51B8????????6B????8B????0FB6????B9????????C1????8B????0FB6????C1????0B??BA????????D1??8B????0FB6????C1????0B??B9????????6B????8B????0FB6????C1????0B??B9????????C1????8B????89????B8????????6B????8B????0FB6??????B9????????C1????8B????0FB6??????C1????0B??BA????????D1??8B????0FB6??????C1????0B??B9????????6B????8B????0FB6??????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????B9????????6B????8B????0FB6??????BA????????C1????8B????0FB6??????C1????0B??B8????????D1??8B????0FB6??????C1????0B??BA????????6B????8B????0FB6??????C1????0B??BA????????6B????8B????89????81????????????75??8B????83????89????C7????????????EB??C7????????????B9????????6B????8B????0FB6????BA????????C1????8B????0FB6????C1????0B??B8????????D1??8B????0FB6????C1????0B??BA????????6B????8B????0FB6????C1????0B??BA????????C1????8B????89????B9????????6B????8B????0FB6??????BA????????C1????8B????0FB6??????C1????0B??B8????????D1??8B????0FB6??????C1????0B??BA????????6B????8B????0FB6??????C1????0B??BA????????6B????8B????89????B8????????6B????8B????0FB6??????B9????????C1????8B????0FB6??????C1????0B??BA????????D1??8B????0FB6??????C1????0B??B9????????6B????8B????0FB6??????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????B9????????6B????8B????0FBE????BA????????C1????8B????0FBE????C1????0B??B8????????D1??8B????0FBE????C1????0B??BA????????6B????8B????0FBE????C1????0B??BA????????6B????8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????C1????8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????D1??8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????6B????8B????89????8B??5DC3CCCCCC558B??B8????????6B????8B????C7????????????B8????????6B????8B????C7????????????B8????????6B????8B????0FB6????B9????????C1????8B????0FB6????C1????0B??BA????????D1??8B????0FB6????C1????0B??B9????????6B????8B????0FB6????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????5DC3CCCCCC558B??83????83??????75??E9????????8B????508D????51E8????????83????BA????????6B????8B????8B????83????B8????????6B????8B????89????B9????????6B????8B????83??????75??B9????????6B????8B????8B????83????BA????????6B????8B????89????83??????77??C7????????????EB??8B????83????89????8B????3B????73??8B????03????0FB6??8B????0FB6??????33??8B????03????88??EB??EB??C7????????????EB??8B????83????89????83??????73??8B????03????0FB6??8B????0FB6??????33??8B????03????88??EB??8B????83????89????8B????83????89????8B????83????89????E9????????8B??5DC3CCCCCCCCCCCCCCCC558B??83????C7????????????EB??8B????83????89????83??????7D??8B????8B????8B????8B????89??????EB??C7????????????EB??8B????83????89????83??????0F8E????????B9????????6B????B8????????C1????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????C1????B8????????6B????8B??????03??????B8????????C1????89??????B9????????C1????BA????????C1????8B??????33??????C1????B9????????C1????BA????????C1????8B??????33??????C1????0B??BA????????C1????89??????B8????????6B????BA????????C1????8B??????03??????B9????????6B????89??????B8????????6B????BA????????6B????8B??????33??????C1????BA????????6B????BA????????6B????8B??????33??????C1????0B??BA????????6B????89??????B9????????C1????BA????????6B????8B??????03??????BA????????C1????89??????B8????????C1????B9????????C1????8B??????33??????C1????B8????????C1????B9????????C1????8B??????33??????C1????0B??B9????????C1????89??????BA????????C1????B8????????6B????8B??????03??????B8????????C1????89??????B9????????6B????B8????????C1????8B??????33??????C1????BA????????6B????BA????????C1????8B??????33??????C1????0B??BA????????6B????89??????B9????????6B????B8????????6B????8B??????03??????B8????????6B????89??????BA????????6B????B9????????6B????8B??????33??????C1????B9????????6B????B9????????6B????8B??????33??????C1????0B??B9????????6B????89??????B8????????C1????B9????????6B????8B??????03??????B9????????C1????89??????BA????????6B????B9????????C1????8B??????33??????C1????B8????????6B????B8????????C1????8B??????33??????C1????0B??B8????????6B????89??????BA????????6B????B9????????6B????8B??????03??????B9????????6B????89??????B8????????6B????BA????????6B????8B??????33??????C1????BA????????6B????BA????????6B????8B??????33??????C1????0B??BA????????6B????89??????B9????????D1??BA????????6B????8B??????03??????BA????????D1??89??????B8????????6B????BA????????D1??8B??????33??????C1????B9????????6B????B9????????D1??8B??????33??????C1????0B??B9????????6B????89??????B8????????6B????BA????????6B????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????D1??B8????????6B????8B??????03??????B8????????D1??89??????B9????????6B????B8????????D1??8B??????33??????C1????BA????????6B????BA????????D1??8B??????33??????C1????0B??BA????????6B????89??????B9????????6B????B8????????6B????8B??????03??????B8????????6B????89??????BA????????6B????B9????????6B????8B??????33??????C1????B9????????6B????B9????????6B????8B??????33??????C1????0B??B9????????6B????89??????B8????????6B????BA????????6B????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????6B???? }

            $pattern2 = { CCCCCCCCCCA1????????C3CCCCCCCCCCCCCCCCCCCC538B??????5533??5785??74??8B??????85??74??8B????85??74??C1????50E8????????83????89??85??74??8B????5633??85??74??5653E8????????83????85??74??8B????85??74??8D??????89??????5150E8????????83????85??74??8B????8B??8B??????89????FF????8B????463B??72??39????B9????????5E0F44??5F8B??5D5BC35F5D33??5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC535556578B??????85??74??83????74??8B????85??74??8B??????85??74??33??85??74??8B??????660F1F??????85??74??8B??53FF????E8????????EB??E8????????8D????8B??FF????8B??53FF??83????85??75??463B????72??5F5E5D33??5BC35F5E5DB8????????5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC6A??FF??????FF??????E8????????83????C3CCCCCCCCCCCCCCCCCCCCCCCCCC6A??FF??????FF??????E8????????83????C3CCCCCCCCCCCCCCCCCCCCCCCCCC83????????????5674??8B??????85??74??56E8????????8B????50E8????????83????85??75??A1????????6A??83????5650E8????????83????85??75??56E8????????83????85??74??8D????66??????74??83????83????75??33??5EC383????74??A1????????6A??83????5150E8????????83????85??74??B8????????5EC3CCCCCCCCCCCCCCCCCCCC83????????????74??8B??????85??74??A1????????6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCCCCCCCCCCCCCC83????????????5674??A1????????83??????74??8B??????85??74??56E8????????8B??????????83????83????75??83??????74??66????????75??0FB7??83????72??83????76??83????66??????76??6A??8D????5650E8????????83????85??74??B8????????5EC333??5EC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC83????????????74??A1????????83????????????74??8B??????85??74??6A??05????????5150E8????????83????85??74??B8????????C333??C3CCCCCC83????????????74??A1????????83????????????74??8B??????85??74??6A??05????????5150E8????????83????85??74??B8????????C333??C3CCCCCC83????????????74??8B??????85??74??A1????????83??????74??6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCC83????????????74??8B??????85??74??A1????????83??????74??6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCC83????????????5674??8B??????85??74??A1????????83??????74??51E8????????8B??83????85??74??8B??????????6A??83????5651E8????????83????85??74??B8????????5EC356E8????????83????33??5EC3CCCCCCCCCCCCCC535556576A??E8????????8B??83????85??0F84????????8B??660F1F??????0FB7????83????51E8????????8B??83????85??74??0FB7????51FF????57E8????????83????83????????????74??A1????????83??????74??6A??83????5750E8????????83????85??74??E8????????8B????3B????74??6A??51E8????????8B??83????85??74??E8????????6A??538B????FF??E8????????538B??????????FF??57E8????????83????8B??03??85??0F85????????55E8????????83????E8????????6A??8B??????????FF??E9????????CCCCCCCCCCCCCC83????5533??565739??????????0F84????????8B??????85??0F84????????8B??????85??0F84????????53E8????????8B??????????FF??83??????8B??74??E8????????FF????8B??????????FF??89??????E8????????8D??????516A??8B??????????8D??????516A??57FF??85??74??8B??????89????83????74??E8????????8B??????????FF??2B??3D????????77??83??????75??5B5F5E8B??5D83????C3BD????????5B5F5E8B??5D83????C35F5E33??5D83????C383????558B??????85??0F84????????5333??5733??89??????89??????E8????????8D??????518D??????8B??????????5157576A??FF????FF??85??0F85????????E8????????8B??????????FF??3D????????0F85????????FF??????E8????????83????89??????85??0F84????????56E8????????8D??????518D??????8B??????????51FF??????FF??????6A??FF????FF??85??74??33??39??????76??8B??????0F1F??????????E8????????8B??????68????????FF????8B??????????FF??FF??89??????8D????????????5053E8????????8B??83????85??74??FF??????68????????E8????????83????89????474683????3B??????72??8B??????FF??????E8????????83????85??74??85??74??E8????????6A??6A??538B??????????57FF??33??85??74??E8????????FF????8B??????????FF??463B??72??53E8????????83????5EE8????????8D??????516A??FF????8B??????????FF??5F5B85??74??8D??????50FF????E8????????83????E8????????FF????8B??????????FF??55E8????????83????33??5D83????C2????CCCCCCCCCCCCCCCCCCCCCCCC83????568B??????85??74??E8????????8D??????516A??8B??????????56FF??85??74??8D??????5056E8????????83????E8????????568B??????????FF??33??5E83????C2????CCCCCCCCCCCC83????83????????????5356570F84????????A1????????83??????0F84????????55E8????????68????????6A??6A??8B??????????FF??8B??89??????85??0F84????????660F1F????????????C7??????????????C7??????????????C7??????????????E8????????8D??????518D??????8B??????????518D??????516A??6A??6A??6A??55FF??85??0F85????????E8????????8B??????????FF??3D????????0F85????????FF??????E8????????83????89??????85??0F84????????E8????????8B??????8D??????518D??????8B??????????518D??????51FF??????566A??6A??55FF??85??0F84????????33??33??89??????39??????0F86????????0F1F??????????FF??E8????????83????85??75??FF????E8????????83????85??74??E8????????68????????FF??8B??????????55FF??89??????85??74??6A??E8????????8B??83????85??74??8B??????8D????????????5189????8B??????5389????E8????????8B??83????85??74??5568????????E8????????83????89????478B??????8B??????83????4089??????3B??????0F82????????85??74??85??74??E8????????6A??6A??538B??????????57FF??33??85??74??0F1F????E8????????FF????8B??????????FF??463B??72??53E8????????83????FF??????E8????????83????E8????????68????????8B??????????FF??E9????????5D5F5E33??5B83????C2????CCCCCC83????53558B??????565785??0F84????????8B????8D??????516A??55C7??????????????FF????85??0F88????????8B??????8D??????C7??????????????52508B??FF????85??0F88????????6A??8D??????6A??50E8????????33??83????B8????????66????????39??????0F8E????????8B??????8D??????5083????C7??????????????438B??89??????0F10??????8B??510F11??FF????85??0F88????????8B??????8D??????C7??????????????52508B??FF????85??0F88????????8B??????8D??????C7??????????????33??52508B??FF????83????????0F84????????FF??????E8????????83????85??0F85????????8B??????8D??????89??????52508B??FF????85??0F88????????8B??????8D??????89??????52508B??FF????85??0F88????????8B??????8D??????89??????52508B??FF????85??0F88????????33?? }

            $pattern3 = { CCCCCCCCCC558B??FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF?????????? }

        condition:
            
            uint16(0) == 0x5a4d and
            any of ($pattern*) 
}
rule Netwalker {

    meta:

        description = "Rule based on code overlap in RagnarLocker ransomware"
        author = "McAfee ATR team"
        date = "2020-06-14"
        rule_version = "v1"
        malware_type = "ransomware"
        actor_group = "Unknown"

  strings:

    $0 = {C88BF28B4330F76F3803C88B434813F2F76F2003C88B433813F2F76F3003C88B434013F2F76F2803C88B432813F2F76F4003C8894D6813F289756C8B4338F76F388BC88BF28B4328F76F4803C88B434813F2F76F2803C88B433013F2F76F400FA4CE}
    $1 = {89542414895424108BEA8BDA8BFA423C22747C3C5C75588A023C5C744F3C2F744B3C2274473C6275078D5702B008EB3F3C6675078D5302B00CEB343C6E75078D5502B00AEB293C72750B8B542410B00D83C202EB1A3C74750B8B542414B00983C2}
    $2 = {C8894D7013F28975748B4338F76F408BC88BF28B4340F76F3803C88B433013F2F76F4803C88B434813F2F76F3003C8894D7813F289757C8B4348F76F388BC88BF28B4338F76F4803C88B434013F2F76F400FA4CE}
    $3 = {C07439473C2F75E380FB2A74DEEB2D8D4ABF8D422080F9190FB6D80FB6C28AD60F47D88AC6042080EA410FB6C880FA190FB6C60F47C83ACB754B46478A1684D2}
    $4 = {8B433013F2F76F0803C88B432013F2F76F1803C88B0313F2F76F3803C88B430813F2F76F3003C88B433813F2F72F03C8894D3813F289753C8B4338F76F088BC8}
    $5 = {F73101320E32213234329832E3320C332D334733643383339133A833BD33053463347C34543564358335AE36C3362937E9379A39BA390A3A203A443A183B2B3B}
    $6 = {8B431813F2F76F4803C88B432813F2F76F3803C88B434013F2F76F200FA4CE0103C903C88B432013F2F76F4003C88B433013F2F76F3003C8894D6013F2897564}
  
  condition:

    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and 
    all of them
}
rule ransomware_sodinokibi {
   meta:
      description = "Using a recently disclosed vulnerability in Oracle WebLogic, criminals use it to install a new variant of ransomware called ¡°Sodinokibi"
      author = "Christiaan Beek | McAfee ATR team"
      date = "2019-05-13"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Sodinokibi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash4 = "9b62f917afa1c1a61e3be0978c8692dac797dd67ce0e5fd2305cc7c6b5fef392"

   strings:

      $x1 = "sodinokibi.exe" fullword wide
      
      $y0 = { 8d 85 6c ff ff ff 50 53 50 e8 62 82 00 00 83 c4 }
      $y1 = { e8 24 ea ff ff ff 75 08 8b ce e8 61 fc ff ff 8b }
      $y2 = { e8 01 64 ff ff ff b6 b0 }

   condition:

      ( uint16(0) == 0x5a4d and 
      filesize < 900KB and 
      pe.imphash() == "672b84df309666b9d7d2bc8cc058e4c2" and 
      ( 8 of them ) and 
      all of ($y*)) or 
      ( all of them )
}
rule Sodinokobi{
    meta:

        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
        author      = "McAfee ATR team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Sodinokibi"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        version     = "1.0"
        
    strings:

        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}
rule badrabbit_ransomware {
   
   meta:

      description = "Rule to detect Bad Rabbit Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown" 
      reference = "https://securelist.com/bad-rabbit-ransomware/82851/"

   strings:
   
      $s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
      $s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "need to do is submit the payment and get the decryption password." fullword wide
      $s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $s6 = "rundll32 %s,#2 %s" fullword ascii
      $s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $s8 = "Readme.txt" fullword wide
      $s9 = "wbem\\wmic.exe" fullword wide
      $s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide

      $og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
      $og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
      $og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }

      $oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
      $oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
      $oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }

      $oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
      $oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
      $oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }

      $ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
      $ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
      $ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }


   condition:

      uint16(0) == 0x5a4d and
      filesize < 1000KB and
      (all of ($s*) and
      all of ($og*)) or
      all of ($oh*) or
      all of ($oj*) or
      all of ($ok*)
}
rule RANSOM_RYUK_May2021 : ransomware{
	meta:
		description = "Rule to detect latest May 2021 compiled Ryuk variant"
		author = "Marc Elias | McAfee ATR Team"
		date = "2021-05-21"
		hash = "8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a"
		version = "0.1"

	strings:
		$ryuk_filemarker = "RYUKTM" fullword wide ascii
		
		$sleep_constants = { 68 F0 49 02 00 FF (15|D1) [0-4] 68 ?? ?? ?? ?? 6A 01 }
		$icmp_echo_constants = { 68 A4 06 00 00 6A 44 8D [1-6] 5? 6A 00 6A 20 [5-20] FF 15 }
		
	condition:
		uint16(0) == 0x5a4d
		and uint32(uint32(0x3C)) == 0x00004550
		and filesize < 200KB
		and ( $ryuk_filemarker
		or ( $sleep_constants 
		and $icmp_echo_constants ))
}
rule Ransom_Win_BlackCat{
	  meta:
	  description = "Detecting variants of Windows BlackCat malware"
	  author = " Trellix ATR"
	  date = "2022-01-06"
	  malware_type = "Ransomware"
	  detection_name = "Ransom_Win_BlackCat"
	  actor_group = "Unknown"

	strings:

	 $URL1 = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide
	 $URL2 = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide

	 $API = { 3a 7c d8 3f }

	 condition:
	  uint16(0) == 0x5a4d and
	  filesize < 3500KB and
	  1 of ($URL*) and
	  $API
}
rule ragnarlocker_ransomware {

   meta:
   
      description = "Rule to detect RagnarLocker samples"
      author = "McAfee ATR Team"
      date = "2020-04-15"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/RagnarLocker"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/ragnar-locker-ransomware-targets-msp-enterprise-support-tools/"
      hash = "9706a97ffa43a0258571def8912dc2b8bf1ee207676052ad1b9c16ca9953fc2c"
      
   strings:
   
      //---RAGNAR SECRET---
      $s1 = {2D 2D 2D 52 41 47 4E 41 52 20 53 45 43 52 45 54 2D 2D 2D}
      $s2 = { 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? B8 ?? ?? ?? ?? 0F 44 }
      $s3 = { 5? 8B ?? 5? 5? 8B ?? ?? 8B ?? 85 ?? 0F 84 }
      $s4 = { FF 1? ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 85 }
      $s5 = { 8D ?? ?? ?? ?? ?? 5? FF 7? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
      
      $op1 = { 0f 11 85 70 ff ff ff 8b b5 74 ff ff ff 0f 10 41 }
      
      $p0 = { 72 eb fe ff 55 8b ec 81 ec 00 01 00 00 53 56 57 }
      $p1 = { 60 be 00 00 41 00 8d be 00 10 ff ff 57 eb 0b 90 }
      
      $bp0 = { e8 b7 d2 ff ff ff b6 84 }
      $bp1 = { c7 85 7c ff ff ff 24 d2 00 00 8b 8d 7c ff ff ff }
      $bp2 = { 8d 85 7c ff ff ff 89 85 64 ff ff ff 8d 4d 84 89 }
      
   condition:
   
     uint16(0) == 0x5a4d and 
     filesize < 100KB and 
     (4 of ($s*) and $op1) or
     all of ($p*) and
     pe.imphash() == "9f611945f0fe0109fe728f39aad47024" or
     all of ($bp*) and
     pe.imphash() == "489a2424d7a14a26bfcfb006de3cd226" 
}
rule ransom_conti {
   
   meta:

      description = "Conti ransomware is havnig capability too scan and encrypt oover the network"
      author = "McAfee ATR team"
      reference = "https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/"
      date = "2020-07-09"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Conti"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
   
   strings:

      $string1 = "HOW_TO_DECRYPTP" fullword ascii
      $string2 = "The system is LOCKED." fullword ascii
      $string3 = "The network is LOCKED." fullword ascii


      $code1 = { ff b4 b5 48 ff ff ff 53 ff 15 bc b0 41 00 85 c0 }
      $code2 = { 6a 02 6a 00 6a ff 68 ec fd ff ff ff 76 0c ff 15 }
      $code3 = { 56 8d 85 38 ff ff ff 50 ff d7 85 c0 0f 84 f2 01 }
   
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 300KB and 
      pe.number_of_sections == 5 and
      ( pe.imphash() == "30fe3f044289487cddc09bfb16ee1fde" or 
      ( all of them and
      all of ($code*) ) )
}














rule HKTL_Meterpreter_inMemory {
   meta:
      description = "Detects Meterpreter in-memory"
      author = "netbiosX, Florian Roth"
      reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
      date = "2020-06-29"
      modified = "2023-04-21"
      score = 85
   strings: 
      $sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
      $sxs1 = "metsrv.x64.dll" ascii fullword
      $ss1 = "WS2_32.dll" ascii fullword
      $ss2 = "ReflectiveLoader" ascii fullword

      $fp1 = "SentinelOne" ascii wide
      $fp2 = "fortiESNAC" ascii wide
      $fp3 = "PSNMVHookMS" ascii wide
   condition: 
      ( 1 of ($sx*) or 2 of ($s*) )
      and not 1 of ($fp*)
}
rule Certutil_Decode_OR_Download {
   meta:
      description = "Certutil Decode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      score = 40
      date = "2017-08-29"
   strings:
      $a1 = "certutil -decode " ascii wide
      $a2 = "certutil  -decode " ascii wide
      $a3 = "certutil.exe -decode " ascii wide
      $a4 = "certutil.exe  -decode " ascii wide
      $a5 = "certutil -urlcache -split -f http" ascii wide
      $a6 = "certutil.exe -urlcache -split -f http" ascii wide
   condition:
      ( not MSI and filesize < 700KB and 1 of them )
}
rule Invoke_Mimikatz {
	meta:
		description = "Detects Invoke-Mimikatz String"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		date = "2016-08-03"
		hash1 = "f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67"
	strings:
		$x2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii
      $x3 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii
	condition:
      1 of them
}
rule APT_MAL_RANSOM_ViceSociety_PolyVice_Jan23_1 {
   meta:
      description = "Detects NTRU-ChaChaPoly (PolyVice) malware used by Vice Society"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12"
      modified = "2023-01-13"
      score = 75
      hash1 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
      hash2 = "8c8cb887b081e0d92856fb68a7df0dabf0b26ed8f0a6c8ed22d785e596ce87f4"
      hash3 = "9d9e949ecd72d7a7c4ae9deae4c035dcae826260ff3b6e8a156240e28d7dbfef"
   strings:
      $x1 = "C:\\Users\\root\\Desktop\\niX\\CB\\libntru\\" ascii
      
      $s1 = "C:\\Users\\root" ascii fullword
      $s2 = "#DBG: target = %s" ascii fullword
      $s3 = "# ./%s [-p <path>]/[-f <file> ] [-e <enc.extension>] [-m <requirements file name>]" ascii fullword
      $s4 = "### ################# ###" ascii fullword

      $op1 = { 89 ca 41 01 fa 89 ef 8b 6c 24 24 44 89 c9 09 d1 44 31 e6 89 c8 }
      $op2 = { bd 02 00 00 00 29 cd 48 0f bf d1 8b 44 46 02 01 44 53 02 8d 54 0d 00 83 c1 02 48 0f bf c2 }
      $op3 = { 48 29 c4 4c 8d 74 24 30 4c 89 f1 e8 46 3c 00 00 84 c0 41 89 c4 0f 85 2b 02 00 00 0f b7 45 f2 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and (
         1 of ($x*) 
         or 2 of them
      ) or 4 of them
}

rule Malware_QA_update {
	meta:
		description = "VT Research QA uploaded malware - file update.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "6d805533623d7063241620eec38b7eb9b625533ccadeaf4f6c2cc6db32711541"
		hash2 = "6415b45f5bae6429dd5d92d6cae46e8a704873b7090853e68e80cd179058903e"
	strings:
		$x1 = "UnActiveOfflineKeylogger" fullword ascii
		$x2 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii
		$x3 = "ActiveOnlineKeylogger" fullword ascii
		$x4 = "C:\\Users\\DarkCoderSc\\" ascii
		$x5 = "Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii
		$x6 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii

		$s1 = "MSRSAAP.EXE" fullword wide
		$s2 = "Command successfully executed!|" fullword ascii
		$s3 = "BTMemoryLoadLibary: Get DLLEntyPoint failed" fullword ascii
		$s4 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" fullword ascii
		$s5 = "\\Internet Explorer\\iexplore.exe" ascii
		$s6 = "ping 127.0.0.1 -n 4 > NUL && \"" fullword ascii
		$s7 = "BTMemoryGetProcAddress: DLL doesn't export anything" fullword ascii
		$s8 = "POST /index.php/1.0" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) or 3 of ($s*) ) )
		or ( all of them )
}

rule XMRIG_Monero_Miner : HIGHVOL {
   meta:
      description = "Detects Monero mining software"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04"
      modified = "2022-11-10"
      modified = "2022-11-10"
      hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
      hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
      hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
      hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
   strings:
      $s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s2 = "--cpu-affinity" ascii
      $s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
      $s4 = "password for mining server" fullword ascii
      $s5 = "XMRig/%s libuv/%s%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 10MB and 2 of them
}
rule Locky_Ransomware {
	meta:
		description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
		author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
		reference = "https://goo.gl/qScSrE"
		date = "2016-02-17"
		hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
	strings:
		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
	condition:
		all of ($o*)
}
rule Regin_Related_Malware {
	meta:
		description = "Malware Sample - maybe Regin related"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "76c355bfeb859a347e38da89e3d30a6ff1f94229"
	strings:
		$s1 = "%c%s%c -p %d -e %d -pv -c \"~~[%x] s; .%c%c%s %s /u %s_%d.dmp; q\"" fullword wide /* score: '22.015' */

		$s0 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide /* PEStudio Blacklist: os */ /* score: '26.02' */
		$s2 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii /* score: '13.01' */
		$s3 = "disp.dll" fullword ascii /* score: '11.01' */
		$s4 = "msvcrtd.dll" fullword ascii /* score: '11.005' */
		$s5 = "%d.%d.%d.%d%c" fullword ascii /* score: '11.0' */
		$s6 = "%ls_%08x" fullword wide /* score: '8.0' */
		$s8 = "d%ls%ls" fullword wide /* score: '7.005' */
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide /* score: '6.025' */
	condition:
		$s1 or 3 of ($s*)
}
rule IMPLANT_4_v7 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $sb1 = {C7 [1-5] 33 32 2E 64 C7 [1-5] 77 73 32 5F 66 C7 [1-5] 6C 6C}
      $sb2 = {C7 [1-5] 75 73 65 72 C7 [1-5] 33 32 2E 64 66 C7 [1-5] 6C 6C}
      $sb3 = {C7 [1-5] 61 64 76 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb4 = {C7 [1-5] 77 69 6E 69 C7 [1-5] 6E 65 74 2E C7 [1-5] 64 6C 6C}
      $sb5 = {C7 [1-5] 73 68 65 6C C7 [1-5] 6C 33 32 2E C7 [1-5] 64 6C 6C}
      $sb6 = {C7 [1-5] 70 73 61 70 C7 [1-5] 69 2E 64 6C 66 C7 [1-5] 6C}
      $sb7 = {C7 [1-5] 6E 65 74 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb8 = {C7 [1-5] 76 65 72 73 C7 [1-5] 69 6F 6E 2E C7 [1-5] 64 6C 6C}
      $sb9 = {C7 [1-5] 6F 6C 65 61 C7 [1-5] 75 74 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb10 = {C7 [1-5] 69 6D 61 67 C7 [1-5] 65 68 6C 70 C7 [1-5] 2E 64 6C 6C}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 3 of them
}

rule SUSP_NullSoftInst_Combo_Oct20_1 {
   meta:
      description = "Detects suspicious NullSoft Installer combination with common Copyright strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/1313023627177193472"
      date = "2020-10-06"
      score = 65
      hash1 = "686b5240e5e503528cc5ac8d764883413a260716dd290f114a60af873ee6a65f"
      hash2 = "93951379e57e4f159bb62fd7dd563d1ac2f3f23c80ba89f2da2e395b8a647dcf"
      hash3 = "a9ca1d6a981ccc8d8b144f337c259891a67eb6b85ee41b03699baacf4aae9a78"
   strings:
      $a1 = "NullsoftInst" ascii 

      $b1 = "Microsoft Corporation" wide fullword
      $b2 = "Apache Software Foundation" ascii wide fullword
      $b3 = "Simon Tatham" wide fullword

      $fp1 = "nsisinstall" fullword ascii
      $fp2 = "\\REGISTRY\\MACHINE\\Software\\" wide
      $fp3 = "Apache Tomcat" wide fullword
      $fp4 = "Bot Framework Emulator" wide fullword
      $fp5 = "Firefox Helper" wide fullword
      $fp6 = "Paint.NET Setup" wide fullword
      $fp7 = "Microsoft .NET Services Installation Utility" wide fullword
      $fp8 = "License: MPL 2" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and
      $a1 and 1 of ($b*) and 
      not 1 of ($fp*)
}

rule SUSP_XORed_URL_in_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      nodeepdive = 1
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii

      $fp01 = "3Com Corporation" ascii
      $fp02 = "bootloader.jar" ascii  
      $fp03 = "AVAST Software" ascii wide
      $fp04 = "smartsvn" wide ascii fullword
      $fp05 = "Avira Operations GmbH" wide fullword
      $fp06 = "Perl Dev Kit" wide fullword
      $fp07 = "Digiread" wide fullword
      $fp08 = "Avid Editor" wide fullword
      $fp09 = "Digisign" wide fullword
      $fp10 = "Microsoft Corporation" wide fullword
      $fp11 = "Microsoft Code Signing" ascii wide
      $fp12 = "XtraProxy" wide fullword
      $fp13 = "A Sophos Company" wide
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}
rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "UrsnifV3 Payload"
        cape_type = "UrsnifV3 Payload"
        packed = "75827be0c600f93d0d23d4b8239f56eb8c7dc4ab6064ad0b79e6695157816988"
        packed = "5d6f1484f6571282790d64821429eeeadee71ba6b6d566088f58370634d2c579"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 ?? 0F B6 3? FF 45 [2-4] 8B C? 23 C? 40 40 D1 E? 7?}
        $crypto32_3 = {F6 46 03 02 75 5? 8B 46 10 40 50 E8 [10-12] 74 ?? F6 46 03 01 74}
        $crypto32_4 = {C7 44 24 10 01 00 00 00 8B 4? 10 [12] 8B [2] 89 01 8B 44 24 10 5F 5E 5B 8B E5 5D C2 0C 00}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and 1 of ($crypto32_*) and $cpuid and not $cape_string
}
rule MAL_GandCrab_Apr18_1 {
   meta:
      description = "Detects GandCrab malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
      date = "2018-04-23"
      hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "7936b0e9491fd747bf2675a7ec8af8ba"
}

rule HKTL_NET_GUID_Stealer {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malwares/Stealer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
        $typelibguid0up = "8FCD4931-91A2-4E18-849B-70DE34AB75DF" ascii wide
        $typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
        $typelibguid1up = "E48811CA-8AF8-4E73-85DD-2045B9CCA73A" ascii wide
        $typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide
        $typelibguid2up = "D3D8A1CC-E123-4905-B3DE-374749122FCF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2020-10-13"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}
rule HKTL_NET_GUID_Stealer {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malwares/Stealer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
        $typelibguid0up = "8FCD4931-91A2-4E18-849B-70DE34AB75DF" ascii wide
        $typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
        $typelibguid1up = "E48811CA-8AF8-4E73-85DD-2045B9CCA73A" ascii wide
        $typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide
        $typelibguid2up = "D3D8A1CC-E123-4905-B3DE-374749122FCF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule SUSP_Modified_SystemExeFileName_in_File {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 65
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
   strings:
      $s1 = "svchosts.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}
rule CN_Honker_smsniff_smsniff {

	meta:

		description = "Sample from CN Honker Pentest Toolset - file smsniff.exe"

		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

		author = "Florian Roth (Nextron Systems)"

		reference = "Disclosed CN Honker Pentest Toolset"

		date = "2015-06-23"

		score = 70

		hash = "8667a785a8ced76d0284d225be230b5f1546f140"

	strings:

		$s1 = "smsniff.exe" fullword wide

		$s5 = "SmartSniff" fullword wide

	condition:

		uint16(0) == 0x5a4d and filesize < 267KB and all of them

}
rule Nanocore_RAT_Gen_2 {
   meta:
      description = "Detetcs the Nanocore RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 100
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"
   strings:
      $x1 = "NanoCore.ClientPluginHost" fullword ascii
      $x2 = "IClientNetworkHost" fullword ascii
      $x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}
rule MAL_Neshta_Generic : HIGHVOL {
   meta:
      description = "Detects Neshta malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-15"
      modified = "2021-04-14"
      hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
      hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
      hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
      hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"
   strings:
      $x1 = "the best. Fuck off all the rest."
      $x2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii

      $s1 = "Neshta" ascii fullword
      $s2 = "Made in Belarus. " ascii fullword

      $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
      $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
      $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }

      $sop1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
      $sop2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and (
         1 of ($x*) or 
         all of ($s*) or 
         3 of them or 
         pe.imphash() == "9f4693fc0c511135129493f2161d1e86"
      )
}
rule MAL_RANSOM_Venus_Nov22_1 {
   meta:
      description = "Detects Venus Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
      date = "2022-11-16"
      score = 85
      hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
      hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
      hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
      hash4 = "969bfe42819e30e35ca601df443471d677e04c988928b63fccb25bf0531ea2cc"
      hash5 = "db6fcd33dcb3f25890c28e47c440845b17ce2042c34ade6d6508afd461bfa21c"
      hash6 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
      hash7 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
   strings:
      $x1 = "<html><head><title>Venus</title><style type = \"text" ascii fullword
      $x2 = "xXBLTZKmAu9pjcfxrIK4gkDp/J9XXATjuysFRXG4rH4=" ascii fullword
      $x3 = "%s%x%x%x%x.goodgame" wide fullword

      $s1 = "/c ping localhost -n 3 > nul & del %s" ascii fullword
      $s2 = "C:\\Windows\\%s.png" wide

      $op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 }
      $op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e }
      $op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "bb2600e94092da119ee6acbbd047be43" or
         1 of ($x*) or
         2 of them
      ) 
      or 4 of them
}
rule Generic_Dropper  {
   meta:
      description = "Detects Dropper PDB string in file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
   strings:
      $s1 = "\\Release\\Dropper.pdb"
      $s2 = "\\Release\\dropper.pdb"
      $s3 = "\\Debug\\Dropper.pdb"
      $s4 = "\\Debug\\dropper.pdb"
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and 1 of them
}
rule ReflectiveLoader {

   meta:

      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"

      reference = "Internal Research"

      score = 70

      date = "2017-07-17"

      modified = "2021-03-15"

      author = "Florian Roth (Nextron Systems)"

      nodeepdive = 1

   strings:

      $x1 = "ReflectiveLoader" fullword ascii

      $x2 = "ReflectivLoader.dll" fullword ascii

      $x3 = "?ReflectiveLoader@@" ascii

      $x4 = "reflective_dll.x64.dll" fullword ascii

      $x5 = "reflective_dll.dll" fullword ascii



      $fp1 = "Sentinel Labs, Inc." wide

      $fp2 = "Panda Security, S.L." wide ascii

   condition:

      uint16(0) == 0x5a4d and (

            1 of ($x*) or

            pe.exports("ReflectiveLoader") or

            pe.exports("_ReflectiveLoader@4") or

            pe.exports("?ReflectiveLoader@@YGKPAX@Z")

         )

      and not 1 of ($fp*)

}
rule BadRabbit_Gen {
   meta:
      description = "Detects BadRabbit Ransomware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
      hash2 = "579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"
      hash3 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
   strings:
      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
      $x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
      $x3 = "C:\\Windows\\infpub.dat" fullword wide
      $x4 = "C:\\Windows\\cscc.dat" fullword wide

      $s1 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s2 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s3 = "\\\\.\\pipe\\%ws" fullword wide
      $s4 = "fsutil usn deletejournal /D %c:" fullword wide
      $s5 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s6 = "Files decryption completed" fullword wide
      $s7 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s8 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
      $s9 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s10 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 2 of them )
}

rule SUSP_PS1_Msdt_Execution_May22 {
   meta:
      description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
      author = "Nasreddine Bencherchali, Christian Burkard"
      date = "2022-05-31"
      modified = "2022-07-08"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 75
   strings:
      $a = "PCWDiagnostic" ascii wide fullword
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt" ascii wide

      $sb1 = "/af " ascii wide
      $sb2 = "-af " ascii wide
      $sb3 = "IT_BrowseForFile=" ascii wide

      $fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
      $fp2 = "FilesFullTrust" wide
   condition:
      filesize < 10MB
      and $a
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
}

rule PUA_Crypto_Mining_CommandLine_Indicators_Oct21 : SCRIPT {
   meta:
      description = "Detects command line parameters often used by crypto mining software"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.poolwatch.io/coin/monero"
      date = "2021-10-24"
      score = 65
   strings:
      $s01 = " --cpu-priority="
      $s02 = "--donate-level=0"
      $s03 = " -o pool."
      $s04 = " -o stratum+tcp://"
      $s05 = " --nicehash"
      $s06 = " --algo=rx/0 "

      $se1 = "LS1kb25hdGUtbGV2ZWw9"
      $se2 = "0tZG9uYXRlLWxldmVsP"
      $se3 = "tLWRvbmF0ZS1sZXZlbD"

      $se4 = "c3RyYXR1bSt0Y3A6Ly"
      $se5 = "N0cmF0dW0rdGNwOi8v"
      $se6 = "zdHJhdHVtK3RjcDovL"
      $se7 = "c3RyYXR1bSt1ZHA6Ly"
      $se8 = "N0cmF0dW0rdWRwOi8v"
      $se9 = "zdHJhdHVtK3VkcDovL"
   condition:
      filesize < 5000KB and 1 of them
}
rule WannaCry_Ransomware_Gen {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (based on rule by US CERT)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
      date = "2017-05-12"
      hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
   strings:
      $s1 = "__TREEID__PLACEHOLDER__" ascii
      $s2 = "__USERID__PLACEHOLDER__" ascii
      $s3 = "Windows for Workgroups 3.1a" fullword ascii
      $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $s5 = "LANMAN1.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Unknown_Malware_Sample_Jul17_2 {

   meta:

      description = "Detects unknown malware sample with pastebin RAW URL"

      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

      author = "Florian Roth (Nextron Systems)"

      reference = "https://goo.gl/iqH8CK"

      date = "2017-08-01"

      hash1 = "3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52"

   strings:

      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii

      $s2 = "https://pastebin.com/raw/" wide

      $s3 = "My.Computer" fullword ascii

      $s4 = "MyTemplate" fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )

}

rule SUSP_NET_NAME_ConfuserEx {
    meta:
        description = "Detects ConfuserEx packed file"
        reference = "https://github.com/yck1509/ConfuserEx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        score = 40
        date = "2021-01-22"
        modified = "2021-01-25"
    strings:
        $name = "ConfuserEx" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule MAL_Unknown_PWDumper_Apr18_3 {

   meta:

      description = "Detects sample from unknown sample set - IL origin"

      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

      author = "Florian Roth (Nextron Systems)"

      reference = "Internal Research"

      date = "2018-04-06"

      hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"

      hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"

   strings:

      $s1 = "loaderx86.dll" fullword ascii

      $s2 = "tcpsvcs.exe" fullword wide

      $s3 = "%Program Files, Common FOLDER%" fullword wide

      $s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide

      $s5 = "loaderx86" fullword ascii

      $s6 = "TNtDllHook$" fullword ascii

   condition:

      uint16(0) == 0x5a4d and filesize < 3000KB and all of them

}
rule CoinMiner_Strings : SCRIPT HIGHVOL {
   meta:
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
      modified = "2021-10-26"
      nodeepdive = 1
   strings:
      $sa1 = "stratum+tcp://" ascii
      $sa2 = "stratum+udp://" ascii
      $sb1 = "\"normalHashing\": true,"
   condition:
      filesize < 3000KB and 1 of them
}
rule WiltedTulip_ReflectiveLoader {
   meta:
      description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
      hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
      hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
      hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
      hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x4 = "Failed to impersonate token from %d (%u)" fullword ascii
      $x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or
      ( 2 of them ) or
      pe.exports("_ReflectiveLoader@4")
}
rule SUSP_ENV_Folder_Root_File_Jan23_1 : SCRIPT {
   meta:
      description = "Detects suspicious file path pointing to the root of a folder easily accessible via environment variables"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-11"
      score = 70
   strings:
      $xr1 = /%([Aa]pp[Dd]ata|APPDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
      $xr2 = /%([Pp]ublic|PUBLIC)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
      $xr4 = /%([Pp]rogram[Dd]ata|PROGRAMDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii

      $fp1 = "perl -MCPAN " ascii
      $fp2 = "CCleaner" ascii
   condition:
      filesize < 20MB and 1 of ($x*)
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}
rule WannaCry_Ransomware {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}
rule MAL_Ryuk_Ransomware {
   meta:
      description = "Detects strings known from Ryuk Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/"
      date = "2018-12-31"
      hash1 = "965884f19026913b2c57b8cd4a86455a61383de01dabb69c557f45bb848f6c26"
      hash2 = "b8fcd4a3902064907fb19e0da3ca7aed72a7e6d1f94d971d1ee7a4d3af6a800d"
   strings:
      $x1 = "/v \"svchos\" /f" fullword wide
      $x2 = "\\Documents and Settings\\Default User\\finish" wide
      $x3 = "\\users\\Public\\finish" wide
      $x4 = "lsaas.exe" fullword wide
      $x5 = "RyukReadMe.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "4a069c1abe5aca148d5a8fdabc26751e" or
         pe.imphash() == "dc5733c013378fa418d13773f5bfe6f1" or
         1 of them
      )
}
rule SUSP_PE_Discord_Attachment_Oct21_1 {
   meta:
      description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-10-12"
      score = 70
   strings:
      $x1 = "https://cdn.discordapp.com/attachments/" ascii wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 5000KB 
      and 1 of them
}
rule MAL_EXE_PrestigeRansomware {
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Prestige Ransomware"
		date = "2023-01-04"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		reference = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		DaysofYARA = "4/100"

	strings:
		$x_ransom_email = "Prestige.ranusomeware@Proton.me" wide
		$x_reg_ransom_note = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Public\\README\" /f" wide

		$ransom_message01 = "To decrypt all the data, you will need to purchase our decryption software." wide
		$ransom_message02 = "Contact us {}. In the letter, type your ID = {:X}." wide
		$ransom_message03 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide
		$ransom_message04 = "- Do not modify or rename encrypted files. You will lose them." wide
	condition:
		uint16(0) == 0x5A4D and 
			(1 of ($x*) or 2 of them or pe.imphash() == "a32bbc5df4195de63ea06feb46cd6b55")
}
rule MAL_EXE_LockBit_v2
{
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"

	strings:
		$s_ransom_note01 = "that is located in every encrypted folder." wide
		$s_ransom_note02 = "Would you like to earn millions of dollars?" wide

		$x_ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide

		$s_str1 = "Active:[ %d [                  Completed:[ %d" wide
		$x_str2 = "\\LockBit_Ransomware.hta" wide ascii
      $s_str2 = "Ransomware.hta" wide ascii
	condition:
		uint16(0) == 0x5A4D and ( 1 of ($x*) or 2 of them ) or 3 of them
}
rule BadRabbitInstaller {
	meta:
		Author = "Intezer Analyze"
		Reference = "https://apt-ecosystem.com"

	strings:
		$block_0 = { 5? 8B ?? 81 E? ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 ?? 89 ?? ?? 8B ?? ?? 5? 68 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 33 ?? 5? 5? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 5? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_1 = { 5? 8B ?? 83 ?? ?? 5? 5? 33 ?? 5? 5? 6A ?? 5? 6A ?? 68 ?? ?? ?? ?? 5? 89 ?? ?? FF 1? ?? ?? ?? ?? 8B ?? 83 ?? ?? 0F 84 }
		$block_2 = { 5? 8B ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 ?? 89 ?? ?? 5? 8B ?? ?? ?? ?? ?? 5? FF D? 8B ?? 85 ?? 0F 84 }
		$block_3 = { 8D ?? ?? ?? ?? ?? 5? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? FF D? 5? FF 1? ?? ?? ?? ?? 8B ?? 85 ?? 0F 84 }
		$block_4 = { 8D ?? ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? 5? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$block_5 = { 5? 2B ?? 8B ?? 5? 6A ?? FF 1? ?? ?? ?? ?? 5? FF 1? ?? ?? ?? ?? 8B ?? 85 ?? 0F 84 }
		$block_6 = { 8B ?? ?? ?? ?? ?? 8B ?? ?? 0F B7 ?? ?? ?? 03 ?? 8D ?? ?? ?? 0F B7 ?? ?? 85 ?? 7E }
	condition:
		hash.sha256(0, filesize) == "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da" or
		7 of them
}

rule CN_disclosed_20180208_c {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
      $x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
      $x3 = "www.upload.ee/image/" wide

      $s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s2 = "/Server.exe" fullword wide
      $s3 = "Executed As " fullword wide
      $s4 = "WmiPrvSE.exe" fullword wide
      $s5 = "Stub.exe" fullword ascii
      $s6 = "Download ERROR" fullword wide
      $s7 = "shutdown -r -t 00" fullword wide
      $s8 = "Select * From AntiVirusProduct" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
        1 of ($x*) or
        4 of them
      )
}

rule MAL_Ransomware_Wadhrama {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-07"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
   condition:
      uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}

rule INDICATOR_SUSPICIOUS_Stomped_PECompilation_Timestamp_InTheFuture {
    meta:
        author = "ditekSHen"
        description = "Detect executables with stomped PE compilation timestamp that is greater than local current time"
    condition:
        uint16(0) == 0x5a4d and pe.timestamp > time.now()
}

rule NotPetya_Ransomware_Jun17 {
   meta:
      description = "Detects new NotPetya Ransomware variant from June 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/h6iaGj"
      date = "2017-06-27"
      hash1 = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
      hash2 = "45ef8d53a5a2011e615f60b058768c44c74e5190fefd790ca95cf035d9e1d5e0"
      hash3 = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
   strings:
      $x1 = "Ooops, your important files are encrypted." fullword wide ascii
      $x2 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $x3 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide
      $x4 = "Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
      $x5 = "fsutil usn deletejournal /D %c:" fullword wide
      $x6 = "wevtutil cl Setup & wevtutil cl System" ascii
      /* ,#1 ..... rundll32.exe */
      $x7 = { 2C 00 23 00 31 00 20 00 00 00 00 00 00 00 00 00 72 00 75 00 6E
         00 64 00 6C 00 6C 00 33 00 32 00 2E 00 65 00 78 00 65 00 }

      $s1 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide
      $s4 = "\\\\.\\pipe\\%ws" fullword wide
      $s5 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide
      $s6 = "u%s \\\\%s -accepteula -s " fullword wide
      $s7 = "dllhost.dat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 3 of them )
}

rule MAL_Sednit_DelphiDownloader_Apr18_2 {
   meta:
      description = "Detects malware from Sednit Delphi Downloader report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
      date = "2018-04-24"
      hash1 = "53aef1e8b281a00dea41387a24664655986b58d61d39cfbde7e58d8c2ca3efda"
      hash2 = "657c83297cfcc5809e89098adf69c206df95aee77bfc1292898bbbe1c44c9dc4"
      hash3 = "5427ecf4fa37e05a4fbab8a31436f2e94283a832b4e60a3475182001b9739182"
      hash4 = "0458317893575568681c86b83e7f9c916540f0f58073b386d4419517c57dcb8f"
      hash5 = "72aa4905598c9fb5a1e3222ba8daa3efb52bbff09d89603ab0911e43e15201f3"
   strings:
      $s1 = "2D444F574E4C4F41445F53544152542D" ascii /* hex encoded string '-DOWNLOAD_START-' */
      $s2 = "55504C4F41445F414E445F455845435554455F46494C45" ascii /* hex encoded string 'UPLOAD_AND_EXECUTE_FILE' */
      $s3 = "4D6F7A696C6C612076352E31202857696E646F7773204E5420362E313B2072763A362E302E3129204765636B6F2F32303130303130312046697265666F782F36" ascii /* hex encoded string 'Mozilla v5.1 (Windows NT 6.1; rv:6.0.1) Gecko/20100101 Firefox/6.0.1' */
      $s4 = "41646F62654461696C79557064617465" ascii /* hex encoded string 'AdobeDailyUpdate' */
      $s5 = "53595354454D494E464F2026205441534B4C495354" ascii /* hex encoded string 'SYSTEMINFO & TASKLIST' */
      $s6 = "6373727376632E657865" ascii /* hex encoded string 'csrsvc.exe' */
      $s7 = "536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E" ascii /* hex encoded string 'Software\Microsoft\Windows\CurrentVersion\Run' */
      $s8 = "5C536F6674776172655C4D6963726F736F66745C57696E646F7773204E545C43757272656E7456657273696F6E" ascii /* hex encoded string '\Software\Microsoft\Windows NT\CurrentVersion' */
      $s9 = "5C536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E" ascii /* hex encoded string '\Software\Microsoft\Windows\CurrentVersion' */
      $s0 = "2D444F574E4C4F41445F53544152542D" ascii /* hex encoded string '-DOWNLOAD_START-' */

      $fp1 = "<key name=\"profiles\">"
   condition:
      filesize < 4000KB and 1 of ($s*) and not 1 of ($fp*)
}
rule APT_MAL_RANSOM_ViceSociety_Chily_Jan23_1 {
   meta:
      description = "Detects Chily or SunnyDay malware used by Vice Society"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12"
      score = 80
      hash1 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
   strings:
      $x1 = ".[Chily@Dr.Com]" ascii fullword

      $s1 = "localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a>" ascii fullword
      $s2 = "C:\\Users\\root\\Desktop" ascii fullword
      $s3 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" wide fullword
      $s4 = "cd %userprofile%\\documents\\" wide
      $s5 = "noise.bmp" wide fullword
      $s6 = " Execution time: %fms (1sec=1000ms)" ascii fullword
      $s7 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide fullword

      $op1 = { 4c 89 c5 89 ce 89 0d f5 41 02 00 4c 89 cf 44 8d 04 49 0f af f2 89 15 e9 41 02 00 44 89 c0 }
      $op2 = { 48 8b 03 48 89 d9 ff 50 10 84 c0 0f 94 c0 01 c0 48 83 c4 20 5b }
      $op3 = { 31 c0 47 8d 2c 00 45 85 f6 4d 63 ed 0f 8e ec 00 00 00 0f 1f 80 00 00 00 00 0f b7 94 44 40 0c 00 00 83 c1 01 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 500KB and (
         1 of ($x*)
         or 3 of them
      )
      or 4 of them
}

rule EXE_in_LNK
{
    meta:
        id = "3SSZmnnXU0l4qoc9wubdhN"
        fingerprint = "f169fab39da34f827cdff5ee022374f7c1cc0b171da9c2bb718d8fee9657d7a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".exe" ascii wide nocase
        $ = ".dll" ascii wide nocase
        $ = ".scr" ascii wide nocase
        $ = ".pif" ascii wide nocase
        $ = "This program" ascii wide nocase
        $ = "TVqQAA" ascii wide nocase

    condition:
        isLNK and any of them
}
rule MAL_RANSOM_Ragna_Locker_Apr20_1 {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
   strings:
      $x1 = "---RAGNAR SECRET---" ascii
      $xc1 = { 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 25 73 0D 0A
               25 73 0D 0A 0D 0A 25 73 0D 0A 00 00 2E 00 72 00
               61 00 67 00 6E 00 61 00 72 00 5F }
      $xc2 = { 00 2D 00 66 00 6F 00 72 00 63 00 65 00 00 00 00
               00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C
               00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00
               00 5C 00 6E 00 6F 00 74 00 65 00 70 00 61 00 64
               00 2E 00 65 00 78 00 65 00 }

      $s1 = "bootfont.bin" wide fullword

      $sc2 = { 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00
               00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E
               00 6F 00 6C 00 64 00 00 00 54 00 6F 00 72 00 20
               00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 }

      $op1 = { c7 85 58 ff ff ff 55 00 6b 00 c7 85 5c ff ff ff }
      $op2 = { 50 c7 85 7a ff ff ff 5c }
      $op3 = { 8b 75 08 8a 84 0d 20 ff ff ff ff 45 08 32 06 8b }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 4 of them
}
rule MAL_RANSOM_COVID19_Apr20_1 {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
   strings:
      $s1 = "/savekey.php" wide

      $op1 = { 3f ff ff ff ff ff 0b b4 }
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      2 of them
}
rule win_cryptolocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cryptolocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptolocker"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 753d 8b4510 833804 7417 32c0 0fb6c8 33c0 }
            // n = 7, score = 600
            //   753d                 | jne                 0x3f
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   833804               | cmp                 dword ptr [eax], 4
            //   7417                 | je                  0x19
            //   32c0                 | xor                 al, al
            //   0fb6c8               | movzx               ecx, al
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 85f6 7413 f6c301 7407 56 ff15???????? 56 }
            // n = 7, score = 600
            //   85f6                 | test                esi, esi
            //   7413                 | je                  0x15
            //   f6c301               | test                bl, 1
            //   7407                 | je                  9
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_2 = { 7517 53 50 ff35???????? ff15???????? 5b 5f }
            // n = 7, score = 600
            //   7517                 | jne                 0x19
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_3 = { 7415 8b4664 85c0 740e 50 ff15???????? }
            // n = 6, score = 600
            //   7415                 | je                  0x17
            //   8b4664               | mov                 eax, dword ptr [esi + 0x64]
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 5f 5d c20400 8b4710 8bd9 c7400c00000000 }
            // n = 6, score = 600
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   8bd9                 | mov                 ebx, ecx
            //   c7400c00000000       | mov                 dword ptr [eax + 0xc], 0

        $sequence_5 = { be08000000 85ff 7413 f6c301 7407 57 ff15???????? }
            // n = 7, score = 600
            //   be08000000           | mov                 esi, 8
            //   85ff                 | test                edi, edi
            //   7413                 | je                  0x15
            //   f6c301               | test                bl, 1
            //   7407                 | je                  9
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_6 = { 8bf1 57 8bfa 85f6 7452 8a06 }
            // n = 6, score = 600
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   8bfa                 | mov                 edi, edx
            //   85f6                 | test                esi, esi
            //   7452                 | je                  0x54
            //   8a06                 | mov                 al, byte ptr [esi]

        $sequence_7 = { 33c0 8bf2 85ff 7504 }
            // n = 4, score = 600
            //   33c0                 | xor                 eax, eax
            //   8bf2                 | mov                 esi, edx
            //   85ff                 | test                edi, edi
            //   7504                 | jne                 6

        $sequence_8 = { 8b4d10 f6c101 7556 8b450c 83f801 7405 83f802 }
            // n = 7, score = 600
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   f6c101               | test                cl, 1
            //   7556                 | jne                 0x58
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83f801               | cmp                 eax, 1
            //   7405                 | je                  7
            //   83f802               | cmp                 eax, 2

        $sequence_9 = { 5d c21800 8b451c f6400c10 7433 5f 5e }
            // n = 7, score = 600
            //   5d                   | pop                 ebp
            //   c21800               | ret                 0x18
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   f6400c10             | test                byte ptr [eax + 0xc], 0x10
            //   7433                 | je                  0x35
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize &lt; 778240
}
rule win_phobos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.phobos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { e8???????? 8345fc10 83c40c 83eb10 4f 75b9 eb61 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8345fc10             | add                 dword ptr [ebp - 4], 0x10
            //   83c40c               | add                 esp, 0xc
            //   83eb10               | sub                 ebx, 0x10
            //   4f                   | dec                 edi
            //   75b9                 | jne                 0xffffffbb
            //   eb61                 | jmp                 0x63

        $sequence_1 = { 5b 8b4508 8bce e8???????? 5f c9 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   c9                   | leave               

        $sequence_2 = { 83c41c 6a09 8945f0 e8???????? 8945ec }
            // n = 5, score = 100
            //   83c41c               | add                 esp, 0x1c
            //   6a09                 | push                9
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_3 = { 03c3 8d440004 50 57 e8???????? 83c40c eb12 }
            // n = 7, score = 100
            //   03c3                 | add                 eax, ebx
            //   8d440004             | lea                 eax, [eax + eax + 4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb12                 | jmp                 0x14

        $sequence_4 = { 83c602 6685c0 75e5 33c0 668902 83c202 33c0 }
            // n = 7, score = 100
            //   83c602               | add                 esi, 2
            //   6685c0               | test                ax, ax
            //   75e5                 | jne                 0xffffffe7
            //   33c0                 | xor                 eax, eax
            //   668902               | mov                 word ptr [edx], ax
            //   83c202               | add                 edx, 2
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 57 6a16 8944243c e8???????? 57 6a23 89442428 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   6a16                 | push                0x16
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   e8????????           |                     
            //   57                   | push                edi
            //   6a23                 | push                0x23
            //   89442428             | mov                 dword ptr [esp + 0x28], eax

        $sequence_6 = { e8???????? 59 50 ff7508 ff74241c ff15???????? 6aff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ff15????????         |                     
            //   6aff                 | push                -1

        $sequence_7 = { 8d45fc 50 ff75fc 53 6a02 ff75e4 ffd7 }
            // n = 7, score = 100
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ffd7                 | call                edi

        $sequence_8 = { 8bc7 5f 5d c3 55 8bec 68a4000000 }
            // n = 7, score = 100
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   68a4000000           | push                0xa4

        $sequence_9 = { 83c410 8945ec 3975fc 0f8434010000 8b45d4 3bc6 740a }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi
            //   0f8434010000         | je                  0x13a
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   3bc6                 | cmp                 eax, esi
            //   740a                 | je                  0xc

    condition:
        7 of them and filesize &lt; 139264
}
rule win_revil_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.revil."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 5d c3 55 8bec 81ec18010000 6a20 }
            // n = 6, score = 4600
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec18010000         | sub                 esp, 0x118
            //   6a20                 | push                0x20

        $sequence_1 = { 0bc3 c1ea08 0bca 8b5508 898a9c000000 8bce }
            // n = 6, score = 4600
            //   0bc3                 | or                  eax, ebx
            //   c1ea08               | shr                 edx, 8
            //   0bca                 | or                  ecx, edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   898a9c000000         | mov                 dword ptr [edx + 0x9c], ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_2 = { 334df4 23c7 3345e8 894b30 8bcb }
            // n = 5, score = 4600
            //   334df4               | xor                 ecx, dword ptr [ebp - 0xc]
            //   23c7                 | and                 eax, edi
            //   3345e8               | xor                 eax, dword ptr [ebp - 0x18]
            //   894b30               | mov                 dword ptr [ebx + 0x30], ecx
            //   8bcb                 | mov                 ecx, ebx

        $sequence_3 = { 83c704 e9???????? 8b75ec 8bc1 c1e812 0cf0 880437 }
            // n = 7, score = 4600
            //   83c704               | add                 edi, 4
            //   e9????????           |                     
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   8bc1                 | mov                 eax, ecx
            //   c1e812               | shr                 eax, 0x12
            //   0cf0                 | or                  al, 0xf0
            //   880437               | mov                 byte ptr [edi + esi], al

        $sequence_4 = { 8b4604 83e2df 8365ec00 8955f8 }
            // n = 4, score = 4600
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   83e2df               | and                 edx, 0xffffffdf
            //   8365ec00             | and                 dword ptr [ebp - 0x14], 0
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_5 = { 33c0 8bbe98000000 8bb69c000000 0facd308 c1e118 0bc3 c1ea08 }
            // n = 7, score = 4600
            //   33c0                 | xor                 eax, eax
            //   8bbe98000000         | mov                 edi, dword ptr [esi + 0x98]
            //   8bb69c000000         | mov                 esi, dword ptr [esi + 0x9c]
            //   0facd308             | shrd                ebx, edx, 8
            //   c1e118               | shl                 ecx, 0x18
            //   0bc3                 | or                  eax, ebx
            //   c1ea08               | shr                 edx, 8

        $sequence_6 = { 8bcf 31411c 8bc7 8bce 334840 }
            // n = 5, score = 4600
            //   8bcf                 | mov                 ecx, edi
            //   31411c               | xor                 dword ptr [ecx + 0x1c], eax
            //   8bc7                 | mov                 eax, edi
            //   8bce                 | mov                 ecx, esi
            //   334840               | xor                 ecx, dword ptr [eax + 0x40]

        $sequence_7 = { 8bc1 c1e812 0cf0 880437 8bc1 c1e80c }
            // n = 6, score = 4600
            //   8bc1                 | mov                 eax, ecx
            //   c1e812               | shr                 eax, 0x12
            //   0cf0                 | or                  al, 0xf0
            //   880437               | mov                 byte ptr [edi + esi], al
            //   8bc1                 | mov                 eax, ecx
            //   c1e80c               | shr                 eax, 0xc

        $sequence_8 = { 898a9c000000 8bce 898298000000 33c0 8b5a68 8b526c 0fa4fe08 }
            // n = 7, score = 4600
            //   898a9c000000         | mov                 dword ptr [edx + 0x9c], ecx
            //   8bce                 | mov                 ecx, esi
            //   898298000000         | mov                 dword ptr [edx + 0x98], eax
            //   33c0                 | xor                 eax, eax
            //   8b5a68               | mov                 ebx, dword ptr [edx + 0x68]
            //   8b526c               | mov                 edx, dword ptr [edx + 0x6c]
            //   0fa4fe08             | shld                esi, edi, 8

        $sequence_9 = { e9???????? 8b45e4 2bc3 83f803 0f8c20050000 43 895db8 }
            // n = 7, score = 4600
            //   e9????????           |                     
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   2bc3                 | sub                 eax, ebx
            //   83f803               | cmp                 eax, 3
            //   0f8c20050000         | jl                  0x526
            //   43                   | inc                 ebx
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx

    condition:
        7 of them and filesize < 155794432
}
rule win_dharma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.dharma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 83c408 85c0 0f8436010000 6a2e 8b55fc 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f8436010000         | je                  0x13c
            //   6a2e                 | push                0x2e
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx

        $sequence_1 = { e8???????? 83c408 8b4dec 8901 8b55fc c1e202 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c1e202               | shl                 edx, 2
            //   52                   | push                edx

        $sequence_2 = { 52 68ff7f0000 8b45e4 50 e8???????? 83c40c 85c0 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   68ff7f0000           | push                0x7fff
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax

        $sequence_3 = { 51 e8???????? 83c408 8945f0 8b55fc 83c201 52 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c201               | add                 edx, 1
            //   52                   | push                edx

        $sequence_4 = { e8???????? 83c408 8b45f0 50 e8???????? 83c404 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi

        $sequence_5 = { 8b45dc 3b4514 7c02 eb5e 8b4ddc 8b55ec 0fb7044a }
            // n = 7, score = 100
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   3b4514               | cmp                 eax, dword ptr [ebp + 0x14]
            //   7c02                 | jl                  4
            //   eb5e                 | jmp                 0x60
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   0fb7044a             | movzx               eax, word ptr [edx + ecx*2]

        $sequence_6 = { 2b4224 8d4c0002 51 8b5508 8b4224 8b4d08 8b5118 }
            // n = 7, score = 100
            //   2b4224               | sub                 eax, dword ptr [edx + 0x24]
            //   8d4c0002             | lea                 ecx, [eax + eax + 2]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4224               | mov                 eax, dword ptr [edx + 0x24]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5118               | mov                 edx, dword ptr [ecx + 0x18]

        $sequence_7 = { 894a08 eb18 8b45ec 8b4808 8b55ec 8b4204 8b0c88 }
            // n = 7, score = 100
            //   894a08               | mov                 dword ptr [edx + 8], ecx
            //   eb18                 | jmp                 0x1a
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   8b0c88               | mov                 ecx, dword ptr [eax + ecx*4]

        $sequence_8 = { 83c40c 8b4dfc 51 e8???????? 83c404 837df400 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0

        $sequence_9 = { 33148db8bf4000 8b45dc 335010 8955d8 8b4de8 c1e918 }
            // n = 6, score = 100
            //   33148db8bf4000       | xor                 edx, dword ptr [ecx*4 + 0x40bfb8]
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   335010               | xor                 edx, dword ptr [eax + 0x10]
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   c1e918               | shr                 ecx, 0x18

    condition:
        7 of them and filesize < 204800
}
rule win_medusalocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.medusalocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusalocker"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4d0c 8d1441 52 8b450c 50 8b4d08 e8???????? }
            // n = 7, score = 400
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8d1441               | lea                 edx, [ecx + eax*2]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_1 = { 7411 8b45f0 8b08 e8???????? 0fb6c8 85c9 7509 }
            // n = 7, score = 400
            //   7411                 | je                  0x13
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     
            //   0fb6c8               | movzx               ecx, al
            //   85c9                 | test                ecx, ecx
            //   7509                 | jne                 0xb

        $sequence_2 = { 8b450c 50 e8???????? 83c408 50 8d4de4 }
            // n = 6, score = 400
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_3 = { 8b55f4 d3ea 83e23f 81ca80000000 8b4520 8b08 8811 }
            // n = 7, score = 400
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   d3ea                 | shr                 edx, cl
            //   83e23f               | and                 edx, 0x3f
            //   81ca80000000         | or                  edx, 0x80
            //   8b4520               | mov                 eax, dword ptr [ebp + 0x20]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8811                 | mov                 byte ptr [ecx], dl

        $sequence_4 = { 8b4df8 894810 8b55f8 2b5508 83c201 52 8b450c }
            // n = 7, score = 400
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894810               | mov                 dword ptr [eax + 0x10], ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   2b5508               | sub                 edx, dword ptr [ebp + 8]
            //   83c201               | add                 edx, 1
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_5 = { e8???????? 83c408 50 e8???????? 8d4508 50 8b4df0 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_6 = { 83c104 e8???????? 8b45fc 8be5 5d c20400 55 }
            // n = 7, score = 400
            //   83c104               | add                 ecx, 4
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_7 = { 8d4dd8 e8???????? 83f810 730e 6a00 6a08 }
            // n = 6, score = 400
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   83f810               | cmp                 eax, 0x10
            //   730e                 | jae                 0x10
            //   6a00                 | push                0
            //   6a08                 | push                8

        $sequence_8 = { 8b8ddcfdffff 83c108 e8???????? c645fc01 8b8ddcfdffff 83c120 e8???????? }
            // n = 7, score = 400
            //   8b8ddcfdffff         | mov                 ecx, dword ptr [ebp - 0x224]
            //   83c108               | add                 ecx, 8
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8b8ddcfdffff         | mov                 ecx, dword ptr [ebp - 0x224]
            //   83c120               | add                 ecx, 0x20
            //   e8????????           |                     

        $sequence_9 = { 83c108 51 ff15???????? 85c0 7539 ff15???????? }
            // n = 6, score = 400
            //   83c108               | add                 ecx, 8
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7539                 | jne                 0x3b
            //   ff15????????         |                     

    condition:
        7 of them and filesize &lt; 1433600
}
rule win_troldesh_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.troldesh."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.troldesh"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b8698000000 8b00 8b00 50 56 e8???????? 59 }
            // n = 7, score = 600
            //   8b8698000000         | mov                 eax, dword ptr [esi + 0x98]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_1 = { ff75f4 e8???????? 83c40c 85c0 0f8456040000 8b4d10 57 }
            // n = 7, score = 600
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f8456040000         | je                  0x45c
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   57                   | push                edi

        $sequence_2 = { eb0c 80bd87fdffff04 7529 6a16 5f 3bfb 7e22 }
            // n = 7, score = 600
            //   eb0c                 | jmp                 0xe
            //   80bd87fdffff04       | cmp                 byte ptr [ebp - 0x279], 4
            //   7529                 | jne                 0x2b
            //   6a16                 | push                0x16
            //   5f                   | pop                 edi
            //   3bfb                 | cmp                 edi, ebx
            //   7e22                 | jle                 0x24

        $sequence_3 = { f6431407 7433 0fb65314 8b75f4 8bca c1ea03 83e107 }
            // n = 7, score = 600
            //   f6431407             | test                byte ptr [ebx + 0x14], 7
            //   7433                 | je                  0x35
            //   0fb65314             | movzx               edx, byte ptr [ebx + 0x14]
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   8bca                 | mov                 ecx, edx
            //   c1ea03               | shr                 edx, 3
            //   83e107               | and                 ecx, 7

        $sequence_4 = { e8???????? ff75fc 8d4dd8 53 e8???????? 8d45d8 50 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax

        $sequence_5 = { ff75fc e8???????? ff4d08 59 85f6 7443 68???????? }
            // n = 7, score = 600
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   85f6                 | test                esi, esi
            //   7443                 | je                  0x45
            //   68????????           |                     

        $sequence_6 = { eb18 f745d200400000 7405 6a03 58 eb0a 0fb745d2 }
            // n = 7, score = 600
            //   eb18                 | jmp                 0x1a
            //   f745d200400000       | test                dword ptr [ebp - 0x2e], 0x4000
            //   7405                 | je                  7
            //   6a03                 | push                3
            //   58                   | pop                 eax
            //   eb0a                 | jmp                 0xc
            //   0fb745d2             | movzx               eax, word ptr [ebp - 0x2e]

        $sequence_7 = { ff750c e8???????? 83c40c 8b4d08 56 8b750c e8???????? }
            // n = 7, score = 600
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   e8????????           |                     

        $sequence_8 = { ff75e8 e8???????? 83c40c e9???????? 399d28ffffff 740c ffb528ffffff }
            // n = 7, score = 600
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e9????????           |                     
            //   399d28ffffff         | cmp                 dword ptr [ebp - 0xd8], ebx
            //   740c                 | je                  0xe
            //   ffb528ffffff         | push                dword ptr [ebp - 0xd8]

        $sequence_9 = { ff15???????? 59 894620 3bc3 7505 eb90 895e20 }
            // n = 7, score = 600
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   894620               | mov                 dword ptr [esi + 0x20], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7505                 | jne                 7
            //   eb90                 | jmp                 0xffffff92
            //   895e20               | mov                 dword ptr [esi + 0x20], ebx

    condition:
        7 of them and filesize < 3915776
}
rule win_xorist_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.xorist."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xorist"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7504 b001 eb44 53 e8???????? 6a0c 59 }
            // n = 7, score = 100
            //   7504                 | jne                 6
            //   b001                 | mov                 al, 1
            //   eb44                 | jmp                 0x46
            //   53                   | push                ebx
            //   e8????????           |                     
            //   6a0c                 | push                0xc
            //   59                   | pop                 ecx

        $sequence_1 = { ff742408 e8???????? 84c0 7404 b001 eb10 ff742404 }
            // n = 7, score = 100
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb10                 | jmp                 0x12
            //   ff742404             | push                dword ptr [esp + 4]

        $sequence_2 = { 56 e8???????? 59 8d8da8fbffff 8d3446 83c602 8bc6 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d8da8fbffff         | lea                 ecx, [ebp - 0x458]
            //   8d3446               | lea                 esi, [esi + eax*2]
            //   83c602               | add                 esi, 2
            //   8bc6                 | mov                 eax, esi

        $sequence_3 = { 8bcf 898668060000 e8???????? 89864c060000 898644060000 85c0 0f8432010000 }
            // n = 7, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   898668060000         | mov                 dword ptr [esi + 0x668], eax
            //   e8????????           |                     
            //   89864c060000         | mov                 dword ptr [esi + 0x64c], eax
            //   898644060000         | mov                 dword ptr [esi + 0x644], eax
            //   85c0                 | test                eax, eax
            //   0f8432010000         | je                  0x138

        $sequence_4 = { 33748500 33749d00 8b442420 8bc8 d1c6 89749d00 8b5c2410 }
            // n = 7, score = 100
            //   33748500             | xor                 esi, dword ptr [ebp + eax*4]
            //   33749d00             | xor                 esi, dword ptr [ebp + ebx*4]
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8bc8                 | mov                 ecx, eax
            //   d1c6                 | rol                 esi, 1
            //   89749d00             | mov                 dword ptr [ebp + ebx*4], esi
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]

        $sequence_5 = { c20400 56 8b742408 ba00000400 3bf2 7328 8b09 }
            // n = 7, score = 100
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   ba00000400           | mov                 edx, 0x40000
            //   3bf2                 | cmp                 esi, edx
            //   7328                 | jae                 0x2a
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_6 = { 807f2c00 7527 8d4730 c6472c01 50 8d4718 50 }
            // n = 7, score = 100
            //   807f2c00             | cmp                 byte ptr [edi + 0x2c], 0
            //   7527                 | jne                 0x29
            //   8d4730               | lea                 eax, [edi + 0x30]
            //   c6472c01             | mov                 byte ptr [edi + 0x2c], 1
            //   50                   | push                eax
            //   8d4718               | lea                 eax, [edi + 0x18]
            //   50                   | push                eax

        $sequence_7 = { e8???????? 8bc6 50 e8???????? 59 8db5aafbffff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8db5aafbffff         | lea                 esi, [ebp - 0x456]

        $sequence_8 = { 3894306c060000 74f1 0fb64101 8b542414 03e8 8b5c241c 8d842424040000 }
            // n = 7, score = 100
            //   3894306c060000       | cmp                 byte ptr [eax + esi + 0x66c], dl
            //   74f1                 | je                  0xfffffff3
            //   0fb64101             | movzx               eax, byte ptr [ecx + 1]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   03e8                 | add                 ebp, eax
            //   8b5c241c             | mov                 ebx, dword ptr [esp + 0x1c]
            //   8d842424040000       | lea                 eax, [esp + 0x424]

        $sequence_9 = { 8b4c2428 83c40c 83c108 83c508 83eb08 894c241c 83ef01 }
            // n = 7, score = 100
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   83c40c               | add                 esp, 0xc
            //   83c108               | add                 ecx, 8
            //   83c508               | add                 ebp, 8
            //   83eb08               | sub                 ebx, 8
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   83ef01               | sub                 edi, 1

    condition:
        7 of them and filesize < 1402880
}
rule win_locky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.locky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.locky"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 8906 85c0 7505 e8???????? 8bc6 c9 c20800 }
            // n = 7, score = 2100
            //   8906                 | mov                 dword ptr [esi], eax
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   c9                   | leave               
            //   c20800               | ret                 8

        $sequence_1 = { 55 8bec 51 51 ff30 8b4508 }
            // n = 6, score = 2100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   ff30                 | push                dword ptr [eax]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { e8???????? 8d45d4 50 8bc6 c645fc03 e8???????? }
            // n = 6, score = 2100
            //   e8????????           |                     
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   8bc6                 | mov                 eax, esi
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   e8????????           |                     

        $sequence_3 = { 8d45d4 50 8b450c e8???????? 8b45d0 83c010 50 }
            // n = 7, score = 2100
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   83c010               | add                 eax, 0x10
            //   50                   | push                eax

        $sequence_4 = { 68???????? 8d45f8 50 e8???????? 3bc7 5f 7210 }
            // n = 7, score = 2100
            //   68????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   3bc7                 | cmp                 eax, edi
            //   5f                   | pop                 edi
            //   7210                 | jb                  0x12

        $sequence_5 = { 68???????? 8d45ec e9???????? c645fc03 3bf3 7407 }
            // n = 6, score = 2100
            //   68????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   e9????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   3bf3                 | cmp                 esi, ebx
            //   7407                 | je                  9

        $sequence_6 = { ff15???????? 85c0 747c 8d45f8 50 6a02 ff75fc }
            // n = 7, score = 2100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   747c                 | je                  0x7e
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a02                 | push                2
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_7 = { 74b2 53 8d45c4 50 8d45d4 50 }
            // n = 6, score = 2100
            //   74b2                 | je                  0xffffffb4
            //   53                   | push                ebx
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax

        $sequence_8 = { f7e1 03d3 5b c21000 e9???????? 8bff 55 }
            // n = 7, score = 1400
            //   f7e1                 | mul                 ecx
            //   03d3                 | add                 edx, ebx
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   e9????????           |                     
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp

        $sequence_9 = { 5e c21000 8bff 55 8bec 33c0 8b4d08 }
            // n = 7, score = 700
            //   5e                   | pop                 esi
            //   c21000               | ret                 0x10
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_10 = { 59 e9???????? 90 8d36 90 }
            // n = 5, score = 700
            //   59                   | pop                 ecx
            //   e9????????           |                     
            //   90                   | nop                 
            //   8d36                 | lea                 esi, [esi]
            //   90                   | nop                 

        $sequence_11 = { 66ab e9???????? 66ab 90 e9???????? 90 }
            // n = 6, score = 700
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   e9????????           |                     
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   90                   | nop                 
            //   e9????????           |                     
            //   90                   | nop                 

        $sequence_12 = { 58 e9???????? 8d36 90 }
            // n = 4, score = 700
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   8d36                 | lea                 esi, [esi]
            //   90                   | nop                 

        $sequence_13 = { 6a01 e9???????? 90 50 90 e9???????? }
            // n = 6, score = 700
            //   6a01                 | push                1
            //   e9????????           |                     
            //   90                   | nop                 
            //   50                   | push                eax
            //   90                   | nop                 
            //   e9????????           |                     

        $sequence_14 = { 58 e9???????? 8d6d00 e9???????? 90 }
            // n = 5, score = 700
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   8d6d00               | lea                 ebp, [ebp]
            //   e9????????           |                     
            //   90                   | nop                 

        $sequence_15 = { 59 90 e9???????? 8d3f e9???????? }
            // n = 5, score = 700
            //   59                   | pop                 ecx
            //   90                   | nop                 
            //   e9????????           |                     
            //   8d3f                 | lea                 edi, [edi]
            //   e9????????           |                     

        $sequence_16 = { 58 e9???????? 90 89d0 }
            // n = 4, score = 700
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   90                   | nop                 
            //   89d0                 | mov                 eax, edx

    condition:
        7 of them and filesize &lt; 1122304
}
rule win_emotet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.emotet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3c7a 7e0b 3c41 7c04 }
            // n = 4, score = 2900
            //   3c7a                 | mov                 byte ptr [ecx], 0x58
            //   7e0b                 | inc                 ecx
            //   3c41                 | jle                 0xd
            //   7c04                 | cmp                 al, 0x41

        $sequence_1 = { 3c41 7c04 3c5a 7e03 c60158 41 }
            // n = 6, score = 2900
            //   3c41                 | mov                 byte ptr [eax - 2], cl
            //   7c04                 | shr                 cx, 8
            //   3c5a                 | inc                 ecx
            //   7e03                 | mov                 byte ptr [eax - 1], cl
            //   c60158               | dec                 ebp
            //   41                   | cmp                 ebx, ecx

        $sequence_2 = { 8a01 3c30 7c04 3c39 7e13 3c61 }
            // n = 6, score = 2900
            //   8a01                 | lea                 eax, [eax + 4]
            //   3c30                 | inc                 ecx
            //   7c04                 | mov                 byte ptr [eax - 3], al
            //   3c39                 | inc                 ecx
            //   7e13                 | mov                 byte ptr [eax - 2], cl
            //   3c61                 | shr                 cx, 8

        $sequence_3 = { 3c39 7e13 3c61 7c04 3c7a 7e0b }
            // n = 6, score = 2900
            //   3c39                 | dec                 ebp
            //   7e13                 | lea                 eax, [eax + 4]
            //   3c61                 | inc                 ecx
            //   7c04                 | mov                 byte ptr [eax], cl
            //   3c7a                 | movzx               eax, cx
            //   7e0b                 | shr                 ecx, 0x10

        $sequence_4 = { 33c0 3903 5f 5e 0f95c0 5b 8be5 }
            // n = 7, score = 2400
            //   33c0                 | cmp                 al, 0x39
            //   3903                 | jle                 0x1f
            //   5f                   | cmp                 al, 0x61
            //   5e                   | jl                  0x14
            //   0f95c0               | cmp                 al, 0x7a
            //   5b                   | jle                 0x1f
            //   8be5                 | cmp                 al, 0x41

        $sequence_5 = { c60158 41 803900 75dd }
            // n = 4, score = 2400
            //   c60158               | cmp                 al, 0x5a
            //   41                   | jle                 0xd
            //   803900               | mov                 byte ptr [ecx], 0x58
            //   75dd                 | cmp                 al, 0x7a

        $sequence_6 = { 7708 0fb7c0 83c020 eb03 0fb7c0 69d23f000100 }
            // n = 6, score = 2300
            //   7708                 | jle                 0xd
            //   0fb7c0               | cmp                 al, 0x41
            //   83c020               | jl                  0xa
            //   eb03                 | cmp                 al, 0x5a
            //   0fb7c0               | cmp                 al, 0x39
            //   69d23f000100         | jle                 0x15

        $sequence_7 = { c1e910 8842fd 884afe c1e908 }
            // n = 4, score = 2100
            //   c1e910               | mov                 al, byte ptr [ecx]
            //   8842fd               | cmp                 al, 0x30
            //   884afe               | jl                  8
            //   c1e908               | cmp                 al, 0x39

        $sequence_8 = { 75f2 eb06 33c9 66894802 }
            // n = 4, score = 2100
            //   75f2                 | jl                  8
            //   eb06                 | cmp                 al, 0x5a
            //   33c9                 | jle                 0xb
            //   66894802             | mov                 byte ptr [ecx], 0x58

        $sequence_9 = { 8d5801 f6c30f 7406 83e3f0 83c310 }
            // n = 5, score = 2000
            //   8d5801               | cmp                 al, 0x7a
            //   f6c30f               | jle                 0x11
            //   7406                 | cmp                 al, 0x41
            //   83e3f0               | jl                  0xe
            //   83c310               | cmp                 al, 0x5a

        $sequence_10 = { 8945c8 8975d4 8955d8 e8???????? }
            // n = 4, score = 1900
            //   8945c8               | cmp                 eax, 0x7f
            //   8975d4               | jbe                 0xb
            //   8955d8               | shr                 eax, 7
            //   e8????????           |                     

        $sequence_11 = { 8b16 8945fc 8d45f8 6a04 }
            // n = 4, score = 1900
            //   8b16                 | shr                 eax, 7
            //   8945fc               | inc                 ecx
            //   8d45f8               | cmp                 eax, 0x7f
            //   6a04                 | ja                  0

        $sequence_12 = { 56 50 8b4774 03878c000000 50 ff15???????? 017758 }
            // n = 7, score = 1900
            //   56                   | mov                 ecx, dword ptr [ebp + 0xc]
            //   50                   | mov                 eax, edx
            //   8b4774               | mov                 edx, dword ptr [esi]
            //   03878c000000         | mov                 dword ptr [ebp - 4], eax
            //   50                   | lea                 eax, [ebp - 8]
            //   ff15????????         |                     
            //   017758               | push                4

        $sequence_13 = { ff15???????? 8b17 83c40c 8b4d0c 8bc2 }
            // n = 5, score = 1900
            //   ff15????????         |                     
            //   8b17                 | inc                 ecx
            //   83c40c               | cmp                 eax, 0x7f
            //   8b4d0c               | ja                  2
            //   8bc2                 | jbe                 0xb

        $sequence_14 = { 0faf4510 50 6a08 ff15???????? 50 }
            // n = 5, score = 1900
            //   0faf4510             | add                 ebx, 0x10
            //   50                   | lea                 ebx, [eax + 1]
            //   6a08                 | test                bl, 0xf
            //   ff15????????         |                     
            //   50                   | je                  0xb

        $sequence_15 = { 8b4508 894dcc 8d4dc8 8945c8 }
            // n = 4, score = 1900
            //   8b4508               | push                0
            //   894dcc               | push                -1
            //   8d4dc8               | push                eax
            //   8945c8               | push                ecx

        $sequence_16 = { c745fc04000000 50 8d45f8 81ca00000020 50 52 }
            // n = 6, score = 1800
            //   c745fc04000000       | cmp                 al, 0x7a
            //   50                   | jle                 0x11
            //   8d45f8               | cmp                 al, 0x41
            //   81ca00000020         | jl                  0xe
            //   50                   | jl                  6
            //   52                   | cmp                 al, 0x5a

        $sequence_17 = { 0fb7c1 c1e910 66c1e808 4d8d4004 418840fd 418848fe 66c1e908 }
            // n = 7, score = 1700
            //   0fb7c1               | shr                 ecx, 6
            //   c1e910               | mov                 dword ptr [ebp + 0x6f], ecx
            //   66c1e808             | dec                 eax
            //   4d8d4004             | add                 ecx, eax
            //   418840fd             | jmp                 0xa
            //   418848fe             | cmp                 byte ptr [ecx], 0
            //   66c1e908             | je                  0xf

        $sequence_18 = { 4c8bdc 49895b08 49896b10 49897318 49897b20 4156 4883ec70 }
            // n = 7, score = 1700
            //   4c8bdc               | dec                 eax
            //   49895b08             | dec                 ecx
            //   49896b10             | dec                 eax
            //   49897318             | cmp                 ecx, eax
            //   49897b20             | movzx               eax, cx
            //   4156                 | shr                 ecx, 0x10
            //   4883ec70             | shr                 ax, 8

        $sequence_19 = { d3e7 83f841 7208 83f85a }
            // n = 4, score = 1700
            //   d3e7                 | cmp                 al, 0x7a
            //   83f841               | jle                 0x13
            //   7208                 | cmp                 al, 0x41
            //   83f85a               | cmp                 al, 0x30

        $sequence_20 = { 418848fe 66c1e908 418848ff 4d3bd9 72cf }
            // n = 5, score = 1700
            //   418848fe             | inc                 ecx
            //   66c1e908             | mov                 byte ptr [eax - 2], cl
            //   418848ff             | shr                 cx, 8
            //   4d3bd9               | inc                 ecx
            //   72cf                 | mov                 byte ptr [eax - 1], cl

        $sequence_21 = { 483bd8 730b 488bcb e8???????? 488bd8 }
            // n = 5, score = 1700
            //   483bd8               | push                esi
            //   730b                 | dec                 eax
            //   488bcb               | sub                 esp, 0x70
            //   e8????????           |                     
            //   488bd8               | sub                 ecx, edx

        $sequence_22 = { 2bca d1e9 03ca c1e906 894d18 }
            // n = 5, score = 1700
            //   2bca                 | sub                 ecx, edx
            //   d1e9                 | shr                 ecx, 1
            //   03ca                 | add                 ecx, edx
            //   c1e906               | shr                 ecx, 6
            //   894d18               | mov                 dword ptr [ebp + 0x18], ecx

        $sequence_23 = { 418bd0 d3e2 418bcb d3e0 }
            // n = 4, score = 1700
            //   418bd0               | dec                 eax
            //   d3e2                 | mov                 dword ptr [eax + 8], ecx
            //   418bcb               | dec                 eax
            //   d3e0                 | mov                 dword ptr [eax + 0x10], edx

        $sequence_24 = { 48895010 4c894018 4c894820 c3 }
            // n = 4, score = 1700
            //   48895010             | shr                 ecx, 1
            //   4c894018             | add                 ecx, edx
            //   4c894820             | shr                 ecx, 6
            //   c3                   | mov                 dword ptr [esp + 0x30], ecx

        $sequence_25 = { 4803c8 eb08 803900 7408 48ffc9 483bc8 }
            // n = 6, score = 1700
            //   4803c8               | add                 ecx, edx
            //   eb08                 | shr                 ecx, 6
            //   803900               | mov                 dword ptr [ebp + 0x20], ecx
            //   7408                 | sub                 ecx, edx
            //   48ffc9               | shr                 ecx, 1
            //   483bc8               | add                 ecx, edx

        $sequence_26 = { c1e807 41 83f87f 77f7 }
            // n = 4, score = 1600
            //   c1e807               | mov                 dword ptr [ebx + 0x18], esi
            //   41                   | dec                 ecx
            //   83f87f               | mov                 dword ptr [ebx + 0x20], edi
            //   77f7                 | inc                 ecx

        $sequence_27 = { f7e1 b84fecc44e 2bca d1e9 }
            // n = 4, score = 1500
            //   f7e1                 | jl                  8
            //   b84fecc44e           | cmp                 al, 0x5a
            //   2bca                 | jle                 0xb
            //   d1e9                 | mov                 byte ptr [ecx], 0x58

        $sequence_28 = { 84c0 75f2 eb03 c60100 }
            // n = 4, score = 1500
            //   84c0                 | shr                 ecx, 1
            //   75f2                 | add                 ecx, edx
            //   eb03                 | shr                 ecx, 6
            //   c60100               | mov                 dword ptr [esp + 0x30], ecx

        $sequence_29 = { 7907 83c107 3bf7 72e8 }
            // n = 4, score = 1200
            //   7907                 | dec                 ecx
            //   83c107               | mov                 dword ptr [ebx + 0x18], esi
            //   3bf7                 | dec                 ecx
            //   72e8                 | mov                 dword ptr [ebx + 0x20], edi

        $sequence_30 = { 83c104 894e04 8b00 85c0 75f4 }
            // n = 5, score = 1200
            //   83c104               | jl                  0xc
            //   894e04               | cmp                 al, 0x5a
            //   8b00                 | jl                  6
            //   85c0                 | cmp                 al, 0x7a
            //   75f4                 | jle                 0xf

        $sequence_31 = { 52 52 52 68???????? 52 }
            // n = 5, score = 1100
            //   52                   | inc                 ecx
            //   52                   | push                esi
            //   52                   | dec                 eax
            //   68????????           |                     
            //   52                   | sub                 esp, 0x70

        $sequence_32 = { 56 57 6a1e 8d45e0 }
            // n = 4, score = 1100
            //   56                   | push                ebx
            //   57                   | push                0
            //   6a1e                 | lea                 eax, [ebp - 4]
            //   8d45e0               | push                ebx

        $sequence_33 = { 8d4dfc 51 6a00 6a01 8d55f8 }
            // n = 5, score = 1100
            //   8d4dfc               | push                esi
            //   51                   | mov                 esi, ecx
            //   6a00                 | mov                 ebx, 0x844cc300
            //   6a01                 | push                edi
            //   8d55f8               | push                0

        $sequence_34 = { 83ec48 53 56 57 6a44 }
            // n = 5, score = 1100
            //   83ec48               | cmp                 eax, 0x7f
            //   53                   | ja                  0
            //   56                   | push                0
            //   57                   | push                -1
            //   6a44                 | push                eax

        $sequence_35 = { 83f87f 760d 8d642400 c1e807 }
            // n = 4, score = 1000
            //   83f87f               | inc                 ecx
            //   760d                 | mov                 byte ptr [eax - 2], cl
            //   8d642400             | shr                 cx, 8
            //   c1e807               | inc                 ecx

        $sequence_36 = { b901000000 83f87f 7609 c1e807 41 }
            // n = 5, score = 900
            //   b901000000           | dec                 eax
            //   83f87f               | mov                 ebx, eax
            //   7609                 | dec                 eax
            //   c1e807               | mov                 dword ptr [eax + 0x10], edx
            //   41                   | dec                 esp

        $sequence_37 = { 6a00 6aff 50 51 ff15???????? }
            // n = 5, score = 800
            //   6a00                 | mov                 dword ptr [ebx + 0x20], edi
            //   6aff                 | inc                 ecx
            //   50                   | push                esi
            //   51                   | dec                 eax
            //   ff15????????         |                     

        $sequence_38 = { 50 6a00 6a01 6a00 ff15???????? a3???????? }
            // n = 6, score = 800
            //   50                   | mov                 dword ptr [ebx + 0x10], ebp
            //   6a00                 | dec                 ecx
            //   6a01                 | mov                 dword ptr [ebx + 0x18], esi
            //   6a00                 | dec                 ecx
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_39 = { 50 6a00 ff75fc 6800040000 }
            // n = 4, score = 600
            //   50                   | add                 eax, 0x20
            //   6a00                 | jmp                 0x11
            //   ff75fc               | movzx               eax, ax
            //   6800040000           | imul                edx, edx, 0x1003f

        $sequence_40 = { 56 68400000f0 6a18 33f6 56 }
            // n = 5, score = 600
            //   56                   | push                ebx
            //   68400000f0           | push                0
            //   6a18                 | push                0
            //   33f6                 | push                dword ptr [ebp + 8]
            //   56                   | push                ebx

        $sequence_41 = { ff75fc 6800040000 6a00 6a00 6a00 }
            // n = 5, score = 600
            //   ff75fc               | mov                 dword ptr [ebp - 0x14], ecx
            //   6800040000           | mov                 dword ptr [ebp - 0x18], edx
            //   6a00                 | mov                 dword ptr [ebp - 0x1c], esi
            //   6a00                 | mov                 ebp, esp
            //   6a00                 | push                esi

        $sequence_42 = { 53 56 8bf1 bb00c34c84 }
            // n = 4, score = 600
            //   53                   | push                ecx
            //   56                   | push                eax
            //   8bf1                 | push                0
            //   bb00c34c84           | push                1

        $sequence_43 = { 50 56 6800800000 6a6a }
            // n = 4, score = 600
            //   50                   | push                eax
            //   56                   | mov                 edi, dword ptr [ebp + 8]
            //   6800800000           | cmp                 esi, 0
            //   6a6a                 | mov                 dword ptr [ebp - 0x10], eax

        $sequence_44 = { 008b45fc33d2 00b871800780 00558b ec 8b450c 00558b ec }
            // n = 7, score = 500
            //   008b45fc33d2         | jle                 0xb
            //   00b871800780         | mov                 byte ptr [ecx], 0x58
            //   00558b               | jle                 0x15
            //   ec                   | cmp                 al, 0x61
            //   8b450c               | jl                  0xa
            //   00558b               | cmp                 al, 0x7a
            //   ec                   | jle                 0x15

        $sequence_45 = { 6a03 6a00 6a00 ff7508 53 50 }
            // n = 6, score = 500
            //   6a03                 | xor                 ecx, ecx
            //   6a00                 | mov                 edx, esp
            //   6a00                 | xor                 esi, esi
            //   ff7508               | mov                 dword ptr [edx + 0xc], esi
            //   53                   | mov                 edx, esp
            //   50                   | xor                 esi, esi

        $sequence_46 = { 83ec10 53 6a00 8d45fc }
            // n = 4, score = 500
            //   83ec10               | mov                 eax, dword ptr [esp + 0x44]
            //   53                   | cmp                 ecx, 0xfc0
            //   6a00                 | mov                 ecx, dword ptr [esp + 0x7c]
            //   8d45fc               | mov                 dword ptr [esp + 0x78], ebp

        $sequence_47 = { 51 ff75f8 50 6a03 6a30 }
            // n = 5, score = 500
            //   51                   | jmp                 0xd
            //   ff75f8               | movzx               eax, ax
            //   50                   | imul                edx, edx, 0x1003f
            //   6a03                 | lea                 ebx, [eax + 1]
            //   6a30                 | test                bl, 0xf

        $sequence_48 = { 01ca 89d6 83c60c 8b7df4 8b4c0f0c }
            // n = 5, score = 500
            //   01ca                 | cmp                 al, 0x41
            //   89d6                 | jl                  0x12
            //   83c60c               | cmp                 al, 0x30
            //   8b7df4               | jl                  8
            //   8b4c0f0c             | cmp                 al, 0x39

        $sequence_49 = { 01f1 8b7db4 11fa 8908 }
            // n = 4, score = 500
            //   01f1                 | cmp                 al, 0x61
            //   8b7db4               | jl                  0xc
            //   11fa                 | cmp                 al, 0x7a
            //   8908                 | jle                 0xd

        $sequence_50 = { 55 89e5 648b0d18000000 8b4130 83b8a400000006 0f92c2 80e201 }
            // n = 7, score = 500
            //   55                   | cmp                 al, 0x41
            //   89e5                 | jl                  0xa
            //   648b0d18000000       | cmp                 al, 0x5a
            //   8b4130               | jle                 0xd
            //   83b8a400000006       | mov                 byte ptr [ecx], 0x58
            //   0f92c2               | inc                 ecx
            //   80e201               | jl                  6

        $sequence_51 = { 8b7d08 83fe00 8945f0 894dec 8955e8 8975e4 }
            // n = 6, score = 500
            //   8b7d08               | cmp                 dword ptr [ebx], eax
            //   83fe00               | pop                 edi
            //   8945f0               | pop                 esi
            //   894dec               | setne               al
            //   8955e8               | pop                 ebx
            //   8975e4               | mov                 esp, ebp

        $sequence_52 = { 55 8bec 83ec08 56 57 8bf1 33ff }
            // n = 7, score = 500
            //   55                   | mov                 ebx, eax
            //   8bec                 | add                 ebx, 0x3c
            //   83ec08               | mov                 edx, esp
            //   56                   | xor                 esi, esi
            //   57                   | mov                 dword ptr [edx + 0xc], esi
            //   8bf1                 | mov                 dword ptr [edx + 8], esi
            //   33ff                 | xor                 ecx, ecx

        $sequence_53 = { 8bf1 bb00c34c84 57 33ff }
            // n = 4, score = 500
            //   8bf1                 | mov                 dword ptr [edx + 0xc], esi
            //   bb00c34c84           | mov                 dword ptr [edx + 8], esi
            //   57                   | mov                 dword ptr [edx + 4], esi
            //   33ff                 | xor                 esi, esi

        $sequence_54 = { 8b466c 5f 5e 5b 8be5 5d }
            // n = 6, score = 500
            //   8b466c               | push                0
            //   5f                   | push                0x104
            //   5e                   | push                edi
            //   5b                   | add                 esp, 0x14
            //   8be5                 | mov                 esi, dword ptr [eax + 0x20]
            //   5d                   | mov                 edi, dword ptr [eax + 0x40]

        $sequence_55 = { 56 8b4510 8b4d0c 8b5508 befbffffff c600e8 }
            // n = 6, score = 500
            //   56                   | cmp                 al, 0x5a
            //   8b4510               | jle                 0xd
            //   8b4d0c               | mov                 byte ptr [ecx], 0x58
            //   8b5508               | jl                  6
            //   befbffffff           | cmp                 al, 0x39
            //   c600e8               | jle                 0x17

        $sequence_56 = { 8b7020 8b7840 89c3 83c33c }
            // n = 4, score = 300
            //   8b7020               | cmp                 eax, 0x7f
            //   8b7840               | mov                 ecx, 1
            //   89c3                 | cmp                 eax, 0x7f
            //   83c33c               | jbe                 0x1c

        $sequence_57 = { 33d2 c605????????00 0fb6d8 e8???????? 0fb6c3 }
            // n = 5, score = 200
            //   33d2                 | cmp                 al, 0x41
            //   c605????????00       |                     
            //   0fb6d8               | jl                  0xe
            //   e8????????           |                     
            //   0fb6c3               | jl                  6

        $sequence_58 = { 89e2 31f6 89720c 897208 }
            // n = 4, score = 200
            //   89e2                 | shr                 eax, 7
            //   31f6                 | mov                 ecx, 1
            //   89720c               | cmp                 eax, 0x7f
            //   897208               | jbe                 0x29

        $sequence_59 = { 8bf8 e8???????? eb04 8b7c2430 }
            // n = 4, score = 200
            //   8bf8                 | cmp                 al, 0x41
            //   e8????????           |                     
            //   eb04                 | jl                  0xc
            //   8b7c2430             | cmp                 al, 0x5a

        $sequence_60 = { ff15???????? 83f803 7405 83f802 751e }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   83f803               | jl                  6
            //   7405                 | cmp                 al, 0x7a
            //   83f802               | jle                 0xf
            //   751e                 | cmp                 al, 0x41

        $sequence_61 = { 743e 8b5c2430 85db 741d }
            // n = 4, score = 200
            //   743e                 | pop                 esi
            //   8b5c2430             | setne               al
            //   85db                 | pop                 ebx
            //   741d                 | mov                 esp, ebp

        $sequence_62 = { 84c0 7519 33c9 0f1f4000 }
            // n = 4, score = 200
            //   84c0                 | cmp                 al, 0x61
            //   7519                 | jl                  6
            //   33c9                 | cmp                 al, 0x7a
            //   0f1f4000             | jle                 0x11

        $sequence_63 = { 8bfe e8???????? 8bd8 85db 746f 8b45f8 }
            // n = 6, score = 100
            //   8bfe                 | mov                 byte ptr [ecx], 0x58
            //   e8????????           |                     
            //   8bd8                 | inc                 ecx
            //   85db                 | cmp                 byte ptr [ecx], 0
            //   746f                 | jne                 0xffffffe8
            //   8b45f8               | jl                  6

        $sequence_64 = { 89e5 56 83e4f8 81ecc8000000 8b4508 f20f1005???????? }
            // n = 6, score = 100
            //   89e5                 | push                0
            //   56                   | push                -1
            //   83e4f8               | push                eax
            //   81ecc8000000         | push                ecx
            //   8b4508               | push                esi
            //   f20f1005????????     |                     

        $sequence_65 = { 740a ff15???????? 89442408 8b442444 890424 e8???????? 8b442444 }
            // n = 7, score = 100
            //   740a                 | test                al, al
            //   ff15????????         |                     
            //   89442408             | jne                 0xfffffff4
            //   8b442444             | jmp                 7
            //   890424               | mov                 byte ptr [ecx], 0
            //   e8????????           |                     
            //   8b442444             | shr                 eax, 7

        $sequence_66 = { ff15???????? 48 8d1585330000 48 8d4c2420 ff15???????? 48 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   48                   | cmp                 al, 0x5a
            //   8d1585330000         | jle                 7
            //   48                   | mov                 byte ptr [ecx], 0x58
            //   8d4c2420             | inc                 ecx
            //   ff15????????         |                     
            //   48                   | cmp                 byte ptr [ecx], 0

        $sequence_67 = { 890c24 c744240400000000 8954241c e8???????? 8d0dda30d800 }
            // n = 5, score = 100
            //   890c24               | cmp                 esi, edi
            //   c744240400000000     | jb                  0xffffffef
            //   8954241c             | push                edx
            //   e8????????           |                     
            //   8d0dda30d800         | push                edx

        $sequence_68 = { 48 8bc8 48 8bd8 e8???????? 48 8d154d1f0000 }
            // n = 7, score = 100
            //   48                   | jle                 5
            //   8bc8                 | mov                 byte ptr [ecx], 0x58
            //   48                   | inc                 ecx
            //   8bd8                 | cmp                 byte ptr [ecx], 0
            //   e8????????           |                     
            //   48                   | cmp                 al, 0x5a
            //   8d154d1f0000         | jle                 5

        $sequence_69 = { 498bca 4d8bc1 e8???????? 0fb6d8 4885ff }
            // n = 5, score = 100
            //   498bca               | test                eax, eax
            //   4d8bc1               | je                  0x51
            //   e8????????           |                     
            //   0fb6d8               | test                al, al
            //   4885ff               | jne                 0x1b

        $sequence_70 = { 488bf9 48894810 4c8d4008 488d4810 488d15e70f0000 }
            // n = 5, score = 100
            //   488bf9               | xor                 ecx, ecx
            //   48894810             | nop                 dword ptr [eax]
            //   4c8d4008             | xor                 edx, edx
            //   488d4810             | movzx               ebx, al
            //   488d15e70f0000       | movzx               eax, bl

        $sequence_71 = { 81f9c00f0000 8b4c247c 896c2478 89442474 89542470 }
            // n = 5, score = 100
            //   81f9c00f0000         | inc                 edx
            //   8b4c247c             | cmp                 eax, 0x7f
            //   896c2478             | ja                  0xfffffffd
            //   89442474             | jns                 9
            //   89542470             | add                 ecx, 7

        $sequence_72 = { 890424 c744240400040000 c744240802000000 8954240c 8b54246c }
            // n = 5, score = 100
            //   890424               | ja                  0xfffffffd
            //   c744240400040000     | shr                 eax, 7
            //   c744240802000000     | inc                 esi
            //   8954240c             | cmp                 eax, 0x7f
            //   8b54246c             | ja                  0xfffffffd

        $sequence_73 = { f20f10442450 8b442444 8b4838 8b5034 891424 894c2404 }
            // n = 6, score = 100
            //   f20f10442450         | mov                 edi, eax
            //   8b442444             | test                edi, edi
            //   8b4838               | je                  0x40
            //   8b5034               | shr                 eax, 7
            //   891424               | inc                 ecx
            //   894c2404             | cmp                 eax, 0x7f

        $sequence_74 = { e8???????? 4c8bf0 e8???????? 488d1547380000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   4c8bf0               | cmp                 eax, 2
            //   e8????????           |                     
            //   488d1547380000       | jne                 0x28

    condition:
        7 of them and filesize < 733184
}
rule win_lockbit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.lockbit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a02 ff750c ff7508 6a00 }
            // n = 4, score = 300
            //   6a02                 | push                2
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0

        $sequence_1 = { 8b733c 03f3 0fb77e06 8db6f8000000 6a00 }
            // n = 5, score = 300
            //   8b733c               | mov                 esi, dword ptr [ebx + 0x3c]
            //   03f3                 | add                 esi, ebx
            //   0fb77e06             | movzx               edi, word ptr [esi + 6]
            //   8db6f8000000         | lea                 esi, [esi + 0xf8]
            //   6a00                 | push                0

        $sequence_2 = { 57 e8???????? 85c0 7502 eb59 }
            // n = 5, score = 300
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   eb59                 | jmp                 0x5b

        $sequence_3 = { 894f08 89570c f745f800000002 740c 5f 5e b801000000 }
            // n = 7, score = 300
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   89570c               | mov                 dword ptr [edi + 0xc], edx
            //   f745f800000002       | test                dword ptr [ebp - 8], 0x2000000
            //   740c                 | je                  0xe
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b801000000           | mov                 eax, 1

        $sequence_4 = { 57 33c0 8d7df0 33c9 }
            // n = 4, score = 300
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8d7df0               | lea                 edi, [ebp - 0x10]
            //   33c9                 | xor                 ecx, ecx

        $sequence_5 = { 8d8550fdffff 50 6a00 ff15???????? }
            // n = 4, score = 300
            //   8d8550fdffff         | lea                 eax, [ebp - 0x2b0]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_6 = { 8bc8 d3ca 03d0 90 85c0 75d8 }
            // n = 6, score = 300
            //   8bc8                 | mov                 ecx, eax
            //   d3ca                 | ror                 edx, cl
            //   03d0                 | add                 edx, eax
            //   90                   | nop                 
            //   85c0                 | test                eax, eax
            //   75d8                 | jne                 0xffffffda

        $sequence_7 = { 6a00 6a00 6800000040 ff75d4 }
            // n = 4, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6800000040           | push                0x40000000
            //   ff75d4               | push                dword ptr [ebp - 0x2c]

        $sequence_8 = { 660f73f904 660fefc8 0f28c1 660f73f804 }
            // n = 4, score = 300
            //   660f73f904           | pslldq              xmm1, 4
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f28c1               | movaps              xmm0, xmm1
            //   660f73f804           | pslldq              xmm0, 4

        $sequence_9 = { 53 56 57 33c0 8b5d14 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]

        $sequence_10 = { 8b4e0c 03cb ff759c 8d858cfeffff 50 ff7610 51 }
            // n = 7, score = 300
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   03cb                 | add                 ecx, ebx
            //   ff759c               | push                dword ptr [ebp - 0x64]
            //   8d858cfeffff         | lea                 eax, [ebp - 0x174]
            //   50                   | push                eax
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   51                   | push                ecx

        $sequence_11 = { 8d7df0 33c9 53 0fa2 8bf3 }
            // n = 5, score = 300
            //   8d7df0               | lea                 edi, [ebp - 0x10]
            //   33c9                 | xor                 ecx, ecx
            //   53                   | push                ebx
            //   0fa2                 | cpuid               
            //   8bf3                 | mov                 esi, ebx

        $sequence_12 = { 8bf3 5b 8907 897704 894f08 89570c 837df001 }
            // n = 7, score = 300
            //   8bf3                 | mov                 esi, ebx
            //   5b                   | pop                 ebx
            //   8907                 | mov                 dword ptr [edi], eax
            //   897704               | mov                 dword ptr [edi + 4], esi
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   89570c               | mov                 dword ptr [edi + 0xc], edx
            //   837df001             | cmp                 dword ptr [ebp - 0x10], 1

        $sequence_13 = { 75e1 8bc2 5e 5a 59 5d }
            // n = 6, score = 300
            //   75e1                 | jne                 0xffffffe3
            //   8bc2                 | mov                 eax, edx
            //   5e                   | pop                 esi
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   5d                   | pop                 ebp

        $sequence_14 = { 720c 6683f839 7706 6683e830 eb05 e9???????? }
            // n = 6, score = 300
            //   720c                 | jb                  0xe
            //   6683f839             | cmp                 ax, 0x39
            //   7706                 | ja                  8
            //   6683e830             | sub                 ax, 0x30
            //   eb05                 | jmp                 7
            //   e9????????           |                     

        $sequence_15 = { 33d0 8bc1 c1e810 0fb6c0 c1e208 }
            // n = 5, score = 300
            //   33d0                 | xor                 edx, eax
            //   8bc1                 | mov                 eax, ecx
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   c1e208               | shl                 edx, 8

        $sequence_16 = { 50 8d45fc 50 ff75fc ff75f4 }
            // n = 5, score = 300
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_17 = { eb59 8d3c47 6a00 8d857cffffff }
            // n = 4, score = 300
            //   eb59                 | jmp                 0x5b
            //   8d3c47               | lea                 edi, [edi + eax*2]
            //   6a00                 | push                0
            //   8d857cffffff         | lea                 eax, [ebp - 0x84]

    condition:
        7 of them and filesize &lt; 2049024
}
rule win_azorult_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.azorult."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azorult"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $sequence_0 = { 33c0 55 68???????? 64ff30 648920 6a00 8d45f0 }
            // n = 7, score = 1200
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   6a00                 | push                0
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_1 = { 890424 85db 7420 54 e8???????? 50 ffd3 }
            // n = 7, score = 1200
            //   890424               | mov                 dword ptr [esp], eax
            //   85db                 | test                ebx, ebx
            //   7420                 | je                  0x22
            //   54                   | push                esp
            //   e8????????           |                     
            //   50                   | push                eax
            //   ffd3                 | call                ebx

        $sequence_2 = { 648910 e9???????? 8d45f4 50 }
            // n = 4, score = 1200
            //   648910               | mov                 dword ptr fs:[eax], edx
            //   e9????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_3 = { 50 e8???????? 83f8ff 0f95c3 33c0 }
            // n = 5, score = 1200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f95c3               | setne               bl
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 50 ba???????? 8d45e8 e8???????? 8d45e4 8b55f8 8a543201 }
            // n = 7, score = 1200
            //   50                   | push                eax
            //   ba????????           |                     
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   e8????????           |                     
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8a543201             | mov                 dl, byte ptr [edx + esi + 1]

        $sequence_5 = { 50 b9???????? ba???????? b801000080 e8???????? 8d85a4fdffff 50 }
            // n = 7, score = 1200
            //   50                   | push                eax
            //   b9????????           |                     
            //   ba????????           |                     
            //   b801000080           | mov                 eax, 0x80000001
            //   e8????????           |                     
            //   8d85a4fdffff         | lea                 eax, [ebp - 0x25c]
            //   50                   | push                eax

        $sequence_6 = { 68???????? ff75f8 68???????? 8d8574fdffff 8d95c8fdffff b904010000 e8???????? }
            // n = 7, score = 1200
            //   68????????           |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   68????????           |                     
            //   8d8574fdffff         | lea                 eax, [ebp - 0x28c]
            //   8d95c8fdffff         | lea                 edx, [ebp - 0x238]
            //   b904010000           | mov                 ecx, 0x104
            //   e8????????           |                     

        $sequence_7 = { 8b45fc 8a4418ff 04bf 2c1a 7206 04fa }
            // n = 6, score = 1200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8a4418ff             | mov                 al, byte ptr [eax + ebx - 1]
            //   04bf                 | add                 al, 0xbf
            //   2c1a                 | sub                 al, 0x1a
            //   7206                 | jb                  8
            //   04fa                 | add                 al, 0xfa

        $sequence_8 = { 7506 ff05???????? 56 e8???????? 59 }
            // n = 5, score = 900
            //   7506                 | jne                 8
            //   ff05????????         |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_9 = { e8???????? 59 8b45f4 40 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   40                   | inc                 eax

        $sequence_10 = { 50 e8???????? 59 8bd8 33c0 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bd8                 | mov                 ebx, eax
            //   33c0                 | xor                 eax, eax

        $sequence_11 = { 85db 7404 8bc3 eb07 }
            // n = 4, score = 500
            //   85db                 | test                ebx, ebx
            //   7404                 | je                  6
            //   8bc3                 | mov                 eax, ebx
            //   eb07                 | jmp                 9

        $sequence_12 = { 014f18 8b4714 85c0 0f854e010000 }
            // n = 4, score = 200
            //   014f18               | add                 dword ptr [edi + 0x18], ecx
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   85c0                 | test                eax, eax
            //   0f854e010000         | jne                 0x154

        $sequence_13 = { 014110 5f 5e 5b }
            // n = 4, score = 200
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_14 = { 011f 59 8bc3 c1e003 01866caf0100 }
            // n = 5, score = 200
            //   011f                 | add                 dword ptr [edi], ebx
            //   59                   | pop                 ecx
            //   8bc3                 | mov                 eax, ebx
            //   c1e003               | shl                 eax, 3
            //   01866caf0100         | add                 dword ptr [esi + 0x1af6c], eax

        $sequence_15 = { 01590c 8b45f0 014110 5f }
            // n = 4, score = 200
            //   01590c               | add                 dword ptr [ecx + 0xc], ebx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize &lt; 1753088
}rule win_gozi_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.gozi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 6a00 8d4da0 e8???????? 50 e8???????? }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { 55 f79bfe7ca80d a7 ad b710 2dc7ce5bbb d6 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   f79bfe7ca80d         | neg                 dword ptr [ebx + 0xda87cfe]
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   b710                 | mov                 bh, 0x10
            //   2dc7ce5bbb           | sub                 eax, 0xbb5bcec7
            //   d6                   | salc                

        $sequence_2 = { 57 56 56 68???????? ff75dc ff15???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   56                   | push                esi
            //   56                   | push                esi
            //   68????????           |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   ff15????????         |                     

        $sequence_3 = { 90 48 9e c1905ffb6daf6b }
            // n = 4, score = 100
            //   90                   | nop                 
            //   48                   | dec                 eax
            //   9e                   | sahf                
            //   c1905ffb6daf6b       | rcl                 dword ptr [eax - 0x509204a1], 0x6b

        $sequence_4 = { 8ee1 54 257c693a5c 48 fb }
            // n = 5, score = 100
            //   8ee1                 | mov                 fs, ecx
            //   54                   | push                esp
            //   257c693a5c           | and                 eax, 0x5c3a697c
            //   48                   | dec                 eax
            //   fb                   | sti                 

        $sequence_5 = { e9???????? 68b37418e6 ff35???????? e8???????? 894590 }
            // n = 5, score = 100
            //   e9????????           |                     
            //   68b37418e6           | push                0xe61874b3
            //   ff35????????         |                     
            //   e8????????           |                     
            //   894590               | mov                 dword ptr [ebp - 0x70], eax

        $sequence_6 = { 75e9 e8???????? 5b 5e c9 c20400 }
            // n = 6, score = 100
            //   75e9                 | jne                 0xffffffeb
            //   e8????????           |                     
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20400               | ret                 4

        $sequence_7 = { c0ee1e 0fca f6c172 8af4 c0eef6 }
            // n = 5, score = 100
            //   c0ee1e               | shr                 dh, 0x1e
            //   0fca                 | bswap               edx
            //   f6c172               | test                cl, 0x72
            //   8af4                 | mov                 dh, ah
            //   c0eef6               | shr                 dh, 0xf6

        $sequence_8 = { 10ba810b7f57 a4 8c6a38 55 f79bfe7ca80d a7 }
            // n = 6, score = 100
            //   10ba810b7f57         | adc                 byte ptr [edx + 0x577f0b81], bh
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   8c6a38               | mov                 word ptr [edx + 0x38], gs
            //   55                   | push                ebp
            //   f79bfe7ca80d         | neg                 dword ptr [ebx + 0xda87cfe]
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]

        $sequence_9 = { 6a29 ffb5d4f2ffff ff7508 ffd6 33c0 }
            // n = 5, score = 100
            //   6a29                 | push                0x29
            //   ffb5d4f2ffff         | push                dword ptr [ebp - 0xd2c]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { e8???????? 83c418 e9???????? 837d0803 751f }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   e9????????           |                     
            //   837d0803             | cmp                 dword ptr [ebp + 8], 3
            //   751f                 | jne                 0x21

        $sequence_11 = { 5c 3c32 7e02 19c1 a6 }
            // n = 5, score = 100
            //   5c                   | pop                 esp
            //   3c32                 | cmp                 al, 0x32
            //   7e02                 | jle                 4
            //   19c1                 | sbb                 ecx, eax
            //   a6                   | cmpsb               byte ptr [esi], byte ptr es:[edi]

        $sequence_12 = { 51 51 8365fc00 56 8b7508 807e1400 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   807e1400             | cmp                 byte ptr [esi + 0x14], 0

        $sequence_13 = { 751e ff45f4 25ff0f0000 0301 }
            // n = 4, score = 100
            //   751e                 | jne                 0x20
            //   ff45f4               | inc                 dword ptr [ebp - 0xc]
            //   25ff0f0000           | and                 eax, 0xfff
            //   0301                 | add                 eax, dword ptr [ecx]

        $sequence_14 = { ae 85729b 7a47 43 c571d5 }
            // n = 5, score = 100
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   85729b               | test                dword ptr [edx - 0x65], esi
            //   7a47                 | jp                  0x49
            //   43                   | inc                 ebx
            //   c571d5               | lds                 esi, ptr [ecx - 0x2b]

        $sequence_15 = { 8b4de4 83c104 894de4 8b55e0 83c202 8955e0 8b45fc }
            // n = 7, score = 100
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   83c104               | add                 ecx, 4
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   83c202               | add                 edx, 2
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_16 = { 0fb3ce feca 80ca32 69f1a6d150d3 }
            // n = 4, score = 100
            //   0fb3ce               | btr                 esi, ecx
            //   feca                 | dec                 dl
            //   80ca32               | or                  dl, 0x32
            //   69f1a6d150d3         | imul                esi, ecx, 0xd350d1a6

        $sequence_17 = { ff750c ff7508 e8???????? 683e010000 6a40 e8???????? }
            // n = 6, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   683e010000           | push                0x13e
            //   6a40                 | push                0x40
            //   e8????????           |                     

        $sequence_18 = { 8945f0 eb02 33d2 8b4f15 }
            // n = 4, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   eb02                 | jmp                 4
            //   33d2                 | xor                 edx, edx
            //   8b4f15               | mov                 ecx, dword ptr [edi + 0x15]

        $sequence_19 = { 12a502b346d1 41 b87e8da638 e022 3a56b9 036890 2b02 }
            // n = 7, score = 100
            //   12a502b346d1         | adc                 ah, byte ptr [ebp - 0x2eb94cfe]
            //   41                   | inc                 ecx
            //   b87e8da638           | mov                 eax, 0x38a68d7e
            //   e022                 | loopne              0x24
            //   3a56b9               | cmp                 dl, byte ptr [esi - 0x47]
            //   036890               | add                 ebp, dword ptr [eax - 0x70]
            //   2b02                 | sub                 eax, dword ptr [edx]

        $sequence_20 = { 8d4dbc 51 50 ff15???????? 8945dc 83f8ff 0f84b9feffff }
            // n = 7, score = 100
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   83f8ff               | cmp                 eax, -1
            //   0f84b9feffff         | je                  0xfffffebf

        $sequence_21 = { ff4508 837d080c 894dec 8d8c0de4feffff 8a11 8810 }
            // n = 6, score = 100
            //   ff4508               | inc                 dword ptr [ebp + 8]
            //   837d080c             | cmp                 dword ptr [ebp + 8], 0xc
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8d8c0de4feffff       | lea                 ecx, [ebp + ecx - 0x11c]
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   8810                 | mov                 byte ptr [eax], dl

        $sequence_22 = { 02738f 1da2c9dde2 f4 16 ee }
            // n = 5, score = 100
            //   02738f               | add                 dh, byte ptr [ebx - 0x71]
            //   1da2c9dde2           | sbb                 eax, 0xe2ddc9a2
            //   f4                   | hlt                 
            //   16                   | push                ss
            //   ee                   | out                 dx, al

        $sequence_23 = { 8dbdc0feffff f3ab 33f6 89b5b8feffff 8975fc 684fd1c15b ff35???????? }
            // n = 7, score = 100
            //   8dbdc0feffff         | lea                 edi, [ebp - 0x140]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   33f6                 | xor                 esi, esi
            //   89b5b8feffff         | mov                 dword ptr [ebp - 0x148], esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   684fd1c15b           | push                0x5bc1d14f
            //   ff35????????         |                     

        $sequence_24 = { 59 7e14 83c606 8d0c30 3b4d10 }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   7e14                 | jle                 0x16
            //   83c606               | add                 esi, 6
            //   8d0c30               | lea                 ecx, [eax + esi]
            //   3b4d10               | cmp                 ecx, dword ptr [ebp + 0x10]

        $sequence_25 = { 0f85c1000000 889d94fdffff 6a40 59 }
            // n = 4, score = 100
            //   0f85c1000000         | jne                 0xc7
            //   889d94fdffff         | mov                 byte ptr [ebp - 0x26c], bl
            //   6a40                 | push                0x40
            //   59                   | pop                 ecx

        $sequence_26 = { 57 894dec a1???????? 8b0d???????? 6a00 68f80a0000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   a1????????           |                     
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   68f80a0000           | push                0xaf8

        $sequence_27 = { 4e 0fbef4 0fbdf1 0fce 2af4 4e }
            // n = 6, score = 100
            //   4e                   | dec                 esi
            //   0fbef4               | movsx               esi, ah
            //   0fbdf1               | bsr                 esi, ecx
            //   0fce                 | bswap               esi
            //   2af4                 | sub                 dh, ah
            //   4e                   | dec                 esi

        $sequence_28 = { 894208 8d45dc 50 8b4d08 }
            // n = 4, score = 100
            //   894208               | mov                 dword ptr [edx + 8], eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_29 = { c3 8b4134 8b4924 8b00 }
            // n = 4, score = 100
            //   c3                   | ret                 
            //   8b4134               | mov                 eax, dword ptr [ecx + 0x34]
            //   8b4924               | mov                 ecx, dword ptr [ecx + 0x24]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_30 = { feca 0fca 80ca4a 0fb3ce }
            // n = 4, score = 100
            //   feca                 | dec                 dl
            //   0fca                 | bswap               edx
            //   80ca4a               | or                  dl, 0x4a
            //   0fb3ce               | btr                 esi, ecx

    condition:
        7 of them and filesize &lt; 568320
}rule win_revil_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.revil."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 5d c3 55 8bec 81ec18010000 6a20 }
            // n = 6, score = 4600
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec18010000         | sub                 esp, 0x118
            //   6a20                 | push                0x20

        $sequence_1 = { 0bc3 c1ea08 0bca 8b5508 898a9c000000 8bce }
            // n = 6, score = 4600
            //   0bc3                 | or                  eax, ebx
            //   c1ea08               | shr                 edx, 8
            //   0bca                 | or                  ecx, edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   898a9c000000         | mov                 dword ptr [edx + 0x9c], ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_2 = { 334df4 23c7 3345e8 894b30 8bcb }
            // n = 5, score = 4600
            //   334df4               | xor                 ecx, dword ptr [ebp - 0xc]
            //   23c7                 | and                 eax, edi
            //   3345e8               | xor                 eax, dword ptr [ebp - 0x18]
            //   894b30               | mov                 dword ptr [ebx + 0x30], ecx
            //   8bcb                 | mov                 ecx, ebx

        $sequence_3 = { 83c704 e9???????? 8b75ec 8bc1 c1e812 0cf0 880437 }
            // n = 7, score = 4600
            //   83c704               | add                 edi, 4
            //   e9????????           |                     
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   8bc1                 | mov                 eax, ecx
            //   c1e812               | shr                 eax, 0x12
            //   0cf0                 | or                  al, 0xf0
            //   880437               | mov                 byte ptr [edi + esi], al

        $sequence_4 = { 8b4604 83e2df 8365ec00 8955f8 }
            // n = 4, score = 4600
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   83e2df               | and                 edx, 0xffffffdf
            //   8365ec00             | and                 dword ptr [ebp - 0x14], 0
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_5 = { 33c0 8bbe98000000 8bb69c000000 0facd308 c1e118 0bc3 c1ea08 }
            // n = 7, score = 4600
            //   33c0                 | xor                 eax, eax
            //   8bbe98000000         | mov                 edi, dword ptr [esi + 0x98]
            //   8bb69c000000         | mov                 esi, dword ptr [esi + 0x9c]
            //   0facd308             | shrd                ebx, edx, 8
            //   c1e118               | shl                 ecx, 0x18
            //   0bc3                 | or                  eax, ebx
            //   c1ea08               | shr                 edx, 8

        $sequence_6 = { 8bcf 31411c 8bc7 8bce 334840 }
            // n = 5, score = 4600
            //   8bcf                 | mov                 ecx, edi
            //   31411c               | xor                 dword ptr [ecx + 0x1c], eax
            //   8bc7                 | mov                 eax, edi
            //   8bce                 | mov                 ecx, esi
            //   334840               | xor                 ecx, dword ptr [eax + 0x40]

        $sequence_7 = { 8bc1 c1e812 0cf0 880437 8bc1 c1e80c }
            // n = 6, score = 4600
            //   8bc1                 | mov                 eax, ecx
            //   c1e812               | shr                 eax, 0x12
            //   0cf0                 | or                  al, 0xf0
            //   880437               | mov                 byte ptr [edi + esi], al
            //   8bc1                 | mov                 eax, ecx
            //   c1e80c               | shr                 eax, 0xc

        $sequence_8 = { 898a9c000000 8bce 898298000000 33c0 8b5a68 8b526c 0fa4fe08 }
            // n = 7, score = 4600
            //   898a9c000000         | mov                 dword ptr [edx + 0x9c], ecx
            //   8bce                 | mov                 ecx, esi
            //   898298000000         | mov                 dword ptr [edx + 0x98], eax
            //   33c0                 | xor                 eax, eax
            //   8b5a68               | mov                 ebx, dword ptr [edx + 0x68]
            //   8b526c               | mov                 edx, dword ptr [edx + 0x6c]
            //   0fa4fe08             | shld                esi, edi, 8

        $sequence_9 = { e9???????? 8b45e4 2bc3 83f803 0f8c20050000 43 895db8 }
            // n = 7, score = 4600
            //   e9????????           |                     
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   2bc3                 | sub                 eax, ebx
            //   83f803               | cmp                 eax, 3
            //   0f8c20050000         | jl                  0x526
            //   43                   | inc                 ebx
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx

    condition:
        7 of them and filesize &lt; 155794432
}rule win_upatre_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.upatre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 50 8bf3 ac 84c0 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   8bf3                 | mov                 esi, ebx
            //   ac                   | lodsb               al, byte ptr [esi]
            //   84c0                 | test                al, al

        $sequence_1 = { 03c1 03c1 8945d0 03c1 }
            // n = 4, score = 200
            //   03c1                 | add                 eax, ecx
            //   03c1                 | add                 eax, ecx
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   03c1                 | add                 eax, ecx

        $sequence_2 = { 8b7594 33c9 66ad 6685c0 7404 }
            // n = 5, score = 200
            //   8b7594               | mov                 esi, dword ptr [ebp - 0x6c]
            //   33c9                 | xor                 ecx, ecx
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   7404                 | je                  6

        $sequence_3 = { ff5504 8acc c1e102 8b45f8 }
            // n = 4, score = 200
            //   ff5504               | call                dword ptr [ebp + 4]
            //   8acc                 | mov                 cl, ah
            //   c1e102               | shl                 ecx, 2
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_4 = { 8945e0 8d75e0 8b7dbc 897d9c b988130000 }
            // n = 5, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8d75e0               | lea                 esi, [ebp - 0x20]
            //   8b7dbc               | mov                 edi, dword ptr [ebp - 0x44]
            //   897d9c               | mov                 dword ptr [ebp - 0x64], edi
            //   b988130000           | mov                 ecx, 0x1388

        $sequence_5 = { 897db0 03f8 897d94 8bdf }
            // n = 4, score = 200
            //   897db0               | mov                 dword ptr [ebp - 0x50], edi
            //   03f8                 | add                 edi, eax
            //   897d94               | mov                 dword ptr [ebp - 0x6c], edi
            //   8bdf                 | mov                 ebx, edi

        $sequence_6 = { 66ab 33c0 66ab bbff0f0000 8b75f0 56 }
            // n = 6, score = 200
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   33c0                 | xor                 eax, eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   bbff0f0000           | mov                 ebx, 0xfff
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   56                   | push                esi

        $sequence_7 = { 57 8b0d???????? 890d???????? 51 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   8b0d????????         |                     
            //   890d????????         |                     
            //   51                   | push                ecx

        $sequence_8 = { 7e0e 0fb755ec 81ea007d0000 668955ec 668b450a 668945e8 0fb745ec }
            // n = 7, score = 100
            //   7e0e                 | jle                 0x10
            //   0fb755ec             | movzx               edx, word ptr [ebp - 0x14]
            //   81ea007d0000         | sub                 edx, 0x7d00
            //   668955ec             | mov                 word ptr [ebp - 0x14], dx
            //   668b450a             | mov                 ax, word ptr [ebp + 0xa]
            //   668945e8             | mov                 word ptr [ebp - 0x18], ax
            //   0fb745ec             | movzx               eax, word ptr [ebp - 0x14]

        $sequence_9 = { 51 e8???????? 83c40c eb2b 8b55f4 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb2b                 | jmp                 0x2d
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_10 = { 8945e0 837de000 0f8409010000 8b45e0 83c008 }
            // n = 5, score = 100
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   837de000             | cmp                 dword ptr [ebp - 0x20], 0
            //   0f8409010000         | je                  0x10f
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   83c008               | add                 eax, 8

        $sequence_11 = { 7437 8b4df8 83c108 894dfc 8b55fc }
            // n = 5, score = 100
            //   7437                 | je                  0x39
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c108               | add                 ecx, 8
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_12 = { eb11 8b55fc 52 8b450c 50 }
            // n = 5, score = 100
            //   eb11                 | jmp                 0x13
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax

        $sequence_13 = { 0fb7c0 83f805 7514 8b4df8 51 }
            // n = 5, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   83f805               | cmp                 eax, 5
            //   7514                 | jne                 0x16
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx

        $sequence_14 = { 0595809f87 3f e0eb 50 0dc21748db 60 }
            // n = 6, score = 100
            //   0595809f87           | add                 eax, 0x879f8095
            //   3f                   | aas                 
            //   e0eb                 | loopne              0xffffffed
            //   50                   | push                eax
            //   0dc21748db           | or                  eax, 0xdb4817c2
            //   60                   | pushal              

        $sequence_15 = { 8d55bc 52 8b45fc 2b45d8 }
            // n = 4, score = 100
            //   8d55bc               | lea                 edx, [ebp - 0x44]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2b45d8               | sub                 eax, dword ptr [ebp - 0x28]

    condition:
        7 of them and filesize &lt; 294912
}rule win_raccoon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.raccoon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.raccoon"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 8b4008 8b4004 83e810 eb2f 837e1000 7513 }
            // n = 6, score = 2400
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   83e810               | sub                 eax, 0x10
            //   eb2f                 | jmp                 0x31
            //   837e1000             | cmp                 dword ptr [esi + 0x10], 0
            //   7513                 | jne                 0x15

        $sequence_1 = { 740e 68???????? ff750c ffd3 }
            // n = 4, score = 2400
            //   740e                 | je                  0x10
            //   68????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffd3                 | call                ebx

        $sequence_2 = { 8d4dfc 51 8d4df8 c745ec02000000 }
            // n = 4, score = 2400
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   51                   | push                ecx
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   c745ec02000000       | mov                 dword ptr [ebp - 0x14], 2

        $sequence_3 = { ff15???????? 6a63 58 eb03 8b45fc 5f }
            // n = 6, score = 2400
            //   ff15????????         |                     
            //   6a63                 | push                0x63
            //   58                   | pop                 eax
            //   eb03                 | jmp                 5
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   5f                   | pop                 edi

        $sequence_4 = { 50 e8???????? ff7508 8bd8 53 895dfc e8???????? }
            // n = 7, score = 2400
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bd8                 | mov                 ebx, eax
            //   53                   | push                ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     

        $sequence_5 = { 83e810 eb31 837e1000 7513 6845110000 }
            // n = 5, score = 2400
            //   83e810               | sub                 eax, 0x10
            //   eb31                 | jmp                 0x33
            //   837e1000             | cmp                 dword ptr [esi + 0x10], 0
            //   7513                 | jne                 0x15
            //   6845110000           | push                0x1145

        $sequence_6 = { 8bd6 50 8bcf e8???????? 59 59 }
            // n = 6, score = 2400
            //   8bd6                 | mov                 edx, esi
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_7 = { 881e 895dfc 8bfa 837a1410 6afa }
            // n = 5, score = 2400
            //   881e                 | mov                 byte ptr [esi], bl
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8bfa                 | mov                 edi, edx
            //   837a1410             | cmp                 dword ptr [edx + 0x14], 0x10
            //   6afa                 | push                -6

        $sequence_8 = { 53 8d4dfc e8???????? 57 e8???????? 59 }
            // n = 6, score = 2400
            //   53                   | push                ebx
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   e8????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_9 = { 8945fc 56 8bf1 85c0 0f84a2000000 85f6 }
            // n = 6, score = 2400
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   85c0                 | test                eax, eax
            //   0f84a2000000         | je                  0xa8
            //   85f6                 | test                esi, esi

    condition:
        7 of them and filesize &lt; 1212416
}rule win_dharma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.dharma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"



    strings:
        $sequence_0 = { e8???????? 83c408 85c0 0f8436010000 6a2e 8b55fc 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f8436010000         | je                  0x13c
            //   6a2e                 | push                0x2e
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx

        $sequence_1 = { e8???????? 83c408 8b4dec 8901 8b55fc c1e202 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c1e202               | shl                 edx, 2
            //   52                   | push                edx

        $sequence_2 = { 52 68ff7f0000 8b45e4 50 e8???????? 83c40c 85c0 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   68ff7f0000           | push                0x7fff
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax

        $sequence_3 = { 51 e8???????? 83c408 8945f0 8b55fc 83c201 52 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c201               | add                 edx, 1
            //   52                   | push                edx

        $sequence_4 = { e8???????? 83c408 8b45f0 50 e8???????? 83c404 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi

        $sequence_5 = { 8b45dc 3b4514 7c02 eb5e 8b4ddc 8b55ec 0fb7044a }
            // n = 7, score = 100
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   3b4514               | cmp                 eax, dword ptr [ebp + 0x14]
            //   7c02                 | jl                  4
            //   eb5e                 | jmp                 0x60
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   0fb7044a             | movzx               eax, word ptr [edx + ecx*2]

        $sequence_6 = { 2b4224 8d4c0002 51 8b5508 8b4224 8b4d08 8b5118 }
            // n = 7, score = 100
            //   2b4224               | sub                 eax, dword ptr [edx + 0x24]
            //   8d4c0002             | lea                 ecx, [eax + eax + 2]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4224               | mov                 eax, dword ptr [edx + 0x24]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5118               | mov                 edx, dword ptr [ecx + 0x18]

        $sequence_7 = { 894a08 eb18 8b45ec 8b4808 8b55ec 8b4204 8b0c88 }
            // n = 7, score = 100
            //   894a08               | mov                 dword ptr [edx + 8], ecx
            //   eb18                 | jmp                 0x1a
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   8b0c88               | mov                 ecx, dword ptr [eax + ecx*4]

        $sequence_8 = { 83c40c 8b4dfc 51 e8???????? 83c404 837df400 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0

        $sequence_9 = { 33148db8bf4000 8b45dc 335010 8955d8 8b4de8 c1e918 }
            // n = 6, score = 100
            //   33148db8bf4000       | xor                 edx, dword ptr [ecx*4 + 0x40bfb8]
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   335010               | xor                 edx, dword ptr [eax + 0x10]
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   c1e918               | shr                 ecx, 0x18

    condition:
        7 of them and filesize &lt; 204800
}rule win_medusalocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.medusalocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusalocker"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4d0c 8d1441 52 8b450c 50 8b4d08 e8???????? }
            // n = 7, score = 400
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8d1441               | lea                 edx, [ecx + eax*2]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_1 = { 7411 8b45f0 8b08 e8???????? 0fb6c8 85c9 7509 }
            // n = 7, score = 400
            //   7411                 | je                  0x13
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     
            //   0fb6c8               | movzx               ecx, al
            //   85c9                 | test                ecx, ecx
            //   7509                 | jne                 0xb

        $sequence_2 = { 8b450c 50 e8???????? 83c408 50 8d4de4 }
            // n = 6, score = 400
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_3 = { 8b55f4 d3ea 83e23f 81ca80000000 8b4520 8b08 8811 }
            // n = 7, score = 400
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   d3ea                 | shr                 edx, cl
            //   83e23f               | and                 edx, 0x3f
            //   81ca80000000         | or                  edx, 0x80
            //   8b4520               | mov                 eax, dword ptr [ebp + 0x20]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8811                 | mov                 byte ptr [ecx], dl

        $sequence_4 = { 8b4df8 894810 8b55f8 2b5508 83c201 52 8b450c }
            // n = 7, score = 400
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894810               | mov                 dword ptr [eax + 0x10], ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   2b5508               | sub                 edx, dword ptr [ebp + 8]
            //   83c201               | add                 edx, 1
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_5 = { e8???????? 83c408 50 e8???????? 8d4508 50 8b4df0 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_6 = { 83c104 e8???????? 8b45fc 8be5 5d c20400 55 }
            // n = 7, score = 400
            //   83c104               | add                 ecx, 4
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_7 = { 8d4dd8 e8???????? 83f810 730e 6a00 6a08 }
            // n = 6, score = 400
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   83f810               | cmp                 eax, 0x10
            //   730e                 | jae                 0x10
            //   6a00                 | push                0
            //   6a08                 | push                8

        $sequence_8 = { 8b8ddcfdffff 83c108 e8???????? c645fc01 8b8ddcfdffff 83c120 e8???????? }
            // n = 7, score = 400
            //   8b8ddcfdffff         | mov                 ecx, dword ptr [ebp - 0x224]
            //   83c108               | add                 ecx, 8
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8b8ddcfdffff         | mov                 ecx, dword ptr [ebp - 0x224]
            //   83c120               | add                 ecx, 0x20
            //   e8????????           |                     

        $sequence_9 = { 83c108 51 ff15???????? 85c0 7539 ff15???????? }
            // n = 6, score = 400
            //   83c108               | add                 ecx, 8
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7539                 | jne                 0x3b
            //   ff15????????         |                     

    condition:
        7 of them and filesize &lt; 1433600
}rule win_virlock_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.virlock."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virlock"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 9c 26a040b8322b 05b0b970c9 ec 16 a8cb ec }
            // n = 7, score = 100
            //   9c                   | pushfd              
            //   26a040b8322b         | mov                 al, byte ptr es:[0x2b32b840]
            //   05b0b970c9           | add                 eax, 0xc970b9b0
            //   ec                   | in                  al, dx
            //   16                   | push                ss
            //   a8cb                 | test                al, 0xcb
            //   ec                   | in                  al, dx

        $sequence_1 = { 3222 a4 2a8b39874133 22a42ad72afdc1 3022 }
            // n = 5, score = 100
            //   3222                 | xor                 ah, byte ptr [edx]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   2a8b39874133         | sub                 cl, byte ptr [ebx + 0x33418739]
            //   22a42ad72afdc1       | and                 ah, byte ptr [edx + ebp - 0x3e02d529]
            //   3022                 | xor                 byte ptr [edx], ah

        $sequence_2 = { 8945f0 ff750c 68???????? e8???????? e8???????? ff15???????? 668945ee }
            // n = 7, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   ff15????????         |                     
            //   668945ee             | mov                 word ptr [ebp - 0x12], ax

        $sequence_3 = { 2d720d255d 15685f3c37 53 396249 2d4b2d5835 1e 6e }
            // n = 7, score = 100
            //   2d720d255d           | sub                 eax, 0x5d250d72
            //   15685f3c37           | adc                 eax, 0x373c5f68
            //   53                   | push                ebx
            //   396249               | cmp                 dword ptr [edx + 0x49], esp
            //   2d4b2d5835           | sub                 eax, 0x35582d4b
            //   1e                   | push                ds
            //   6e                   | outsb               dx, byte ptr [esi]

        $sequence_4 = { e8???????? 6a00 68???????? e8???????? e8???????? ff15???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   ff15????????         |                     

        $sequence_5 = { 48 58 52 41 }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   58                   | pop                 eax
            //   52                   | push                edx
            //   41                   | inc                 ecx

        $sequence_6 = { 47 50 42 4a 49 56 42 }
            // n = 7, score = 100
            //   47                   | inc                 edi
            //   50                   | push                eax
            //   42                   | inc                 edx
            //   4a                   | dec                 edx
            //   49                   | dec                 ecx
            //   56                   | push                esi
            //   42                   | inc                 edx

        $sequence_7 = { 60 16 16 4c 6b1617 4c 6a16 }
            // n = 7, score = 100
            //   60                   | pushal              
            //   16                   | push                ss
            //   16                   | push                ss
            //   4c                   | dec                 esp
            //   6b1617               | imul                edx, dword ptr [esi], 0x17
            //   4c                   | dec                 esp
            //   6a16                 | push                0x16

        $sequence_8 = { 83f193 697587936c3586 e669 4b b395 59 }
            // n = 6, score = 100
            //   83f193               | xor                 ecx, 0xffffff93
            //   697587936c3586       | imul                esi, dword ptr [ebp - 0x79], 0x86356c93
            //   e669                 | out                 0x69, al
            //   4b                   | dec                 ebx
            //   b395                 | mov                 bl, 0x95
            //   59                   | pop                 ecx

        $sequence_9 = { 4d 45 4b 4d 46 58 4f }
            // n = 7, score = 100
            //   4d                   | dec                 ebp
            //   45                   | inc                 ebp
            //   4b                   | dec                 ebx
            //   4d                   | dec                 ebp
            //   46                   | inc                 esi
            //   58                   | pop                 eax
            //   4f                   | dec                 edi

    condition:
        7 of them and filesize &lt; 4202496
}rule win_troldesh_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.troldesh."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.troldesh"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b8698000000 8b00 8b00 50 56 e8???????? 59 }
            // n = 7, score = 600
            //   8b8698000000         | mov                 eax, dword ptr [esi + 0x98]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_1 = { ff75f4 e8???????? 83c40c 85c0 0f8456040000 8b4d10 57 }
            // n = 7, score = 600
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f8456040000         | je                  0x45c
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   57                   | push                edi

        $sequence_2 = { eb0c 80bd87fdffff04 7529 6a16 5f 3bfb 7e22 }
            // n = 7, score = 600
            //   eb0c                 | jmp                 0xe
            //   80bd87fdffff04       | cmp                 byte ptr [ebp - 0x279], 4
            //   7529                 | jne                 0x2b
            //   6a16                 | push                0x16
            //   5f                   | pop                 edi
            //   3bfb                 | cmp                 edi, ebx
            //   7e22                 | jle                 0x24

        $sequence_3 = { f6431407 7433 0fb65314 8b75f4 8bca c1ea03 83e107 }
            // n = 7, score = 600
            //   f6431407             | test                byte ptr [ebx + 0x14], 7
            //   7433                 | je                  0x35
            //   0fb65314             | movzx               edx, byte ptr [ebx + 0x14]
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   8bca                 | mov                 ecx, edx
            //   c1ea03               | shr                 edx, 3
            //   83e107               | and                 ecx, 7

        $sequence_4 = { e8???????? ff75fc 8d4dd8 53 e8???????? 8d45d8 50 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax

        $sequence_5 = { ff75fc e8???????? ff4d08 59 85f6 7443 68???????? }
            // n = 7, score = 600
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   85f6                 | test                esi, esi
            //   7443                 | je                  0x45
            //   68????????           |                     

        $sequence_6 = { eb18 f745d200400000 7405 6a03 58 eb0a 0fb745d2 }
            // n = 7, score = 600
            //   eb18                 | jmp                 0x1a
            //   f745d200400000       | test                dword ptr [ebp - 0x2e], 0x4000
            //   7405                 | je                  7
            //   6a03                 | push                3
            //   58                   | pop                 eax
            //   eb0a                 | jmp                 0xc
            //   0fb745d2             | movzx               eax, word ptr [ebp - 0x2e]

        $sequence_7 = { ff750c e8???????? 83c40c 8b4d08 56 8b750c e8???????? }
            // n = 7, score = 600
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   e8????????           |                     

        $sequence_8 = { ff75e8 e8???????? 83c40c e9???????? 399d28ffffff 740c ffb528ffffff }
            // n = 7, score = 600
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e9????????           |                     
            //   399d28ffffff         | cmp                 dword ptr [ebp - 0xd8], ebx
            //   740c                 | je                  0xe
            //   ffb528ffffff         | push                dword ptr [ebp - 0xd8]

        $sequence_9 = { ff15???????? 59 894620 3bc3 7505 eb90 895e20 }
            // n = 7, score = 600
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   894620               | mov                 dword ptr [esi + 0x20], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7505                 | jne                 7
            //   eb90                 | jmp                 0xffffff92
            //   895e20               | mov                 dword ptr [esi + 0x20], ebx

    condition:
        7 of them and filesize &lt; 3915776
}rule win_deathransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.deathransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 0f43ce 3b55fc 8b75f0 1bc0 c1eb10 f7d8 }
            // n = 6, score = 100
            //   0f43ce               | cmovae              ecx, esi
            //   3b55fc               | cmp                 edx, dword ptr [ebp - 4]
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   1bc0                 | sbb                 eax, eax
            //   c1eb10               | shr                 ebx, 0x10
            //   f7d8                 | neg                 eax

        $sequence_1 = { 0bf0 8b55e8 8975fc 8bc3 014dfc 81c2a706dc9b 8b75e4 }
            // n = 7, score = 100
            //   0bf0                 | or                  esi, eax
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   8bc3                 | mov                 eax, ebx
            //   014dfc               | add                 dword ptr [ebp - 4], ecx
            //   81c2a706dc9b         | add                 edx, 0x9bdc06a7
            //   8b75e4               | mov                 esi, dword ptr [ebp - 0x1c]

        $sequence_2 = { 2345e8 0b5de8 235df4 0bd8 895df0 014df0 8b4d94 }
            // n = 7, score = 100
            //   2345e8               | and                 eax, dword ptr [ebp - 0x18]
            //   0b5de8               | or                  ebx, dword ptr [ebp - 0x18]
            //   235df4               | and                 ebx, dword ptr [ebp - 0xc]
            //   0bd8                 | or                  ebx, eax
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   014df0               | add                 dword ptr [ebp - 0x10], ecx
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]

        $sequence_3 = { 894df8 85d2 0f8556ffffff 5f 5e 8bc1 5b }
            // n = 7, score = 100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   85d2                 | test                edx, edx
            //   0f8556ffffff         | jne                 0xffffff5c
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8bc1                 | mov                 eax, ecx
            //   5b                   | pop                 ebx

        $sequence_4 = { 6a08 ff15???????? 50 ff15???????? 8bf0 897508 85f6 }
            // n = 7, score = 100
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   85f6                 | test                esi, esi

        $sequence_5 = { 0b7de4 237ddc 0bf8 897de0 }
            // n = 4, score = 100
            //   0b7de4               | or                  edi, dword ptr [ebp - 0x1c]
            //   237ddc               | and                 edi, dword ptr [ebp - 0x24]
            //   0bf8                 | or                  edi, eax
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi

        $sequence_6 = { 8d8e00000100 0345fc 03f8 3bd3 8b5df8 0f43ce 3b7dfc }
            // n = 7, score = 100
            //   8d8e00000100         | lea                 ecx, [esi + 0x10000]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   03f8                 | add                 edi, eax
            //   3bd3                 | cmp                 edx, ebx
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   0f43ce               | cmovae              ecx, esi
            //   3b7dfc               | cmp                 edi, dword ptr [ebp - 4]

        $sequence_7 = { 85f6 741e 8b4df8 83c128 034dfc 85f6 }
            // n = 6, score = 100
            //   85f6                 | test                esi, esi
            //   741e                 | je                  0x20
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c128               | add                 ecx, 0x28
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   85f6                 | test                esi, esi

        $sequence_8 = { 0f43c8 8bc6 8b75f8 c1e810 03c8 03f1 3bf1 }
            // n = 7, score = 100
            //   0f43c8               | cmovae              ecx, eax
            //   8bc6                 | mov                 eax, esi
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   c1e810               | shr                 eax, 0x10
            //   03c8                 | add                 ecx, eax
            //   03f1                 | add                 esi, ecx
            //   3bf1                 | cmp                 esi, ecx

        $sequence_9 = { 6a01 6a00 68???????? ffd6 85c0 0f881b020000 68???????? }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f881b020000         | js                  0x221
            //   68????????           |                     

    condition:
        7 of them and filesize &lt; 133120
}rule win_mokes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.mokes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mokes"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f20f1194248c000000 f30f1084248c000000 f30f1144243c f30f10842490000000 f30f11442440 0f57c0 660f11842484010000 }
            // n = 7, score = 400
            //   f20f1194248c000000     | movsd    qword ptr [esp + 0x8c], xmm2
            //   f30f1084248c000000     | movss    xmm0, dword ptr [esp + 0x8c]
            //   f30f1144243c         | movss               dword ptr [esp + 0x3c], xmm0
            //   f30f10842490000000     | movss    xmm0, dword ptr [esp + 0x90]
            //   f30f11442440         | movss               dword ptr [esp + 0x40], xmm0
            //   0f57c0               | xorps               xmm0, xmm0
            //   660f11842484010000     | movupd    xmmword ptr [esp + 0x184], xmm0

        $sequence_1 = { ff742440 e8???????? 8b44240c 8b7c241c 8bcf 8b7024 03742478 }
            // n = 7, score = 400
            //   ff742440             | push                dword ptr [esp + 0x40]
            //   e8????????           |                     
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   8bcf                 | mov                 ecx, edi
            //   8b7024               | mov                 esi, dword ptr [eax + 0x24]
            //   03742478             | add                 esi, dword ptr [esp + 0x78]

        $sequence_2 = { ffd0 eb0d 8b4718 85c0 7409 50 e8???????? }
            // n = 7, score = 400
            //   ffd0                 | call                eax
            //   eb0d                 | jmp                 0xf
            //   8b4718               | mov                 eax, dword ptr [edi + 0x18]
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { e8???????? 84c0 740b f6432802 c644245400 7405 c644245401 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   740b                 | je                  0xd
            //   f6432802             | test                byte ptr [ebx + 0x28], 2
            //   c644245400           | mov                 byte ptr [esp + 0x54], 0
            //   7405                 | je                  7
            //   c644245401           | mov                 byte ptr [esp + 0x54], 1

        $sequence_4 = { f20f11a424a0000000 8d8c2490000000 f20f1000 f20f11442450 f20f118424a8000000 e8???????? 84c0 }
            // n = 7, score = 400
            //   f20f11a424a0000000     | movsd    qword ptr [esp + 0xa0], xmm4
            //   8d8c2490000000       | lea                 ecx, [esp + 0x90]
            //   f20f1000             | movsd               xmm0, qword ptr [eax]
            //   f20f11442450         | movsd               qword ptr [esp + 0x50], xmm0
            //   f20f118424a8000000     | movsd    qword ptr [esp + 0xa8], xmm0
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_5 = { ff742428 8d8c24e4000000 50 8d442470 50 e8???????? 83c414 }
            // n = 7, score = 400
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   8d8c24e4000000       | lea                 ecx, [esp + 0xe4]
            //   50                   | push                eax
            //   8d442470             | lea                 eax, [esp + 0x70]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { f00fc110 750a 85c9 7406 51 e8???????? 6a05 }
            // n = 7, score = 400
            //   f00fc110             | lock xadd           dword ptr [eax], edx
            //   750a                 | jne                 0xc
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a05                 | push                5

        $sequence_7 = { f781fc00000000000100 750a c7878c00000000000000 8b9fc4000000 b827000000 6689442418 b9fdff0000 }
            // n = 7, score = 400
            //   f781fc00000000000100     | test    dword ptr [ecx + 0xfc], 0x10000
            //   750a                 | jne                 0xc
            //   c7878c00000000000000     | mov    dword ptr [edi + 0x8c], 0
            //   8b9fc4000000         | mov                 ebx, dword ptr [edi + 0xc4]
            //   b827000000           | mov                 eax, 0x27
            //   6689442418           | mov                 word ptr [esp + 0x18], ax
            //   b9fdff0000           | mov                 ecx, 0xfffd

        $sequence_8 = { ff750c ff7508 ff74241c 6a07 51 52 50 }
            // n = 7, score = 400
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   6a07                 | push                7
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_9 = { ff5274 83cfff 8bce 85c0 740c 8d442414 50 }
            // n = 7, score = 400
            //   ff5274               | call                dword ptr [edx + 0x74]
            //   83cfff               | or                  edi, 0xffffffff
            //   8bce                 | mov                 ecx, esi
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax

    condition:
        7 of them and filesize &lt; 18505728
}rule win_lazardoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.lazardoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lazardoor"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b940000000 ff15???????? 488bf0 4885c0 0f8453010000 8b1d???????? 4c89b42488000000 }
            // n = 7, score = 100
            //   b940000000           | pop                 esi
            //   ff15????????         |                     
            //   488bf0               | pop                 ebp
            //   4885c0               | ret                 
            //   0f8453010000         | inc                 ecx
            //   8b1d????????         |                     
            //   4c89b42488000000     | mov                 ecx, 4

        $sequence_1 = { 740b 83f80a 750a 4a011c09 eb04 42011c09 }
            // n = 6, score = 100
            //   740b                 | cmp                 dword ptr [ecx], esp
            //   83f80a               | jne                 0x7af
            //   750a                 | je                  0x76e
            //   4a011c09             | inc                 ebp
            //   eb04                 | xor                 ecx, ecx
            //   42011c09             | dec                 eax

        $sequence_2 = { 488bca 4c8d0579f60000 83e13f 488bc2 48c1f806 488d0cc9 498b04c0 }
            // n = 7, score = 100
            //   488bca               | shr                 edx, cl
            //   4c8d0579f60000       | inc                 ecx
            //   83e13f               | inc                 ecx
            //   488bc2               | dec                 ebx
            //   48c1f806             | mov                 ecx, dword ptr [edi + edx*8 + 0x27630]
            //   488d0cc9             | dec                 ecx
            //   498b04c0             | add                 ecx, eax

        $sequence_3 = { 4898 483bd0 770c e8???????? bb22000000 ebcc 4885f6 }
            // n = 7, score = 100
            //   4898                 | inc                 ecx
            //   483bd0               | mov                 esi, ebp
            //   770c                 | inc                 ecx
            //   e8????????           |                     
            //   bb22000000           | mov                 edi, ebp
            //   ebcc                 | dec                 eax
            //   4885f6               | mov                 ecx, eax

        $sequence_4 = { 74bf 488bd3 488bc8 e8???????? b9e8030000 ff15???????? }
            // n = 6, score = 100
            //   74bf                 | dec                 eax
            //   488bd3               | mov                 ecx, dword ptr [ebp - 0x30]
            //   488bc8               | inc                 ebp
            //   e8????????           |                     
            //   b9e8030000           | xor                 ecx, ecx
            //   ff15????????         |                     

        $sequence_5 = { 498bcf ff15???????? 488b06 ffc7 }
            // n = 4, score = 100
            //   498bcf               | dec                 ecx
            //   ff15????????         |                     
            //   488b06               | arpl                word ptr [edi + 0x3c], dx
            //   ffc7                 | dec                 eax

        $sequence_6 = { 488b4708 4883c708 4883c308 4885c0 }
            // n = 4, score = 100
            //   488b4708             | je                  0x485
            //   4883c708             | inc                 ebp
            //   4883c308             | lea                 eax, [ecx + 1]
            //   4885c0               | dec                 eax

        $sequence_7 = { 8d82b0abffff 498be9 498bf0 8bda 488bf9 83f80b }
            // n = 6, score = 100
            //   8d82b0abffff         | mov                 dword ptr [esp + 0x20], ebp
            //   498be9               | mov                 dword ptr [esp + 0x40], eax
            //   498bf0               | dec                 esp
            //   8bda                 | lea                 eax, [0xc7db]
            //   488bf9               | dec                 eax
            //   83f80b               | mov                 edx, ebx

        $sequence_8 = { 493bd0 720c 488d542440 e8???????? }
            // n = 4, score = 100
            //   493bd0               | mov                 ecx, dword ptr [ebp + 0xc0]
            //   720c                 | dec                 eax
            //   488d542440           | xor                 ecx, esp
            //   e8????????           |                     

        $sequence_9 = { 7410 488d15615b0200 488bc8 e8???????? 90 488d4c2460 ffd3 }
            // n = 7, score = 100
            //   7410                 | lea                 ecx, [0x10ed7]
            //   488d15615b0200       | and                 eax, 0x3f
            //   488bc8               | dec                 ebp
            //   e8????????           |                     
            //   90                   | mov                 ebp, esp
            //   488d4c2460           | dec                 ecx
            //   ffd3                 | sar                 ebp, 6

    condition:
        7 of them and filesize &lt; 405504
}rule win_xorist_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.xorist."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xorist"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7504 b001 eb44 53 e8???????? 6a0c 59 }
            // n = 7, score = 100
            //   7504                 | jne                 6
            //   b001                 | mov                 al, 1
            //   eb44                 | jmp                 0x46
            //   53                   | push                ebx
            //   e8????????           |                     
            //   6a0c                 | push                0xc
            //   59                   | pop                 ecx

        $sequence_1 = { ff742408 e8???????? 84c0 7404 b001 eb10 ff742404 }
            // n = 7, score = 100
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb10                 | jmp                 0x12
            //   ff742404             | push                dword ptr [esp + 4]

        $sequence_2 = { 56 e8???????? 59 8d8da8fbffff 8d3446 83c602 8bc6 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d8da8fbffff         | lea                 ecx, [ebp - 0x458]
            //   8d3446               | lea                 esi, [esi + eax*2]
            //   83c602               | add                 esi, 2
            //   8bc6                 | mov                 eax, esi

        $sequence_3 = { 8bcf 898668060000 e8???????? 89864c060000 898644060000 85c0 0f8432010000 }
            // n = 7, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   898668060000         | mov                 dword ptr [esi + 0x668], eax
            //   e8????????           |                     
            //   89864c060000         | mov                 dword ptr [esi + 0x64c], eax
            //   898644060000         | mov                 dword ptr [esi + 0x644], eax
            //   85c0                 | test                eax, eax
            //   0f8432010000         | je                  0x138

        $sequence_4 = { 33748500 33749d00 8b442420 8bc8 d1c6 89749d00 8b5c2410 }
            // n = 7, score = 100
            //   33748500             | xor                 esi, dword ptr [ebp + eax*4]
            //   33749d00             | xor                 esi, dword ptr [ebp + ebx*4]
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8bc8                 | mov                 ecx, eax
            //   d1c6                 | rol                 esi, 1
            //   89749d00             | mov                 dword ptr [ebp + ebx*4], esi
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]

        $sequence_5 = { c20400 56 8b742408 ba00000400 3bf2 7328 8b09 }
            // n = 7, score = 100
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   ba00000400           | mov                 edx, 0x40000
            //   3bf2                 | cmp                 esi, edx
            //   7328                 | jae                 0x2a
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_6 = { 807f2c00 7527 8d4730 c6472c01 50 8d4718 50 }
            // n = 7, score = 100
            //   807f2c00             | cmp                 byte ptr [edi + 0x2c], 0
            //   7527                 | jne                 0x29
            //   8d4730               | lea                 eax, [edi + 0x30]
            //   c6472c01             | mov                 byte ptr [edi + 0x2c], 1
            //   50                   | push                eax
            //   8d4718               | lea                 eax, [edi + 0x18]
            //   50                   | push                eax

        $sequence_7 = { e8???????? 8bc6 50 e8???????? 59 8db5aafbffff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8db5aafbffff         | lea                 esi, [ebp - 0x456]

        $sequence_8 = { 3894306c060000 74f1 0fb64101 8b542414 03e8 8b5c241c 8d842424040000 }
            // n = 7, score = 100
            //   3894306c060000       | cmp                 byte ptr [eax + esi + 0x66c], dl
            //   74f1                 | je                  0xfffffff3
            //   0fb64101             | movzx               eax, byte ptr [ecx + 1]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   03e8                 | add                 ebp, eax
            //   8b5c241c             | mov                 ebx, dword ptr [esp + 0x1c]
            //   8d842424040000       | lea                 eax, [esp + 0x424]

        $sequence_9 = { 8b4c2428 83c40c 83c108 83c508 83eb08 894c241c 83ef01 }
            // n = 7, score = 100
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   83c40c               | add                 esp, 0xc
            //   83c108               | add                 ecx, 8
            //   83c508               | add                 ebp, 8
            //   83eb08               | sub                 ebx, 8
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   83ef01               | sub                 edi, 1

    condition:
        7 of them and filesize &lt; 1402880
}
rule win_virut_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.virut."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virut"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 2bc8 51 03c7 50 ff742424 ff15???????? }
            // n = 6, score = 200
            //   2bc8                 | sub                 ecx, eax
            //   51                   | push                ecx
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   ff15????????         |                     

        $sequence_1 = { ffd7 85c0 75b1 ff742418 }
            // n = 4, score = 200
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   75b1                 | jne                 0xffffffb3
            //   ff742418             | push                dword ptr [esp + 0x18]

        $sequence_2 = { 6a44 58 8d9704010000 ab }
            // n = 4, score = 200
            //   6a44                 | push                0x44
            //   58                   | pop                 eax
            //   8d9704010000         | lea                 edx, [edi + 0x104]
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_3 = { 8d8424d4000000 50 ff15???????? 6800100000 8d842474050000 50 8d8424d0000000 }
            // n = 7, score = 200
            //   8d8424d4000000       | lea                 eax, [esp + 0xd4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6800100000           | push                0x1000
            //   8d842474050000       | lea                 eax, [esp + 0x574]
            //   50                   | push                eax
            //   8d8424d0000000       | lea                 eax, [esp + 0xd0]

        $sequence_4 = { 74dc 93 e8???????? 33c9 91 }
            // n = 5, score = 200
            //   74dc                 | je                  0xffffffde
            //   93                   | xchg                eax, ebx
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   91                   | xchg                eax, ecx

        $sequence_5 = { 54 51 50 52 51 }
            // n = 5, score = 200
            //   54                   | push                esp
            //   51                   | push                ecx
            //   50                   | push                eax
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_6 = { 8bdf 33c9 ac 3c61 7206 3c7a 7702 }
            // n = 7, score = 200
            //   8bdf                 | mov                 ebx, edi
            //   33c9                 | xor                 ecx, ecx
            //   ac                   | lodsb               al, byte ptr [esi]
            //   3c61                 | cmp                 al, 0x61
            //   7206                 | jb                  8
            //   3c7a                 | cmp                 al, 0x7a
            //   7702                 | ja                  4

        $sequence_7 = { e8???????? 33d2 6a1a 5e f7f6 80c241 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   6a1a                 | push                0x1a
            //   5e                   | pop                 esi
            //   f7f6                 | div                 esi
            //   80c241               | add                 dl, 0x41

        $sequence_8 = { 8d044d00000000 66ab 8d4704 ab 32e4 }
            // n = 5, score = 200
            //   8d044d00000000       | lea                 eax, [ecx*2]
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d4704               | lea                 eax, [edi + 4]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   32e4                 | xor                 ah, ah

        $sequence_9 = { ff15???????? 895c2414 6a64 ff15???????? 8b442414 99 6a64 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   99                   | cdq                 
            //   6a64                 | push                0x64

        $sequence_10 = { ff15???????? 385c2413 0f8402010000 803f4d }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   385c2413             | cmp                 byte ptr [esp + 0x13], bl
            //   0f8402010000         | je                  0x108
            //   803f4d               | cmp                 byte ptr [edi], 0x4d

        $sequence_11 = { 59 85c0 7416 e314 }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7416                 | je                  0x18
            //   e314                 | jecxz               0x16

        $sequence_12 = { 50 8d8424d0000000 50 ffd6 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   8d8424d0000000       | lea                 eax, [esp + 0xd0]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_13 = { 8bba0c010000 8b8a08010000 03f8 2bcb 60 8bcb f3a6 }
            // n = 7, score = 200
            //   8bba0c010000         | mov                 edi, dword ptr [edx + 0x10c]
            //   8b8a08010000         | mov                 ecx, dword ptr [edx + 0x108]
            //   03f8                 | add                 edi, eax
            //   2bcb                 | sub                 ecx, ebx
            //   60                   | pushal              
            //   8bcb                 | mov                 ecx, ebx
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]

        $sequence_14 = { 53 8d442410 50 6800040000 8d842404060000 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   6800040000           | push                0x400
            //   8d842404060000       | lea                 eax, [esp + 0x604]

        $sequence_15 = { 290c24 8b7224 59 03f3 8b521c 0fb7044e }
            // n = 6, score = 200
            //   290c24               | sub                 dword ptr [esp], ecx
            //   8b7224               | mov                 esi, dword ptr [edx + 0x24]
            //   59                   | pop                 ecx
            //   03f3                 | add                 esi, ebx
            //   8b521c               | mov                 edx, dword ptr [edx + 0x1c]
            //   0fb7044e             | movzx               eax, word ptr [esi + ecx*2]

    condition:
        7 of them and filesize &lt; 98304
}rule win_andromeda_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.andromeda."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.andromeda"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 368ab42b00ffffff 3688b42800ffffff 3688942b00ffffff 02d6 81e2ff000000 368a942a00ffffff 301439 }
            // n = 7, score = 800
            //   368ab42b00ffffff     | mov                 dh, byte ptr ss:[ebx + ebp - 0x100]
            //   3688b42800ffffff     | mov                 byte ptr ss:[eax + ebp - 0x100], dh
            //   3688942b00ffffff     | mov                 byte ptr ss:[ebx + ebp - 0x100], dl
            //   02d6                 | add                 dl, dh
            //   81e2ff000000         | and                 edx, 0xff
            //   368a942a00ffffff     | mov                 dl, byte ptr ss:[edx + ebp - 0x100]
            //   301439               | xor                 byte ptr [ecx + edi], dl

        $sequence_1 = { 7408 43 3b5d0c 74cf ebcf }
            // n = 5, score = 800
            //   7408                 | je                  0xa
            //   43                   | inc                 ebx
            //   3b5d0c               | cmp                 ebx, dword ptr [ebp + 0xc]
            //   74cf                 | je                  0xffffffd1
            //   ebcf                 | jmp                 0xffffffd1

        $sequence_2 = { 8b7d10 fec0 368a942800ffffff 02da 368ab42b00ffffff }
            // n = 5, score = 800
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   fec0                 | inc                 al
            //   368a942800ffffff     | mov                 dl, byte ptr ss:[eax + ebp - 0x100]
            //   02da                 | add                 bl, dl
            //   368ab42b00ffffff     | mov                 dh, byte ptr ss:[ebx + ebp - 0x100]

        $sequence_3 = { 2d04040404 e2f8 fc 33c0 8b7508 33db }
            // n = 6, score = 800
            //   2d04040404           | sub                 eax, 0x4040404
            //   e2f8                 | loop                0xfffffffa
            //   fc                   | cld                 
            //   33c0                 | xor                 eax, eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { 74cf ebcf 33c0 33db }
            // n = 4, score = 800
            //   74cf                 | je                  0xffffffd1
            //   ebcf                 | jmp                 0xffffffd1
            //   33c0                 | xor                 eax, eax
            //   33db                 | xor                 ebx, ebx

        $sequence_5 = { 020433 368ab42800ffffff 3688b42900ffffff 3688942800ffffff fec1 7408 }
            // n = 6, score = 800
            //   020433               | add                 al, byte ptr [ebx + esi]
            //   368ab42800ffffff     | mov                 dh, byte ptr ss:[eax + ebp - 0x100]
            //   3688b42900ffffff     | mov                 byte ptr ss:[ecx + ebp - 0x100], dh
            //   3688942800ffffff     | mov                 byte ptr ss:[eax + ebp - 0x100], dl
            //   fec1                 | inc                 cl
            //   7408                 | je                  0xa

        $sequence_6 = { 33db 33c9 33d2 8b7d10 }
            // n = 4, score = 800
            //   33db                 | xor                 ebx, ebx
            //   33c9                 | xor                 ecx, ecx
            //   33d2                 | xor                 edx, edx
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]

        $sequence_7 = { 55 8bec 81c400ffffff 60 b940000000 }
            // n = 5, score = 800
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81c400ffffff         | add                 esp, 0xffffff00
            //   60                   | pushal              
            //   b940000000           | mov                 ecx, 0x40

        $sequence_8 = { 60 e8???????? 5d 81ed???????? 33c9 }
            // n = 5, score = 700
            //   60                   | pushal              
            //   e8????????           |                     
            //   5d                   | pop                 ebp
            //   81ed????????         |                     
            //   33c9                 | xor                 ecx, ecx

        $sequence_9 = { 0fb64601 84c0 7905 0d00ffffff }
            // n = 4, score = 400
            //   0fb64601             | movzx               eax, byte ptr [esi + 1]
            //   84c0                 | test                al, al
            //   7905                 | jns                 7
            //   0d00ffffff           | or                  eax, 0xffffff00

        $sequence_10 = { 85ca 7404 0420 8806 }
            // n = 4, score = 400
            //   85ca                 | test                edx, ecx
            //   7404                 | je                  6
            //   0420                 | add                 al, 0x20
            //   8806                 | mov                 byte ptr [esi], al

        $sequence_11 = { 50 e8???????? 83c40c 6800000100 e8???????? }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6800000100           | push                0x10000
            //   e8????????           |                     

        $sequence_12 = { 8a06 33c9 3c5a 0f9ec1 33d2 }
            // n = 5, score = 400
            //   8a06                 | mov                 al, byte ptr [esi]
            //   33c9                 | xor                 ecx, ecx
            //   3c5a                 | cmp                 al, 0x5a
            //   0f9ec1               | setle               cl
            //   33d2                 | xor                 edx, edx

        $sequence_13 = { 6a00 6a30 8d45d0 50 6a01 ff7508 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   6a30                 | push                0x30
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_14 = { 0f9ec1 33d2 3c41 0f9dc2 85ca 7404 }
            // n = 6, score = 400
            //   0f9ec1               | setle               cl
            //   33d2                 | xor                 edx, edx
            //   3c41                 | cmp                 al, 0x41
            //   0f9dc2               | setge               dl
            //   85ca                 | test                edx, ecx
            //   7404                 | je                  6

        $sequence_15 = { ffd6 57 689f010000 6811010000 57 }
            // n = 5, score = 300
            //   ffd6                 | call                esi
            //   57                   | push                edi
            //   689f010000           | push                0x19f
            //   6811010000           | push                0x111
            //   57                   | push                edi

        $sequence_16 = { 6a00 6a00 6a06 6a01 6a02 e8???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_17 = { e8???????? 68???????? 6801010000 e8???????? 66c745e00200 68401f0000 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   68????????           |                     
            //   6801010000           | push                0x101
            //   e8????????           |                     
            //   66c745e00200         | mov                 word ptr [ebp - 0x20], 2
            //   68401f0000           | push                0x1f40

        $sequence_18 = { 6a00 ff75f0 e8???????? c7459c44000000 8945d4 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   c7459c44000000       | mov                 dword ptr [ebp - 0x64], 0x44
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax

        $sequence_19 = { ff35???????? e8???????? 8945fc 83f800 0f8476010000 }
            // n = 5, score = 200
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   83f800               | cmp                 eax, 0
            //   0f8476010000         | je                  0x17c

        $sequence_20 = { 8945dc 66c745cc0000 c745c801010000 8d458c }
            // n = 4, score = 200
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   66c745cc0000         | mov                 word ptr [ebp - 0x34], 0
            //   c745c801010000       | mov                 dword ptr [ebp - 0x38], 0x101
            //   8d458c               | lea                 eax, [ebp - 0x74]

        $sequence_21 = { 6a00 ff35???????? e8???????? 8945f8 83f800 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   83f800               | cmp                 eax, 0

        $sequence_22 = { 7457 33c0 8d7d9c b944000000 f3aa 6a00 6a00 }
            // n = 7, score = 200
            //   7457                 | je                  0x59
            //   33c0                 | xor                 eax, eax
            //   8d7d9c               | lea                 edi, [ebp - 0x64]
            //   b944000000           | mov                 ecx, 0x44
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_23 = { e8???????? 668945e2 c745e400000000 6a00 6a00 6a00 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   668945e2             | mov                 word ptr [ebp - 0x1e], ax
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_24 = { 894514 81cfc88ca632 ff5638 23d8 837d1400 }
            // n = 5, score = 100
            //   894514               | mov                 dword ptr [ebp + 0x14], eax
            //   81cfc88ca632         | or                  edi, 0x32a68cc8
            //   ff5638               | call                dword ptr [esi + 0x38]
            //   23d8                 | and                 ebx, eax
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0

        $sequence_25 = { 6af5 ff5630 6af5 8bd8 ff5630 8bf8 ff560c }
            // n = 7, score = 100
            //   6af5                 | push                -0xb
            //   ff5630               | call                dword ptr [esi + 0x30]
            //   6af5                 | push                -0xb
            //   8bd8                 | mov                 ebx, eax
            //   ff5630               | call                dword ptr [esi + 0x30]
            //   8bf8                 | mov                 edi, eax
            //   ff560c               | call                dword ptr [esi + 0xc]

        $sequence_26 = { 56 8b7508 57 6af5 ff5630 6af5 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   6af5                 | push                -0xb
            //   ff5630               | call                dword ptr [esi + 0x30]
            //   6af5                 | push                -0xb

        $sequence_27 = { eb02 33d2 81cf2c83af71 69f6403b5e1d 81ffad9a5b3f }
            // n = 5, score = 100
            //   eb02                 | jmp                 4
            //   33d2                 | xor                 edx, edx
            //   81cf2c83af71         | or                  edi, 0x71af832c
            //   69f6403b5e1d         | imul                esi, esi, 0x1d5e3b40
            //   81ffad9a5b3f         | cmp                 edi, 0x3f5b9aad

        $sequence_28 = { 81c3a2c3ae30 81fb8c880547 745e 837df800 }
            // n = 4, score = 100
            //   81c3a2c3ae30         | add                 ebx, 0x30aec3a2
            //   81fb8c880547         | cmp                 ebx, 0x4705888c
            //   745e                 | je                  0x60
            //   837df800             | cmp                 dword ptr [ebp - 8], 0

        $sequence_29 = { ff5614 8b4de4 0bd8 8a01 3c41 }
            // n = 5, score = 100
            //   ff5614               | call                dword ptr [esi + 0x14]
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   0bd8                 | or                  ebx, eax
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   3c41                 | cmp                 al, 0x41

        $sequence_30 = { ff5648 ff5634 0fafc7 8945e4 8b45fc 83c02c 50 }
            // n = 7, score = 100
            //   ff5648               | call                dword ptr [esi + 0x48]
            //   ff5634               | call                dword ptr [esi + 0x34]
            //   0fafc7               | imul                eax, edi
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c02c               | add                 eax, 0x2c
            //   50                   | push                eax

        $sequence_31 = { c64405d800 81c39bd6e836 ff560c 03f8 }
            // n = 4, score = 100
            //   c64405d800           | mov                 byte ptr [ebp + eax - 0x28], 0
            //   81c39bd6e836         | add                 ebx, 0x36e8d69b
            //   ff560c               | call                dword ptr [esi + 0xc]
            //   03f8                 | add                 edi, eax

    condition:
        7 of them and filesize &lt; 204800
}rule win_smokeloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.smokeloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smokeloader"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { ff15???????? 8d45f0 50 8d45e8 50 8d45e0 50 }
            // n = 7, score = 1300
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax

        $sequence_1 = { 57 ff15???????? 6a00 6800000002 }
            // n = 4, score = 1100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6800000002           | push                0x2000000

        $sequence_2 = { 8d45dc 50 6a00 53 ff15???????? 8d45f0 50 }
            // n = 7, score = 1100
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_3 = { 50 8d45e0 50 56 ff15???????? 56 }
            // n = 6, score = 1100
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_4 = { 740a 83c104 83f920 72f0 }
            // n = 4, score = 900
            //   740a                 | je                  0xc
            //   83c104               | add                 ecx, 4
            //   83f920               | cmp                 ecx, 0x20
            //   72f0                 | jb                  0xfffffffa

        $sequence_5 = { ff15???????? bf90010000 8bcf e8???????? }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   bf90010000           | mov                 edi, 0x190
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8bf0 8d45fc 50 ff75fc 56 6a19 }
            // n = 7, score = 900
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   56                   | push                esi
            //   6a19                 | push                0x19

        $sequence_7 = { 50 56 681f000f00 57 }
            // n = 4, score = 900
            //   50                   | push                eax
            //   56                   | mov                 esi, eax
            //   681f000f00           | lea                 eax, [ebp - 4]
            //   57                   | push                eax

        $sequence_8 = { 0fb64405dc 50 8d45ec 50 }
            // n = 4, score = 900
            //   0fb64405dc           | movzx               eax, byte ptr [ebp + eax - 0x24]
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax

        $sequence_9 = { 668ce8 6685c0 7406 fe05???????? }
            // n = 4, score = 900
            //   668ce8               | push                eax
            //   6685c0               | lea                 eax, [ebp - 0x20]
            //   7406                 | push                eax
            //   fe05????????         |                     

        $sequence_10 = { 56 8d45fc 50 57 57 6a19 ff75f8 }
            // n = 7, score = 900
            //   56                   | push                esi
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   57                   | push                edi
            //   6a19                 | push                0x19
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_11 = { 56 ff15???????? 50 56 6a00 ff15???????? }
            // n = 6, score = 800
            //   56                   | push                esi
            //   ff15????????         |                     
            //   50                   | push                esi
            //   56                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_12 = { 8b07 03c3 50 ff15???????? }
            // n = 4, score = 800
            //   8b07                 | push                esi
            //   03c3                 | push                esi
            //   50                   | push                edi
            //   ff15????????         |                     

        $sequence_13 = { 7507 33c0 e9???????? e8???????? b904010000 }
            // n = 5, score = 800
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   e8????????           |                     
            //   b904010000           | mov                 ecx, 0x104

        $sequence_14 = { 8b84310c010000 03c7 50 8b843104010000 03c5 50 }
            // n = 6, score = 700
            //   8b84310c010000       | push                esi
            //   03c7                 | push                0x19
            //   50                   | mov                 al, byte ptr [esp + ecx + 0x18]
            //   8b843104010000       | xor                 byte ptr [ebx + ebp], al
            //   03c5                 | inc                 ebx
            //   50                   | cmp                 ebx, dword ptr [esp + 0x11c]

        $sequence_15 = { 03f0 23f1 8a443418 88443c18 88543418 0fb64c3c18 }
            // n = 6, score = 700
            //   03f0                 | lea                 eax, [ebp - 4]
            //   23f1                 | push                eax
            //   8a443418             | push                edi
            //   88443c18             | push                edi
            //   88543418             | push                0x19
            //   0fb64c3c18           | push                dword ptr [ebp - 8]

        $sequence_16 = { 50 57 ff15???????? 43 83fb0f }
            // n = 5, score = 700
            //   50                   | push                0x2000000
            //   57                   | push                3
            //   ff15????????         |                     
            //   43                   | push                ebx
            //   83fb0f               | lea                 eax, [ebp - 0x10]

        $sequence_17 = { 8a440c18 30042b 43 3b9c241c010000 72c0 5f 5e }
            // n = 7, score = 700
            //   8a440c18             | push                esi
            //   30042b               | lea                 eax, [ebp - 4]
            //   43                   | push                eax
            //   3b9c241c010000       | push                edi
            //   72c0                 | push                edi
            //   5f                   | push                0x19
            //   5e                   | push                esi

        $sequence_18 = { 01d4 8d85f0fdffff 8b750c 8b7d10 }
            // n = 4, score = 500
            //   01d4                 | add                 esp, edx
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]

        $sequence_19 = { c70200000000 6800800000 52 51 }
            // n = 4, score = 500
            //   c70200000000         | mov                 dword ptr [edx], 0
            //   6800800000           | push                0x8000
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_20 = { e8???????? 8d8decfdffff 8d95f0fdffff c70200000000 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   c70200000000         | mov                 dword ptr [edx], 0

        $sequence_21 = { 31c0 66894603 8d8de8fdffff 50 50 }
            // n = 5, score = 500
            //   31c0                 | xor                 eax, eax
            //   66894603             | mov                 word ptr [esi + 3], ax
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_22 = { e8???????? 2500300038 005800 2500300038 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   2500300038           | and                 eax, 0x38003000
            //   005800               | add                 byte ptr [eax], bl
            //   2500300038           | and                 eax, 0x38003000

        $sequence_23 = { ffb5f0fdffff 50 53 e8???????? }
            // n = 4, score = 500
            //   ffb5f0fdffff         | push                dword ptr [ebp - 0x210]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_24 = { c60653 56 6a00 6a00 6a00 }
            // n = 5, score = 500
            //   c60653               | mov                 byte ptr [esi], 0x53
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_25 = { 8b7d10 50 57 56 53 }
            // n = 5, score = 500
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_26 = { fc 5f 5e 5b }
            // n = 4, score = 400
            //   fc                   | mov                 ebx, 0xc14043b8
            //   5f                   | pop                 eax
            //   5e                   | sub                 esi, eax
            //   5b                   | shr                 esi, 1

        $sequence_27 = { 60 89c6 89cf fc }
            // n = 4, score = 400
            //   60                   | xor                 eax, eax
            //   89c6                 | mov                 ecx, 0x104
            //   89cf                 | dec                 eax
            //   fc                   | mov                 dword ptr [eax + 0x10], ebx

        $sequence_28 = { 30d0 aa e2f3 7505 }
            // n = 4, score = 400
            //   30d0                 | xor                 al, dl
            //   aa                   | stosb               byte ptr es:[edi], al
            //   e2f3                 | loop                0xfffffff5
            //   7505                 | jne                 7

        $sequence_29 = { 55 89e5 81ec5c060000 53 }
            // n = 4, score = 400
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   81ec5c060000         | sub                 esp, 0x65c
            //   53                   | push                ebx

        $sequence_30 = { 89cf fc b280 31db a4 b302 }
            // n = 6, score = 400
            //   89cf                 | mov                 edi, 0x190
            //   fc                   | mov                 ecx, edi
            //   b280                 | je                  0xc
            //   31db                 | add                 ecx, 4
            //   a4                   | cmp                 ecx, 0x20
            //   b302                 | jb                  0xfffffffa

        $sequence_31 = { 41b800300000 ff15???????? 448b4754 488bd6 488bc8 }
            // n = 5, score = 300
            //   41b800300000         | dec                 ecx
            //   ff15????????         |                     
            //   448b4754             | mov                 ecx, esp
            //   488bd6               | mov                 edx, dword ptr [edi + 0x35e]
            //   488bc8               | dec                 esp

        $sequence_32 = { 49 8d3c8c 8b37 4c 01c6 }
            // n = 5, score = 300
            //   49                   | dec                 ecx
            //   8d3c8c               | lea                 edi, [esp + ecx*4]
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   4c                   | dec                 esp
            //   01c6                 | add                 esi, eax

        $sequence_33 = { 57 4156 4883ec30 33db 488be9 4885c9 0f8498000000 }
            // n = 7, score = 300
            //   57                   | lea                 eax, [ebp - 0x11]
            //   4156                 | add                 edx, 0x363
            //   4883ec30             | inc                 ecx
            //   33db                 | mov                 eax, 0x3000
            //   488be9               | inc                 esp
            //   4885c9               | mov                 eax, dword ptr [edi + 0x54]
            //   0f8498000000         | dec                 eax

        $sequence_34 = { 488bd6 4889442420 ff15???????? 488bce 85c0 7567 }
            // n = 6, score = 300
            //   488bd6               | mov                 edx, 0x104
            //   4889442420           | dec                 eax
            //   ff15????????         |                     
            //   488bce               | mov                 edx, esi
            //   85c0                 | dec                 eax
            //   7567                 | mov                 dword ptr [esp + 0x20], eax

        $sequence_35 = { 41 8b4b18 45 8b6320 4d 01c4 }
            // n = 6, score = 300
            //   41                   | inc                 ecx
            //   8b4b18               | mov                 ecx, dword ptr [ebx + 0x18]
            //   45                   | inc                 ebp
            //   8b6320               | mov                 esp, dword ptr [ebx + 0x20]
            //   4d                   | dec                 ebp
            //   01c4                 | add                 esp, eax

        $sequence_36 = { 89d0 c1e205 01c2 31c0 }
            // n = 4, score = 300
            //   89d0                 | mov                 eax, edx
            //   c1e205               | shl                 edx, 5
            //   01c2                 | add                 edx, eax
            //   31c0                 | xor                 eax, eax

        $sequence_37 = { 55 89e5 81ec54040000 53 56 }
            // n = 5, score = 300
            //   55                   | push                eax
            //   89e5                 | push                ebx
            //   81ec54040000         | lea                 ecx, [ebp - 0x214]
            //   53                   | lea                 edx, [ebp - 0x210]
            //   56                   | mov                 dword ptr [edx], 0

        $sequence_38 = { ff15???????? 488d4c2460 ba04010000 ff15???????? }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   488d4c2460           | dec                 eax
            //   ba04010000           | lea                 ecx, [esp + 0x60]
            //   ff15????????         |                     

        $sequence_39 = { 8b6320 4d 01c4 ffc9 49 8d3c8c }
            // n = 6, score = 300
            //   8b6320               | mov                 esp, dword ptr [ebx + 0x20]
            //   4d                   | dec                 ebp
            //   01c4                 | add                 esp, eax
            //   ffc9                 | dec                 ecx
            //   49                   | dec                 ecx
            //   8d3c8c               | lea                 edi, [esp + ecx*4]

        $sequence_40 = { 41 8b7b24 4c 01c7 668b0c4f }
            // n = 5, score = 300
            //   41                   | inc                 ecx
            //   8b7b24               | mov                 edi, dword ptr [ebx + 0x24]
            //   4c                   | dec                 esp
            //   01c7                 | add                 edi, eax
            //   668b0c4f             | mov                 cx, word ptr [edi + ecx*2]

        $sequence_41 = { 8bd3 498bcc e8???????? 8b975e030000 4c8d45ef 81c263030000 }
            // n = 6, score = 300
            //   8bd3                 | dec                 eax
            //   498bcc               | mov                 ecx, esi
            //   e8????????           |                     
            //   8b975e030000         | test                eax, eax
            //   4c8d45ef             | jne                 0x69
            //   81c263030000         | mov                 edx, ebx

        $sequence_42 = { 8b7b1c 4c 01c7 8b048f }
            // n = 4, score = 300
            //   8b7b1c               | mov                 edi, dword ptr [ebx + 0x1c]
            //   4c                   | dec                 esp
            //   01c7                 | add                 edi, eax
            //   8b048f               | mov                 eax, dword ptr [edi + ecx*4]

        $sequence_43 = { c3 56 89c2 8b453c 8b7c2878 01ef }
            // n = 6, score = 200
            //   c3                   | mov                 eax, dword ptr [eax + ebp]
            //   56                   | add                 eax, ebp
            //   89c2                 | mov                 edi, dword ptr [eax + ebp + 0x78]
            //   8b453c               | add                 edi, ebp
            //   8b7c2878             | mov                 esi, dword ptr [edi + 0x20]
            //   01ef                 | add                 esi, ebp

        $sequence_44 = { 55 8bec 83ec0c e8???????? 8945f8 8b45f8 8b4858 }
            // n = 7, score = 200
            //   55                   | mov                 dword ptr [ebp - 0x6c], eax
            //   8bec                 | mov                 ecx, dword ptr [ebp - 0x60]
            //   83ec0c               | mov                 edx, dword ptr [ebp - 0x6c]
            //   e8????????           |                     
            //   8945f8               | jne                 0x15
            //   8b45f8               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b4858               | imul                edx, edx, 3

        $sequence_45 = { 837d1000 740d 8b4508 0345f0 8a4dec }
            // n = 5, score = 200
            //   837d1000             | push                eax
            //   740d                 | push                dword ptr [ebp - 4]
            //   8b4508               | push                esi
            //   0345f0               | push                0x19
            //   8a4dec               | push                eax

        $sequence_46 = { 50 e8???????? 89459c 8b4da0 8b559c 895158 }
            // n = 6, score = 200
            //   50                   | add                 edx, dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   89459c               | mov                 eax, dword ptr [ebp - 4]
            //   8b4da0               | mov                 ecx, dword ptr [ebp - 0x48]
            //   8b559c               | mov                 dword ptr [eax + 0x1c], ecx
            //   895158               | mov                 edx, dword ptr [ebp - 0x7c]

        $sequence_47 = { 50 e8???????? 8b4d0c 833900 7412 8b550c 833a03 }
            // n = 7, score = 200
            //   50                   | push                esi
            //   e8????????           |                     
            //   8b4d0c               | push                0xf001f
            //   833900               | push                edi
            //   7412                 | mov                 ebp, esp
            //   8b550c               | sub                 esp, 0x88
            //   833a03               | push                edi

        $sequence_48 = { 7513 8b5510 6bd203 0355e4 8b45fc }
            // n = 5, score = 200
            //   7513                 | mov                 dword ptr [ebp - 0x28], 0
            //   8b5510               | cmp                 dword ptr [ebp + 0x10], 0
            //   6bd203               | je                  0x13
            //   0355e4               | mov                 eax, dword ptr [ebp + 8]
            //   8b45fc               | add                 eax, dword ptr [ebp - 0x10]

        $sequence_49 = { 58 29c6 d1ee 037724 0fb7442efe c1e002 }
            // n = 6, score = 200
            //   58                   | lodsd               eax, dword ptr [esi]
            //   29c6                 | add                 eax, ebp
            //   d1ee                 | xor                 ecx, ecx
            //   037724               | rol                 ecx, 8
            //   0fb7442efe           | shl                 eax, 2
            //   c1e002               | add                 eax, dword ptr [edi + 0x1c]

        $sequence_50 = { aa e2f3 7506 7404 }
            // n = 4, score = 200
            //   aa                   | push                ebx
            //   e2f3                 | push                esi
            //   7506                 | ret                 0x10
            //   7404                 | push                ebp

        $sequence_51 = { c1e002 03471c 8b0428 01e8 }
            // n = 4, score = 200
            //   c1e002               | cld                 
            //   03471c               | mov                 dl, 0x80
            //   8b0428               | xor                 ebx, ebx
            //   01e8                 | mov                 esi, eax

        $sequence_52 = { 8bec 81ec88000000 57 c745e800000000 c745f400000000 c745f800000000 c745d800000000 }
            // n = 7, score = 200
            //   8bec                 | lea                 eax, [ebp - 0x20]
            //   81ec88000000         | push                eax
            //   57                   | push                esi
            //   c745e800000000       | mov                 edi, 0x190
            //   c745f400000000       | mov                 ecx, edi
            //   c745f800000000       | mov                 esi, eax
            //   c745d800000000       | lea                 eax, [ebp - 4]

        $sequence_53 = { 8b7c2878 01ef 8b7720 01ee 56 ad 01e8 }
            // n = 7, score = 200
            //   8b7c2878             | mov                 edi, ecx
            //   01ef                 | cld                 
            //   8b7720               | mov                 dl, 0x80
            //   01ee                 | xor                 ebx, ebx
            //   56                   | mov                 esi, eax
            //   ad                   | mov                 edi, ecx
            //   01e8                 | cld                 

        $sequence_54 = { 5b c9 c20800 55 89e5 83ec04 }
            // n = 6, score = 200
            //   5b                   | mov                 ebp, esp
            //   c9                   | sub                 esp, 0x454
            //   c20800               | xor                 al, dl
            //   55                   | stosb               byte ptr es:[edi], al
            //   89e5                 | loop                0xfffffff6
            //   83ec04               | jne                 0xb

        $sequence_55 = { 56 57 007508 bbb84340c1 }
            // n = 4, score = 200
            //   56                   | mov                 dl, 0x80
            //   57                   | xor                 ebx, ebx
            //   007508               | movsb               byte ptr es:[edi], byte ptr [esi]
            //   bbb84340c1           | mov                 bl, 2

        $sequence_56 = { e8???????? 894594 8b4da0 8b5594 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   894594               | mov                 dword ptr [ebp - 0x18], 0
            //   8b4da0               | mov                 dword ptr [ebp - 0xc], 0
            //   8b5594               | mov                 dword ptr [ebp - 8], 0

        $sequence_57 = { 8b4db8 89481c 8b5584 8b45b4 894220 eb0a 8b4d84 }
            // n = 7, score = 200
            //   8b4db8               | mov                 cl, byte ptr [ebp - 0x14]
            //   89481c               | push                eax
            //   8b5584               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b45b4               | cmp                 dword ptr [ecx], 0
            //   894220               | je                  0x1b
            //   eb0a                 | mov                 edx, dword ptr [ebp + 0xc]
            //   8b4d84               | cmp                 dword ptr [edx], 3

        $sequence_58 = { ad 01e8 31c9 c1c108 }
            // n = 4, score = 200
            //   ad                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   01e8                 | pushal              
            //   31c9                 | mov                 esi, eax
            //   c1c108               | mov                 edi, ecx

        $sequence_59 = { bf370e04b6 58 7e51 b6aa }
            // n = 4, score = 100
            //   bf370e04b6           | sub                 dword ptr [ebx + 0xd], edx
            //   58                   | pop                 ebp
            //   7e51                 | ficomp              word ptr [ecx - 0x4909c4a7]
            //   b6aa                 | fcomp               dword ptr [ebp + 0x5df0d952]

        $sequence_60 = { d89d52d9f05d 5d 5d dc22 4d 5d 7d5d }
            // n = 7, score = 100
            //   d89d52d9f05d         | loop                0xfffffff8
            //   5d                   | jne                 0xd
            //   5d                   | stosb               byte ptr es:[edi], al
            //   dc22                 | loop                0xfffffff5
            //   4d                   | jne                 0xa
            //   5d                   | je                  0xa
            //   7d5d                 | pop                 ebx

        $sequence_61 = { 59 dbdd 9a9fd66979de99 59 b657 11dc b354 }
            // n = 7, score = 100
            //   59                   | pop                 ebp
            //   dbdd                 | pop                 ebp
            //   9a9fd66979de99       | fsub                qword ptr [edx]
            //   59                   | dec                 ebp
            //   b657                 | pop                 ebp
            //   11dc                 | jge                 0x6b
            //   b354                 | mov                 dh, 0xa8

        $sequence_62 = { 29530d a2???????? 5d de99593bf6b6 }
            // n = 4, score = 100
            //   29530d               | je                  0xb
            //   a2????????           |                     
            //   5d                   | xor                 al, dl
            //   de99593bf6b6         | stosb               byte ptr es:[edi], al

        $sequence_63 = { b6a8 51 55 b658 5d }
            // n = 5, score = 100
            //   b6a8                 | leave               
            //   51                   | ret                 8
            //   55                   | push                ebp
            //   b658                 | mov                 ebp, esp
            //   5d                   | sub                 esp, 4

    condition:
        7 of them and filesize &lt; 245760
}rule win_diztakun_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.diztakun."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diztakun"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 844f08 7543 83f80d 7505 844f08 7539 83f81b }
            // n = 7, score = 100
            //   844f08               | test                byte ptr [edi + 8], cl
            //   7543                 | jne                 0x45
            //   83f80d               | cmp                 eax, 0xd
            //   7505                 | jne                 7
            //   844f08               | test                byte ptr [edi + 8], cl
            //   7539                 | jne                 0x3b
            //   83f81b               | cmp                 eax, 0x1b

        $sequence_1 = { 7524 a1???????? a3???????? a1???????? c705????????50754200 8935???????? a3???????? }
            // n = 7, score = 100
            //   7524                 | jne                 0x26
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????50754200     |     
            //   8935????????         |                     
            //   a3????????           |                     

        $sequence_2 = { e9???????? 836c240404 e9???????? 8b4138 85c0 7509 ff7120 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   836c240404           | sub                 dword ptr [esp + 4], 4
            //   e9????????           |                     
            //   8b4138               | mov                 eax, dword ptr [ecx + 0x38]
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb
            //   ff7120               | push                dword ptr [ecx + 0x20]

        $sequence_3 = { 51 ff15???????? 8d542414 52 681f000200 6a00 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   52                   | push                edx
            //   681f000200           | push                0x2001f
            //   6a00                 | push                0

        $sequence_4 = { 56 e8???????? 8b7c2418 83c010 8907 83c404 c784242c020000ffffffff }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   83c010               | add                 eax, 0x10
            //   8907                 | mov                 dword ptr [edi], eax
            //   83c404               | add                 esp, 4
            //   c784242c020000ffffffff     | mov    dword ptr [esp + 0x22c], 0xffffffff

        $sequence_5 = { 85ff 744a 6a05 8bce e8???????? 8b4e20 50 }
            // n = 7, score = 100
            //   85ff                 | test                edi, edi
            //   744a                 | je                  0x4c
            //   6a05                 | push                5
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   50                   | push                eax

        $sequence_6 = { 8bd8 68???????? 8d4c242c c68424dc0700000a e8???????? 89442448 68???????? }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   68????????           |                     
            //   8d4c242c             | lea                 ecx, [esp + 0x2c]
            //   c68424dc0700000a     | mov                 byte ptr [esp + 0x7dc], 0xa
            //   e8????????           |                     
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   68????????           |                     

        $sequence_7 = { 7f0a 8b08 8b11 50 8b4204 ffd0 c7842424020000ffffffff }
            // n = 7, score = 100
            //   7f0a                 | jg                  0xc
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   50                   | push                eax
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   ffd0                 | call                eax
            //   c7842424020000ffffffff     | mov    dword ptr [esp + 0x224], 0xffffffff

        $sequence_8 = { 50 8d4c241c e8???????? 889c24d8070000 8b442458 83c0f0 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   e8????????           |                     
            //   889c24d8070000       | mov                 byte ptr [esp + 0x7d8], bl
            //   8b442458             | mov                 eax, dword ptr [esp + 0x58]
            //   83c0f0               | add                 eax, -0x10

        $sequence_9 = { 40 c706???????? c74640d0b74300 33c9 894628 89462c 894e24 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   c706????????         |                     
            //   c74640d0b74300       | mov                 dword ptr [esi + 0x40], 0x43b7d0
            //   33c9                 | xor                 ecx, ecx
            //   894628               | mov                 dword ptr [esi + 0x28], eax
            //   89462c               | mov                 dword ptr [esi + 0x2c], eax
            //   894e24               | mov                 dword ptr [esi + 0x24], ecx

    condition:
        7 of them and filesize &lt; 688128
}rule win_emotet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.emotet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3c7a 7e0b 3c41 7c04 }
            // n = 4, score = 2900
            //   3c7a                 | mov                 byte ptr [ecx], 0x58
            //   7e0b                 | inc                 ecx
            //   3c41                 | jle                 0xd
            //   7c04                 | cmp                 al, 0x41

        $sequence_1 = { 3c41 7c04 3c5a 7e03 c60158 41 }
            // n = 6, score = 2900
            //   3c41                 | mov                 byte ptr [eax - 2], cl
            //   7c04                 | shr                 cx, 8
            //   3c5a                 | inc                 ecx
            //   7e03                 | mov                 byte ptr [eax - 1], cl
            //   c60158               | dec                 ebp
            //   41                   | cmp                 ebx, ecx

        $sequence_2 = { 8a01 3c30 7c04 3c39 7e13 3c61 }
            // n = 6, score = 2900
            //   8a01                 | lea                 eax, [eax + 4]
            //   3c30                 | inc                 ecx
            //   7c04                 | mov                 byte ptr [eax - 3], al
            //   3c39                 | inc                 ecx
            //   7e13                 | mov                 byte ptr [eax - 2], cl
            //   3c61                 | shr                 cx, 8

        $sequence_3 = { 3c39 7e13 3c61 7c04 3c7a 7e0b }
            // n = 6, score = 2900
            //   3c39                 | dec                 ebp
            //   7e13                 | lea                 eax, [eax + 4]
            //   3c61                 | inc                 ecx
            //   7c04                 | mov                 byte ptr [eax], cl
            //   3c7a                 | movzx               eax, cx
            //   7e0b                 | shr                 ecx, 0x10

        $sequence_4 = { 33c0 3903 5f 5e 0f95c0 5b 8be5 }
            // n = 7, score = 2400
            //   33c0                 | cmp                 al, 0x39
            //   3903                 | jle                 0x1f
            //   5f                   | cmp                 al, 0x61
            //   5e                   | jl                  0x14
            //   0f95c0               | cmp                 al, 0x7a
            //   5b                   | jle                 0x1f
            //   8be5                 | cmp                 al, 0x41

        $sequence_5 = { c60158 41 803900 75dd }
            // n = 4, score = 2400
            //   c60158               | cmp                 al, 0x5a
            //   41                   | jle                 0xd
            //   803900               | mov                 byte ptr [ecx], 0x58
            //   75dd                 | cmp                 al, 0x7a

        $sequence_6 = { 7708 0fb7c0 83c020 eb03 0fb7c0 69d23f000100 }
            // n = 6, score = 2300
            //   7708                 | jle                 0xd
            //   0fb7c0               | cmp                 al, 0x41
            //   83c020               | jl                  0xa
            //   eb03                 | cmp                 al, 0x5a
            //   0fb7c0               | cmp                 al, 0x39
            //   69d23f000100         | jle                 0x15

        $sequence_7 = { c1e910 8842fd 884afe c1e908 }
            // n = 4, score = 2100
            //   c1e910               | mov                 al, byte ptr [ecx]
            //   8842fd               | cmp                 al, 0x30
            //   884afe               | jl                  8
            //   c1e908               | cmp                 al, 0x39

        $sequence_8 = { 75f2 eb06 33c9 66894802 }
            // n = 4, score = 2100
            //   75f2                 | jl                  8
            //   eb06                 | cmp                 al, 0x5a
            //   33c9                 | jle                 0xb
            //   66894802             | mov                 byte ptr [ecx], 0x58

        $sequence_9 = { 8d5801 f6c30f 7406 83e3f0 83c310 }
            // n = 5, score = 2000
            //   8d5801               | cmp                 al, 0x7a
            //   f6c30f               | jle                 0x11
            //   7406                 | cmp                 al, 0x41
            //   83e3f0               | jl                  0xe
            //   83c310               | cmp                 al, 0x5a

        $sequence_10 = { 8945c8 8975d4 8955d8 e8???????? }
            // n = 4, score = 1900
            //   8945c8               | cmp                 eax, 0x7f
            //   8975d4               | jbe                 0xb
            //   8955d8               | shr                 eax, 7
            //   e8????????           |                     

        $sequence_11 = { 8b16 8945fc 8d45f8 6a04 }
            // n = 4, score = 1900
            //   8b16                 | shr                 eax, 7
            //   8945fc               | inc                 ecx
            //   8d45f8               | cmp                 eax, 0x7f
            //   6a04                 | ja                  0

        $sequence_12 = { 56 50 8b4774 03878c000000 50 ff15???????? 017758 }
            // n = 7, score = 1900
            //   56                   | mov                 ecx, dword ptr [ebp + 0xc]
            //   50                   | mov                 eax, edx
            //   8b4774               | mov                 edx, dword ptr [esi]
            //   03878c000000         | mov                 dword ptr [ebp - 4], eax
            //   50                   | lea                 eax, [ebp - 8]
            //   ff15????????         |                     
            //   017758               | push                4

        $sequence_13 = { ff15???????? 8b17 83c40c 8b4d0c 8bc2 }
            // n = 5, score = 1900
            //   ff15????????         |                     
            //   8b17                 | inc                 ecx
            //   83c40c               | cmp                 eax, 0x7f
            //   8b4d0c               | ja                  2
            //   8bc2                 | jbe                 0xb

        $sequence_14 = { 0faf4510 50 6a08 ff15???????? 50 }
            // n = 5, score = 1900
            //   0faf4510             | add                 ebx, 0x10
            //   50                   | lea                 ebx, [eax + 1]
            //   6a08                 | test                bl, 0xf
            //   ff15????????         |                     
            //   50                   | je                  0xb

        $sequence_15 = { 8b4508 894dcc 8d4dc8 8945c8 }
            // n = 4, score = 1900
            //   8b4508               | push                0
            //   894dcc               | push                -1
            //   8d4dc8               | push                eax
            //   8945c8               | push                ecx

        $sequence_16 = { c745fc04000000 50 8d45f8 81ca00000020 50 52 }
            // n = 6, score = 1800
            //   c745fc04000000       | cmp                 al, 0x7a
            //   50                   | jle                 0x11
            //   8d45f8               | cmp                 al, 0x41
            //   81ca00000020         | jl                  0xe
            //   50                   | jl                  6
            //   52                   | cmp                 al, 0x5a

        $sequence_17 = { 0fb7c1 c1e910 66c1e808 4d8d4004 418840fd 418848fe 66c1e908 }
            // n = 7, score = 1700
            //   0fb7c1               | shr                 ecx, 6
            //   c1e910               | mov                 dword ptr [ebp + 0x6f], ecx
            //   66c1e808             | dec                 eax
            //   4d8d4004             | add                 ecx, eax
            //   418840fd             | jmp                 0xa
            //   418848fe             | cmp                 byte ptr [ecx], 0
            //   66c1e908             | je                  0xf

        $sequence_18 = { 4c8bdc 49895b08 49896b10 49897318 49897b20 4156 4883ec70 }
            // n = 7, score = 1700
            //   4c8bdc               | dec                 eax
            //   49895b08             | dec                 ecx
            //   49896b10             | dec                 eax
            //   49897318             | cmp                 ecx, eax
            //   49897b20             | movzx               eax, cx
            //   4156                 | shr                 ecx, 0x10
            //   4883ec70             | shr                 ax, 8

        $sequence_19 = { d3e7 83f841 7208 83f85a }
            // n = 4, score = 1700
            //   d3e7                 | cmp                 al, 0x7a
            //   83f841               | jle                 0x13
            //   7208                 | cmp                 al, 0x41
            //   83f85a               | cmp                 al, 0x30

        $sequence_20 = { 418848fe 66c1e908 418848ff 4d3bd9 72cf }
            // n = 5, score = 1700
            //   418848fe             | inc                 ecx
            //   66c1e908             | mov                 byte ptr [eax - 2], cl
            //   418848ff             | shr                 cx, 8
            //   4d3bd9               | inc                 ecx
            //   72cf                 | mov                 byte ptr [eax - 1], cl

        $sequence_21 = { 483bd8 730b 488bcb e8???????? 488bd8 }
            // n = 5, score = 1700
            //   483bd8               | push                esi
            //   730b                 | dec                 eax
            //   488bcb               | sub                 esp, 0x70
            //   e8????????           |                     
            //   488bd8               | sub                 ecx, edx

        $sequence_22 = { 2bca d1e9 03ca c1e906 894d18 }
            // n = 5, score = 1700
            //   2bca                 | sub                 ecx, edx
            //   d1e9                 | shr                 ecx, 1
            //   03ca                 | add                 ecx, edx
            //   c1e906               | shr                 ecx, 6
            //   894d18               | mov                 dword ptr [ebp + 0x18], ecx

        $sequence_23 = { 418bd0 d3e2 418bcb d3e0 }
            // n = 4, score = 1700
            //   418bd0               | dec                 eax
            //   d3e2                 | mov                 dword ptr [eax + 8], ecx
            //   418bcb               | dec                 eax
            //   d3e0                 | mov                 dword ptr [eax + 0x10], edx

        $sequence_24 = { 48895010 4c894018 4c894820 c3 }
            // n = 4, score = 1700
            //   48895010             | shr                 ecx, 1
            //   4c894018             | add                 ecx, edx
            //   4c894820             | shr                 ecx, 6
            //   c3                   | mov                 dword ptr [esp + 0x30], ecx

        $sequence_25 = { 4803c8 eb08 803900 7408 48ffc9 483bc8 }
            // n = 6, score = 1700
            //   4803c8               | add                 ecx, edx
            //   eb08                 | shr                 ecx, 6
            //   803900               | mov                 dword ptr [ebp + 0x20], ecx
            //   7408                 | sub                 ecx, edx
            //   48ffc9               | shr                 ecx, 1
            //   483bc8               | add                 ecx, edx

        $sequence_26 = { c1e807 41 83f87f 77f7 }
            // n = 4, score = 1600
            //   c1e807               | mov                 dword ptr [ebx + 0x18], esi
            //   41                   | dec                 ecx
            //   83f87f               | mov                 dword ptr [ebx + 0x20], edi
            //   77f7                 | inc                 ecx

        $sequence_27 = { f7e1 b84fecc44e 2bca d1e9 }
            // n = 4, score = 1500
            //   f7e1                 | jl                  8
            //   b84fecc44e           | cmp                 al, 0x5a
            //   2bca                 | jle                 0xb
            //   d1e9                 | mov                 byte ptr [ecx], 0x58

        $sequence_28 = { 84c0 75f2 eb03 c60100 }
            // n = 4, score = 1500
            //   84c0                 | shr                 ecx, 1
            //   75f2                 | add                 ecx, edx
            //   eb03                 | shr                 ecx, 6
            //   c60100               | mov                 dword ptr [esp + 0x30], ecx

        $sequence_29 = { 7907 83c107 3bf7 72e8 }
            // n = 4, score = 1200
            //   7907                 | dec                 ecx
            //   83c107               | mov                 dword ptr [ebx + 0x18], esi
            //   3bf7                 | dec                 ecx
            //   72e8                 | mov                 dword ptr [ebx + 0x20], edi

        $sequence_30 = { 83c104 894e04 8b00 85c0 75f4 }
            // n = 5, score = 1200
            //   83c104               | jl                  0xc
            //   894e04               | cmp                 al, 0x5a
            //   8b00                 | jl                  6
            //   85c0                 | cmp                 al, 0x7a
            //   75f4                 | jle                 0xf

        $sequence_31 = { 52 52 52 68???????? 52 }
            // n = 5, score = 1100
            //   52                   | inc                 ecx
            //   52                   | push                esi
            //   52                   | dec                 eax
            //   68????????           |                     
            //   52                   | sub                 esp, 0x70

        $sequence_32 = { 56 57 6a1e 8d45e0 }
            // n = 4, score = 1100
            //   56                   | push                ebx
            //   57                   | push                0
            //   6a1e                 | lea                 eax, [ebp - 4]
            //   8d45e0               | push                ebx

        $sequence_33 = { 8d4dfc 51 6a00 6a01 8d55f8 }
            // n = 5, score = 1100
            //   8d4dfc               | push                esi
            //   51                   | mov                 esi, ecx
            //   6a00                 | mov                 ebx, 0x844cc300
            //   6a01                 | push                edi
            //   8d55f8               | push                0

        $sequence_34 = { 83ec48 53 56 57 6a44 }
            // n = 5, score = 1100
            //   83ec48               | cmp                 eax, 0x7f
            //   53                   | ja                  0
            //   56                   | push                0
            //   57                   | push                -1
            //   6a44                 | push                eax

        $sequence_35 = { 83f87f 760d 8d642400 c1e807 }
            // n = 4, score = 1000
            //   83f87f               | inc                 ecx
            //   760d                 | mov                 byte ptr [eax - 2], cl
            //   8d642400             | shr                 cx, 8
            //   c1e807               | inc                 ecx

        $sequence_36 = { b901000000 83f87f 7609 c1e807 41 }
            // n = 5, score = 900
            //   b901000000           | dec                 eax
            //   83f87f               | mov                 ebx, eax
            //   7609                 | dec                 eax
            //   c1e807               | mov                 dword ptr [eax + 0x10], edx
            //   41                   | dec                 esp

        $sequence_37 = { 6a00 6aff 50 51 ff15???????? }
            // n = 5, score = 800
            //   6a00                 | mov                 dword ptr [ebx + 0x20], edi
            //   6aff                 | inc                 ecx
            //   50                   | push                esi
            //   51                   | dec                 eax
            //   ff15????????         |                     

        $sequence_38 = { 50 6a00 6a01 6a00 ff15???????? a3???????? }
            // n = 6, score = 800
            //   50                   | mov                 dword ptr [ebx + 0x10], ebp
            //   6a00                 | dec                 ecx
            //   6a01                 | mov                 dword ptr [ebx + 0x18], esi
            //   6a00                 | dec                 ecx
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_39 = { 50 6a00 ff75fc 6800040000 }
            // n = 4, score = 600
            //   50                   | add                 eax, 0x20
            //   6a00                 | jmp                 0x11
            //   ff75fc               | movzx               eax, ax
            //   6800040000           | imul                edx, edx, 0x1003f

        $sequence_40 = { 56 68400000f0 6a18 33f6 56 }
            // n = 5, score = 600
            //   56                   | push                ebx
            //   68400000f0           | push                0
            //   6a18                 | push                0
            //   33f6                 | push                dword ptr [ebp + 8]
            //   56                   | push                ebx

        $sequence_41 = { ff75fc 6800040000 6a00 6a00 6a00 }
            // n = 5, score = 600
            //   ff75fc               | mov                 dword ptr [ebp - 0x14], ecx
            //   6800040000           | mov                 dword ptr [ebp - 0x18], edx
            //   6a00                 | mov                 dword ptr [ebp - 0x1c], esi
            //   6a00                 | mov                 ebp, esp
            //   6a00                 | push                esi

        $sequence_42 = { 53 56 8bf1 bb00c34c84 }
            // n = 4, score = 600
            //   53                   | push                ecx
            //   56                   | push                eax
            //   8bf1                 | push                0
            //   bb00c34c84           | push                1

        $sequence_43 = { 50 56 6800800000 6a6a }
            // n = 4, score = 600
            //   50                   | push                eax
            //   56                   | mov                 edi, dword ptr [ebp + 8]
            //   6800800000           | cmp                 esi, 0
            //   6a6a                 | mov                 dword ptr [ebp - 0x10], eax

        $sequence_44 = { 008b45fc33d2 00b871800780 00558b ec 8b450c 00558b ec }
            // n = 7, score = 500
            //   008b45fc33d2         | jle                 0xb
            //   00b871800780         | mov                 byte ptr [ecx], 0x58
            //   00558b               | jle                 0x15
            //   ec                   | cmp                 al, 0x61
            //   8b450c               | jl                  0xa
            //   00558b               | cmp                 al, 0x7a
            //   ec                   | jle                 0x15

        $sequence_45 = { 6a03 6a00 6a00 ff7508 53 50 }
            // n = 6, score = 500
            //   6a03                 | xor                 ecx, ecx
            //   6a00                 | mov                 edx, esp
            //   6a00                 | xor                 esi, esi
            //   ff7508               | mov                 dword ptr [edx + 0xc], esi
            //   53                   | mov                 edx, esp
            //   50                   | xor                 esi, esi

        $sequence_46 = { 83ec10 53 6a00 8d45fc }
            // n = 4, score = 500
            //   83ec10               | mov                 eax, dword ptr [esp + 0x44]
            //   53                   | cmp                 ecx, 0xfc0
            //   6a00                 | mov                 ecx, dword ptr [esp + 0x7c]
            //   8d45fc               | mov                 dword ptr [esp + 0x78], ebp

        $sequence_47 = { 51 ff75f8 50 6a03 6a30 }
            // n = 5, score = 500
            //   51                   | jmp                 0xd
            //   ff75f8               | movzx               eax, ax
            //   50                   | imul                edx, edx, 0x1003f
            //   6a03                 | lea                 ebx, [eax + 1]
            //   6a30                 | test                bl, 0xf

        $sequence_48 = { 01ca 89d6 83c60c 8b7df4 8b4c0f0c }
            // n = 5, score = 500
            //   01ca                 | cmp                 al, 0x41
            //   89d6                 | jl                  0x12
            //   83c60c               | cmp                 al, 0x30
            //   8b7df4               | jl                  8
            //   8b4c0f0c             | cmp                 al, 0x39

        $sequence_49 = { 01f1 8b7db4 11fa 8908 }
            // n = 4, score = 500
            //   01f1                 | cmp                 al, 0x61
            //   8b7db4               | jl                  0xc
            //   11fa                 | cmp                 al, 0x7a
            //   8908                 | jle                 0xd

        $sequence_50 = { 55 89e5 648b0d18000000 8b4130 83b8a400000006 0f92c2 80e201 }
            // n = 7, score = 500
            //   55                   | cmp                 al, 0x41
            //   89e5                 | jl                  0xa
            //   648b0d18000000       | cmp                 al, 0x5a
            //   8b4130               | jle                 0xd
            //   83b8a400000006       | mov                 byte ptr [ecx], 0x58
            //   0f92c2               | inc                 ecx
            //   80e201               | jl                  6

        $sequence_51 = { 8b7d08 83fe00 8945f0 894dec 8955e8 8975e4 }
            // n = 6, score = 500
            //   8b7d08               | cmp                 dword ptr [ebx], eax
            //   83fe00               | pop                 edi
            //   8945f0               | pop                 esi
            //   894dec               | setne               al
            //   8955e8               | pop                 ebx
            //   8975e4               | mov                 esp, ebp

        $sequence_52 = { 55 8bec 83ec08 56 57 8bf1 33ff }
            // n = 7, score = 500
            //   55                   | mov                 ebx, eax
            //   8bec                 | add                 ebx, 0x3c
            //   83ec08               | mov                 edx, esp
            //   56                   | xor                 esi, esi
            //   57                   | mov                 dword ptr [edx + 0xc], esi
            //   8bf1                 | mov                 dword ptr [edx + 8], esi
            //   33ff                 | xor                 ecx, ecx

        $sequence_53 = { 8bf1 bb00c34c84 57 33ff }
            // n = 4, score = 500
            //   8bf1                 | mov                 dword ptr [edx + 0xc], esi
            //   bb00c34c84           | mov                 dword ptr [edx + 8], esi
            //   57                   | mov                 dword ptr [edx + 4], esi
            //   33ff                 | xor                 esi, esi

        $sequence_54 = { 8b466c 5f 5e 5b 8be5 5d }
            // n = 6, score = 500
            //   8b466c               | push                0
            //   5f                   | push                0x104
            //   5e                   | push                edi
            //   5b                   | add                 esp, 0x14
            //   8be5                 | mov                 esi, dword ptr [eax + 0x20]
            //   5d                   | mov                 edi, dword ptr [eax + 0x40]

        $sequence_55 = { 56 8b4510 8b4d0c 8b5508 befbffffff c600e8 }
            // n = 6, score = 500
            //   56                   | cmp                 al, 0x5a
            //   8b4510               | jle                 0xd
            //   8b4d0c               | mov                 byte ptr [ecx], 0x58
            //   8b5508               | jl                  6
            //   befbffffff           | cmp                 al, 0x39
            //   c600e8               | jle                 0x17

        $sequence_56 = { 8b7020 8b7840 89c3 83c33c }
            // n = 4, score = 300
            //   8b7020               | cmp                 eax, 0x7f
            //   8b7840               | mov                 ecx, 1
            //   89c3                 | cmp                 eax, 0x7f
            //   83c33c               | jbe                 0x1c

        $sequence_57 = { 33d2 c605????????00 0fb6d8 e8???????? 0fb6c3 }
            // n = 5, score = 200
            //   33d2                 | cmp                 al, 0x41
            //   c605????????00       |                     
            //   0fb6d8               | jl                  0xe
            //   e8????????           |                     
            //   0fb6c3               | jl                  6

        $sequence_58 = { 89e2 31f6 89720c 897208 }
            // n = 4, score = 200
            //   89e2                 | shr                 eax, 7
            //   31f6                 | mov                 ecx, 1
            //   89720c               | cmp                 eax, 0x7f
            //   897208               | jbe                 0x29

        $sequence_59 = { 8bf8 e8???????? eb04 8b7c2430 }
            // n = 4, score = 200
            //   8bf8                 | cmp                 al, 0x41
            //   e8????????           |                     
            //   eb04                 | jl                  0xc
            //   8b7c2430             | cmp                 al, 0x5a

        $sequence_60 = { ff15???????? 83f803 7405 83f802 751e }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   83f803               | jl                  6
            //   7405                 | cmp                 al, 0x7a
            //   83f802               | jle                 0xf
            //   751e                 | cmp                 al, 0x41

        $sequence_61 = { 743e 8b5c2430 85db 741d }
            // n = 4, score = 200
            //   743e                 | pop                 esi
            //   8b5c2430             | setne               al
            //   85db                 | pop                 ebx
            //   741d                 | mov                 esp, ebp

        $sequence_62 = { 84c0 7519 33c9 0f1f4000 }
            // n = 4, score = 200
            //   84c0                 | cmp                 al, 0x61
            //   7519                 | jl                  6
            //   33c9                 | cmp                 al, 0x7a
            //   0f1f4000             | jle                 0x11

        $sequence_63 = { 8bfe e8???????? 8bd8 85db 746f 8b45f8 }
            // n = 6, score = 100
            //   8bfe                 | mov                 byte ptr [ecx], 0x58
            //   e8????????           |                     
            //   8bd8                 | inc                 ecx
            //   85db                 | cmp                 byte ptr [ecx], 0
            //   746f                 | jne                 0xffffffe8
            //   8b45f8               | jl                  6

        $sequence_64 = { 89e5 56 83e4f8 81ecc8000000 8b4508 f20f1005???????? }
            // n = 6, score = 100
            //   89e5                 | push                0
            //   56                   | push                -1
            //   83e4f8               | push                eax
            //   81ecc8000000         | push                ecx
            //   8b4508               | push                esi
            //   f20f1005????????     |                     

        $sequence_65 = { 740a ff15???????? 89442408 8b442444 890424 e8???????? 8b442444 }
            // n = 7, score = 100
            //   740a                 | test                al, al
            //   ff15????????         |                     
            //   89442408             | jne                 0xfffffff4
            //   8b442444             | jmp                 7
            //   890424               | mov                 byte ptr [ecx], 0
            //   e8????????           |                     
            //   8b442444             | shr                 eax, 7

        $sequence_66 = { ff15???????? 48 8d1585330000 48 8d4c2420 ff15???????? 48 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   48                   | cmp                 al, 0x5a
            //   8d1585330000         | jle                 7
            //   48                   | mov                 byte ptr [ecx], 0x58
            //   8d4c2420             | inc                 ecx
            //   ff15????????         |                     
            //   48                   | cmp                 byte ptr [ecx], 0

        $sequence_67 = { 890c24 c744240400000000 8954241c e8???????? 8d0dda30d800 }
            // n = 5, score = 100
            //   890c24               | cmp                 esi, edi
            //   c744240400000000     | jb                  0xffffffef
            //   8954241c             | push                edx
            //   e8????????           |                     
            //   8d0dda30d800         | push                edx

        $sequence_68 = { 48 8bc8 48 8bd8 e8???????? 48 8d154d1f0000 }
            // n = 7, score = 100
            //   48                   | jle                 5
            //   8bc8                 | mov                 byte ptr [ecx], 0x58
            //   48                   | inc                 ecx
            //   8bd8                 | cmp                 byte ptr [ecx], 0
            //   e8????????           |                     
            //   48                   | cmp                 al, 0x5a
            //   8d154d1f0000         | jle                 5

        $sequence_69 = { 498bca 4d8bc1 e8???????? 0fb6d8 4885ff }
            // n = 5, score = 100
            //   498bca               | test                eax, eax
            //   4d8bc1               | je                  0x51
            //   e8????????           |                     
            //   0fb6d8               | test                al, al
            //   4885ff               | jne                 0x1b

        $sequence_70 = { 488bf9 48894810 4c8d4008 488d4810 488d15e70f0000 }
            // n = 5, score = 100
            //   488bf9               | xor                 ecx, ecx
            //   48894810             | nop                 dword ptr [eax]
            //   4c8d4008             | xor                 edx, edx
            //   488d4810             | movzx               ebx, al
            //   488d15e70f0000       | movzx               eax, bl

        $sequence_71 = { 81f9c00f0000 8b4c247c 896c2478 89442474 89542470 }
            // n = 5, score = 100
            //   81f9c00f0000         | inc                 edx
            //   8b4c247c             | cmp                 eax, 0x7f
            //   896c2478             | ja                  0xfffffffd
            //   89442474             | jns                 9
            //   89542470             | add                 ecx, 7

        $sequence_72 = { 890424 c744240400040000 c744240802000000 8954240c 8b54246c }
            // n = 5, score = 100
            //   890424               | ja                  0xfffffffd
            //   c744240400040000     | shr                 eax, 7
            //   c744240802000000     | inc                 esi
            //   8954240c             | cmp                 eax, 0x7f
            //   8b54246c             | ja                  0xfffffffd

        $sequence_73 = { f20f10442450 8b442444 8b4838 8b5034 891424 894c2404 }
            // n = 6, score = 100
            //   f20f10442450         | mov                 edi, eax
            //   8b442444             | test                edi, edi
            //   8b4838               | je                  0x40
            //   8b5034               | shr                 eax, 7
            //   891424               | inc                 ecx
            //   894c2404             | cmp                 eax, 0x7f

        $sequence_74 = { e8???????? 4c8bf0 e8???????? 488d1547380000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   4c8bf0               | cmp                 eax, 2
            //   e8????????           |                     
            //   488d1547380000       | jne                 0x28

    condition:
        7 of them and filesize &lt; 733184
}rule win_zeus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.zeus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb58 833f00 7651 8b5f08 }
            // n = 4, score = 700
            //   eb58                 | jmp                 0x5a
            //   833f00               | cmp                 dword ptr [edi], 0
            //   7651                 | jbe                 0x53
            //   8b5f08               | mov                 ebx, dword ptr [edi + 8]

        $sequence_1 = { e8???????? 8b7dfc 8bf0 3bfb }
            // n = 4, score = 600
            //   e8????????           |                     
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8bf0                 | mov                 esi, eax
            //   3bfb                 | cmp                 edi, ebx

        $sequence_2 = { fec0 c21400 8b4c2414 85c9 7504 }
            // n = 5, score = 600
            //   fec0                 | inc                 al
            //   c21400               | ret                 0x14
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   85c9                 | test                ecx, ecx
            //   7504                 | jne                 6

        $sequence_3 = { fe45ff 807dff04 72c3 8b5df0 eb69 0fb645ff }
            // n = 6, score = 600
            //   fe45ff               | inc                 byte ptr [ebp - 1]
            //   807dff04             | cmp                 byte ptr [ebp - 1], 4
            //   72c3                 | jb                  0xffffffc5
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   eb69                 | jmp                 0x6b
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]

        $sequence_4 = { e8???????? 8a45ff 33c9 84c0 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   8a45ff               | mov                 al, byte ptr [ebp - 1]
            //   33c9                 | xor                 ecx, ecx
            //   84c0                 | test                al, al

        $sequence_5 = { ff75fc 8d45fc 56 50 }
            // n = 4, score = 600
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_6 = { ff15???????? 83cbff 8906 3bc3 0f8432010000 8d4c2420 }
            // n = 6, score = 600
            //   ff15????????         |                     
            //   83cbff               | or                  ebx, 0xffffffff
            //   8906                 | mov                 dword ptr [esi], eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f8432010000         | je                  0x138
            //   8d4c2420             | lea                 ecx, [esp + 0x20]

        $sequence_7 = { fec0 c9 c3 6a1c }
            // n = 4, score = 600
            //   fec0                 | inc                 al
            //   c9                   | leave               
            //   c3                   | ret                 
            //   6a1c                 | push                0x1c

        $sequence_8 = { 8bf3 6810270000 ff35???????? ff15???????? }
            // n = 4, score = 500
            //   8bf3                 | mov                 esi, ebx
            //   6810270000           | push                0x2710
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_9 = { 891d???????? 891d???????? ffd6 68???????? }
            // n = 4, score = 500
            //   891d????????         |                     
            //   891d????????         |                     
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_10 = { e8???????? 84c0 7442 6a10 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7442                 | je                  0x44
            //   6a10                 | push                0x10

        $sequence_11 = { 8d8db0fdffff e8???????? 8ad8 84db }
            // n = 4, score = 400
            //   8d8db0fdffff         | lea                 ecx, [ebp - 0x250]
            //   e8????????           |                     
            //   8ad8                 | mov                 bl, al
            //   84db                 | test                bl, bl

        $sequence_12 = { c20400 55 8bec f6451802 }
            // n = 4, score = 300
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   f6451802             | test                byte ptr [ebp + 0x18], 2

        $sequence_13 = { 5e 8ac3 5b c20800 55 8bec 83e4f8 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl
            //   5b                   | pop                 ebx
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8

        $sequence_14 = { 7506 b364 6a14 eb18 81fb5a5c4156 }
            // n = 5, score = 200
            //   7506                 | jne                 8
            //   b364                 | mov                 bl, 0x64
            //   6a14                 | push                0x14
            //   eb18                 | jmp                 0x1a
            //   81fb5a5c4156         | cmp                 ebx, 0x56415c5a

        $sequence_15 = { 83c8fe 40 ff75f4 f7d8 }
            // n = 4, score = 200
            //   83c8fe               | or                  eax, 0xfffffffe
            //   40                   | inc                 eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   f7d8                 | neg                 eax

        $sequence_16 = { 81fb45415356 0f85b2000000 b365 6a15 }
            // n = 4, score = 200
            //   81fb45415356         | cmp                 ebx, 0x56534145
            //   0f85b2000000         | jne                 0xb8
            //   b365                 | mov                 bl, 0x65
            //   6a15                 | push                0x15

        $sequence_17 = { 6813270000 6a04 5b 8bc6 c745f809080002 e8???????? 8ad8 }
            // n = 7, score = 200
            //   6813270000           | push                0x2713
            //   6a04                 | push                4
            //   5b                   | pop                 ebx
            //   8bc6                 | mov                 eax, esi
            //   c745f809080002       | mov                 dword ptr [ebp - 8], 0x2000809
            //   e8????????           |                     
            //   8ad8                 | mov                 bl, al

        $sequence_18 = { 740b 3d59495351 0f85ca000000 807b0420 0f85c0000000 33c0 83c6fb }
            // n = 7, score = 200
            //   740b                 | je                  0xd
            //   3d59495351           | cmp                 eax, 0x51534959
            //   0f85ca000000         | jne                 0xd0
            //   807b0420             | cmp                 byte ptr [ebx + 4], 0x20
            //   0f85c0000000         | jne                 0xc6
            //   33c0                 | xor                 eax, eax
            //   83c6fb               | add                 esi, -5

        $sequence_19 = { 6809080002 8bc6 50 8d45fc 50 e8???????? }
            // n = 6, score = 200
            //   6809080002           | push                0x2000809
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_20 = { 8d470c 50 c707000e0000 c7470809080002 e8???????? }
            // n = 5, score = 200
            //   8d470c               | lea                 eax, [edi + 0xc]
            //   50                   | push                eax
            //   c707000e0000         | mov                 dword ptr [edi], 0xe00
            //   c7470809080002       | mov                 dword ptr [edi + 8], 0x2000809
            //   e8????????           |                     

        $sequence_21 = { ff35???????? e8???????? 5f 5e 8ac3 5b }
            // n = 6, score = 200
            //   ff35????????         |                     
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl
            //   5b                   | pop                 ebx

        $sequence_22 = { b809080002 3945f4 7713 807d0801 0f8598000000 }
            // n = 5, score = 200
            //   b809080002           | mov                 eax, 0x2000809
            //   3945f4               | cmp                 dword ptr [ebp - 0xc], eax
            //   7713                 | ja                  0x15
            //   807d0801             | cmp                 byte ptr [ebp + 8], 1
            //   0f8598000000         | jne                 0x9e

        $sequence_23 = { eb18 81fb5a5c4156 740c 81fb45415356 }
            // n = 4, score = 200
            //   eb18                 | jmp                 0x1a
            //   81fb5a5c4156         | cmp                 ebx, 0x56415c5a
            //   740c                 | je                  0xe
            //   81fb45415356         | cmp                 ebx, 0x56534145

    condition:
        7 of them and filesize &lt; 319488
}rule win_cerber_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cerber."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cerber"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 837d1000 6a20 8db41848020000 59 f3a5 }
            // n = 5, score = 1200
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   6a20                 | push                0x20
            //   8db41848020000       | lea                 esi, [eax + ebx + 0x248]
            //   59                   | pop                 ecx
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_1 = { 6a20 5b 3bcb 725c 8bc1 }
            // n = 5, score = 1200
            //   6a20                 | push                0x20
            //   5b                   | pop                 ebx
            //   3bcb                 | cmp                 ecx, ebx
            //   725c                 | jb                  0x5e
            //   8bc1                 | mov                 eax, ecx

        $sequence_2 = { 7424 8bf9 2bfa 8d3cbe 49 83ef04 897d10 }
            // n = 7, score = 1200
            //   7424                 | je                  0x26
            //   8bf9                 | mov                 edi, ecx
            //   2bfa                 | sub                 edi, edx
            //   8d3cbe               | lea                 edi, [esi + edi*4]
            //   49                   | dec                 ecx
            //   83ef04               | sub                 edi, 4
            //   897d10               | mov                 dword ptr [ebp + 0x10], edi

        $sequence_3 = { 41 894df8 83f920 72f0 d3650c }
            // n = 5, score = 1200
            //   41                   | inc                 ecx
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   83f920               | cmp                 ecx, 0x20
            //   72f0                 | jb                  0xfffffff2
            //   d3650c               | shl                 dword ptr [ebp + 0xc], cl

        $sequence_4 = { 41 894df0 bb80000000 85ff 7e1a 895dfc 297dfc }
            // n = 7, score = 1200
            //   41                   | inc                 ecx
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   bb80000000           | mov                 ebx, 0x80
            //   85ff                 | test                edi, edi
            //   7e1a                 | jle                 0x1c
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   297dfc               | sub                 dword ptr [ebp - 4], edi

        $sequence_5 = { 837d0c00 7507 6a0d e9???????? ff7528 8d8534fdffff 53 }
            // n = 7, score = 1200
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7507                 | jne                 9
            //   6a0d                 | push                0xd
            //   e9????????           |                     
            //   ff7528               | push                dword ptr [ebp + 0x28]
            //   8d8534fdffff         | lea                 eax, [ebp - 0x2cc]
            //   53                   | push                ebx

        $sequence_6 = { 7422 83f801 750b 4a b800000080 83e904 }
            // n = 6, score = 1200
            //   7422                 | je                  0x24
            //   83f801               | cmp                 eax, 1
            //   750b                 | jne                 0xd
            //   4a                   | dec                 edx
            //   b800000080           | mov                 eax, 0x80000000
            //   83e904               | sub                 ecx, 4

        $sequence_7 = { 7425 ff7528 53 ff7520 }
            // n = 4, score = 1200
            //   7425                 | je                  0x27
            //   ff7528               | push                dword ptr [ebp + 0x28]
            //   53                   | push                ebx
            //   ff7520               | push                dword ptr [ebp + 0x20]

    condition:
        7 of them and filesize &lt; 573440
}rule win_tofsee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.tofsee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"


    strings:
        $sequence_0 = { 46 84c0 75f9 2bf1 f60304 7474 e8???????? }
            // n = 7, score = 400
            //   46                   | inc                 esi
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bf1                 | sub                 esi, ecx
            //   f60304               | test                byte ptr [ebx], 4
            //   7474                 | je                  0x76
            //   e8????????           |                     

        $sequence_1 = { eb0a c705????????2c010000 53 e8???????? 2b05???????? 59 3bc5 }
            // n = 7, score = 400
            //   eb0a                 | jmp                 0xc
            //   c705????????2c010000     |     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   2b05????????         |                     
            //   59                   | pop                 ecx
            //   3bc5                 | cmp                 eax, ebp

        $sequence_2 = { 41 85c0 88540ddb 75f0 8b750c 8bc1 49 }
            // n = 7, score = 400
            //   41                   | inc                 ecx
            //   85c0                 | test                eax, eax
            //   88540ddb             | mov                 byte ptr [ebp + ecx - 0x25], dl
            //   75f0                 | jne                 0xfffffff2
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8bc1                 | mov                 eax, ecx
            //   49                   | dec                 ecx

        $sequence_3 = { 83c8ff c3 1bc0 f7d8 c3 8b4c2408 }
            // n = 6, score = 400
            //   83c8ff               | or                  eax, 0xffffffff
            //   c3                   | ret                 
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   c3                   | ret                 
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]

        $sequence_4 = { 66895806 a1???????? 66895808 a1???????? 6689580a 8b15???????? }
            // n = 6, score = 400
            //   66895806             | mov                 word ptr [eax + 6], bx
            //   a1????????           |                     
            //   66895808             | mov                 word ptr [eax + 8], bx
            //   a1????????           |                     
            //   6689580a             | mov                 word ptr [eax + 0xa], bx
            //   8b15????????         |                     

        $sequence_5 = { 837d0c03 7510 80781000 0f8434020000 56 e9???????? 8b4f14 }
            // n = 7, score = 400
            //   837d0c03             | cmp                 dword ptr [ebp + 0xc], 3
            //   7510                 | jne                 0x12
            //   80781000             | cmp                 byte ptr [eax + 0x10], 0
            //   0f8434020000         | je                  0x23a
            //   56                   | push                esi
            //   e9????????           |                     
            //   8b4f14               | mov                 ecx, dword ptr [edi + 0x14]

        $sequence_6 = { eb04 834e1401 ffd7 a3???????? ffd7 bde8030000 33d2 }
            // n = 7, score = 400
            //   eb04                 | jmp                 6
            //   834e1401             | or                  dword ptr [esi + 0x14], 1
            //   ffd7                 | call                edi
            //   a3????????           |                     
            //   ffd7                 | call                edi
            //   bde8030000           | mov                 ebp, 0x3e8
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 5d f7fd 03da 47 3bf9 7ce5 5d }
            // n = 7, score = 400
            //   5d                   | pop                 ebp
            //   f7fd                 | idiv                ebp
            //   03da                 | add                 ebx, edx
            //   47                   | inc                 edi
            //   3bf9                 | cmp                 edi, ecx
            //   7ce5                 | jl                  0xffffffe7
            //   5d                   | pop                 ebp

        $sequence_8 = { 50 ff15???????? ff742424 ff15???????? 8b442418 eb0d }
            // n = 6, score = 400
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   ff15????????         |                     
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   eb0d                 | jmp                 0xf

        $sequence_9 = { 7428 8b00 85c0 7413 8b10 6a01 8bc8 }
            // n = 7, score = 400
            //   7428                 | je                  0x2a
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   6a01                 | push                1
            //   8bc8                 | mov                 ecx, eax

    condition:
        7 of them and filesize &lt; 147456
}