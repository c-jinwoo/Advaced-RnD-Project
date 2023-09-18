/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-19
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe {
   meta:
      description = "mw - file 3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
   strings:
      $s1 = "eProcessPH" fullword ascii /* score: '15.00'*/
      $s2 = "ProcessIPH" fullword ascii /* score: '15.00'*/
      $s3 = "AppDataHPH" fullword ascii /* score: '11.00'*/
      $s4 = "C:\\UsPH" fullword ascii /* score: '10.00'*/
      $s5 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s6 = ".dllPH" fullword ascii /* score: '10.00'*/
      $s7 = "LISTENINP" fullword ascii /* score: '9.50'*/
      $s8 = "calhost" fullword ascii /* score: '9.00'*/
      $s9 = "GetProcePH" fullword ascii /* score: '9.00'*/
      $s10 = "sGetValuPH" fullword ascii /* score: '9.00'*/
      $s11 = "Gecko) CPH" fullword ascii /* score: '9.00'*/
      $s12 = "GetSysPH" fullword ascii /* score: '9.00'*/
      $s13 = "KERNEL32PH" fullword ascii /* score: '9.00'*/
      $s14 = "GetCurPH" fullword ascii /* score: '9.00'*/
      $s15 = "GetModPH" fullword ascii /* score: '9.00'*/
      $s16 = "GetLasPH" fullword ascii /* score: '9.00'*/
      $s17 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s18 = "Address P" fullword ascii /* score: '7.00'*/
      $s19 = "size %d.PH" fullword ascii /* score: '7.00'*/
      $s20 = "4 runtimPH" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f {
   meta:
      description = "mw - file d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
   strings:
      $s1 = "EL32.dllPH" fullword ascii /* score: '13.00'*/
      $s2 = "PasswordPH" fullword ascii /* score: '12.00'*/
      $s3 = "\\AppDataPH" fullword ascii /* score: '12.00'*/
      $s4 = ".com.cn|PH" fullword ascii /* score: '11.00'*/
      $s5 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s6 = "C:\\UPH" fullword ascii /* score: '10.00'*/
      $s7 = "YYYYYPA" fullword ascii /* score: '9.50'*/
      $s8 = "sGetValuPH" fullword ascii /* score: '9.00'*/
      $s9 = "GetProPH" fullword ascii /* score: '9.00'*/
      $s10 = "GetMPH" fullword ascii /* score: '9.00'*/
      $s11 = "GetCurrePH" fullword ascii /* score: '9.00'*/
      $s12 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s13 = "Address P" fullword ascii /* score: '7.00'*/
      $s14 = "size %d.PH" fullword ascii /* score: '7.00'*/
      $s15 = "4 runtimPH" fullword ascii /* score: '7.00'*/
      $s16 = " failed PH" fullword ascii /* score: '7.00'*/
      $s17 = "e failurPH" fullword ascii /* score: '7.00'*/
      $s18 = "sion %d.PH" fullword ascii /* score: '7.00'*/
      $s19 = "lLookupFPH" fullword ascii /* score: '7.00'*/
      $s20 = "astErrorPH" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_4f88738e04447344100bb9532c239032b86e71d8037ccb121e2959f37fff53cf {
   meta:
      description = "mw - file 4f88738e04447344100bb9532c239032b86e71d8037ccb121e2959f37fff53cf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "4f88738e04447344100bb9532c239032b86e71d8037ccb121e2959f37fff53cf"
   strings:
      $s1 = "SSAMAQH" fullword ascii /* score: '10.50'*/
      $s2 = "WnpG.tPH" fullword ascii /* score: '10.00'*/
      $s3 = "S+ UtiPAPI" fullword ascii /* score: '8.00'*/
      $s4 = "AWAVAUATM" fullword ascii /* score: '6.50'*/
      $s5 = "AYUQRAPAQAWL" fullword ascii /* score: '6.50'*/
      $s6 = "UGHYAQH" fullword ascii /* score: '6.50'*/
      $s7 = "RYPLAPI" fullword ascii /* score: '6.50'*/
      $s8 = "tWuGdg5" fullword ascii /* score: '5.00'*/
      $s9 = "Y%nY%E" fullword ascii /* score: '5.00'*/
      $s10 = "SPqZAPI" fullword ascii /* score: '4.00'*/
      $s11 = ".crq'`" fullword ascii /* score: '4.00'*/
      $s12 = "oQeOAVI" fullword ascii /* score: '4.00'*/
      $s13 = "owMDkovBAQI" fullword ascii /* score: '4.00'*/
      $s14 = "pPIxe)BPH" fullword ascii /* score: '4.00'*/
      $s15 = "NiFsT4QAASI" fullword ascii /* score: '4.00'*/
      $s16 = "qzAu[AUH" fullword ascii /* score: '4.00'*/
      $s17 = "jtiv0ATI" fullword ascii /* score: '4.00'*/
      $s18 = "XfZG<yAQI" fullword ascii /* score: '4.00'*/
      $s19 = "pXttjjUwASH" fullword ascii /* score: '4.00'*/
      $s20 = "Cqxz5SIfARH" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x00e8 and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe_d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9e_0 {
   meta:
      description = "mw - from files 3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe, d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe"
      hash2 = "d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
   strings:
      $s1 = "msvcrt.dPH" fullword ascii /* score: '10.00'*/
      $s2 = "sGetValuPH" fullword ascii /* score: '9.00'*/
      $s3 = "%d_%02d%PH" fullword ascii /* score: '8.00'*/
      $s4 = "Address P" fullword ascii /* score: '7.00'*/
      $s5 = "size %d.PH" fullword ascii /* score: '7.00'*/
      $s6 = "4 runtimPH" fullword ascii /* score: '7.00'*/
      $s7 = " failed PH" fullword ascii /* score: '7.00'*/
      $s8 = "e failurPH" fullword ascii /* score: '7.00'*/
      $s9 = "sion %d.PH" fullword ascii /* score: '7.00'*/
      $s10 = "AWAVAUATPH" fullword ascii /* score: '6.50'*/
      $s11 = "LJPNDBHFPH" fullword ascii /* score: '6.50'*/
      $s12 = "AVAUATWSPH" fullword ascii /* score: '6.50'*/
      $s13 = "ILONEHCBPH" fullword ascii /* score: '6.50'*/
      $s14 = "AVAUATVSPH" fullword ascii /* score: '6.50'*/
      $s15 = "AUATWSH" fullword ascii /* score: '6.50'*/
      $s16 = "AUATWVSHPH" fullword ascii /* score: '6.50'*/
      $s17 = "AVAUATSHPH" fullword ascii /* score: '6.50'*/
      $s18 = "AUATUWVSPH" fullword ascii /* score: '6.50'*/
      $s19 = "ACEGIKMOPH" fullword ascii /* score: '6.50'*/
      $s20 = "VAUATUWVPH" fullword ascii /* score: '6.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

