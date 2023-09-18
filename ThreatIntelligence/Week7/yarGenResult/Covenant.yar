/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-07-19
   Identifier: mw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule b95781c20c5a77c56384ae5f239aff908709dd4502437801d880f7702e2da862 {
   meta:
      description = "mw - file b95781c20c5a77c56384ae5f239aff908709dd4502437801d880f7702e2da862"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-07-19"
      hash1 = "b95781c20c5a77c56384ae5f239aff908709dd4502437801d880f7702e2da862"
   strings:
      $s1 = "http://137.135.244.225:8000,http://pipelineupdates.northeurope.cloudapp.azure.com:8000" fullword wide /* score: '25.00'*/
      $s2 = "TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDEuMC4yMjI4LjAgU2FmYXJpLzUz" wide /* base64 encoded string 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36' */ /* score: '21.00'*/
      $s3 = "2zst51op.opp.exe" fullword ascii /* score: '19.00'*/
      $s4 = "ExecuteStager" fullword ascii /* score: '18.00'*/
      $s5 = "<ExecuteStager>b__3_0" fullword ascii /* score: '18.00'*/
      $s6 = "<ExecuteStager>b__3" fullword ascii /* score: '18.00'*/
      $s7 = "<ExecuteStager>b__3_1" fullword ascii /* score: '18.00'*/
      $s8 = "<ExecuteStager>b__3_2" fullword ascii /* score: '18.00'*/
      $s9 = "VXNlci1BZ2VudA==" fullword wide /* base64 encoded string 'User-Agent' */ /* score: '14.00'*/
      $s10 = "MessageTransform" fullword ascii /* score: '9.00'*/
      $s11 = "i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73" fullword wide /* score: '9.00'*/
      $s12 = "{{\"GUID\":\"{0}\",\"Type\":{1},\"Meta\":\"{2}\",\"IV\":\"{3}\",\"EncryptedMessage\":\"{4}\",\"HMAC\":\"{5}\"}}" fullword wide /* score: '9.00'*/
      $s13 = "2zst51op.opp" fullword ascii /* score: '7.00'*/
      $s14 = "CovenantCertHash" fullword ascii /* score: '7.00'*/
      $s15 = "CookieWebClient" fullword ascii /* score: '7.00'*/
      $s16 = "<CookieContainer>k__BackingField" fullword ascii /* score: '7.00'*/
      $s17 = "GruntStager" fullword ascii /* score: '7.00'*/
      $s18 = "cookies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98'*/ /* Goodware String - occured 22 times */
      $s19 = "PaddingMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s20 = "CipherMode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 54 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

