// idiot: warning: $e2 in rule CNCrypto_Obfuscated is slowing down scanning
/* results: 242
real  0m6.409s
user  0m41.700s
sys 0m2.240s
*/

rule CNCrypto_Obfuscated: malicious obfuscated
{
  meta:
      description = "http://www.cn-software.com/en/cncrypto/"
      author = "delyee"
      date = "07.08.2019"
      example = "<?php $_0OO=__FILE__;$_O0O=6;$_OOO=9074;eval(base64_decode(\"JF8wMDBPPUFycmF5KCk7Zm9yICgkX"
  strings:
      // $e1 = /\$[_0O]{4}\=__FILE__/
      // $e2 = /\$[_0O]{4}\=[0-9]{1,4}/
      $s1 = { 65 76 61 6c 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 }
      $s2 = { 45 6e 63 72 79 70 74 65 64 20 62 79 20 43 4e 43 72 79 70 74 6f }
      $hex_e1 = { 24 (4f | 5f | 30) (4f | 5f | 30) [1-6] 3d 5f 5f 46 49 4c 45 5f 5f 3b}
      $hex_e2 = { (4f | 5f | 30) 3d (3? | 3? 3? 3? 3?) 3b }
      // 3A-3F useless
      // $hex_e2 = { 3d (3? | 3? 3? | 3? 3? 3? | 3? 3? 3? 3?) 3b }
      // $hex_e2 = { 24 (4f | 5f | 30) (4f | 5f | 30) [1-6] 3d [1-4] 3b }
  condition:
      $s1 and (all of ($hex_e1,$hex_e2) or $s2)
      //all of ($s1,$hex_e1,$hex_e2) or all of ($s1,$s2)
      // for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
}
