// idiot: warning: $e2 in rule CNCrypto_Obfuscated is slowing down scanning
/* results: 
real  0m5.945s
user  0m37.672s
sys 0m2.108s
*/

rule CNCrypto: Encoders obfuscated malicious
{
  meta:
      description = "http://www.cn-software.com/en/cncrypto/"
      author = "delyee"
      date = "07.08.2019"
      example = "<?php $_0OO=__FILE__;$_O0O=6;$_OOO=9074;eval(base64_decode(\"JF8wMDBPPUFycmF5KCk7Zm9yICgkX"
  strings:
      $e1 = /\$[_0O]{4}\=__FILE__/
      $e2 = /\$[_0O]{4}\=[0-9]+\;/
      $s1 = "eval(base64_decode("
      $s2 = "Encrypted by CNCrypto"
  condition:
      $s2 and ($e1 and #e2 == 2) or ($s1 and $s2)
}
