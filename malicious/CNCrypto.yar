rule CNCrypto_Obfuscated: malicious obfuscated
{
  meta:
      description = "http://www.cn-software.com/en/cncrypto/"
      author = "delyee"
      date = "07.08.2019"
      example = "<?php $_0OO=__FILE__;$_O0O=6;$_OOO=9074;eval(base64_decode(\"JF8wMDBPPUFycmF5KCk7Zm9yICgkX"
  strings:
      $e1 = /\$[_0O]{4}\=__FILE__/
      $e2 = /\$[_0O]{4}\=[0-9]{1,4}/
      $s1 = "eval(base64_decode("
      $s2 = "Encrypted by CNCrypto"
  condition:
      $s1 and ($e1 and #e2 == 2) and $s2 or $s1 and $s2
}
