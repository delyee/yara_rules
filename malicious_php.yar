/*
Пишу правило для детекта "malicious" контента в PHP скриптах

grep -RPn "(passthru|shell_exec|system|base64_decode|fopen|fclose|eval)" /var/www/ > /var/www/backlist.txt
--> "eval, base64_decode, str_rot13, gzinflate, gzuncompress, strrev, gzdecode"
==> "passthru, shell_exec, system, fopen, fclose"

*/


rule Zero_Obfuscated_vars: phpshell malicious
{
  meta:
      description = "Детект переменных следующего вида - '$0O00_0O'"
      author = "delyee"
      date = "07.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      $strange_var = /\$[0O_]{10}\=/
  condition:
      #strange_var > 5
}

rule Eval_Statements: phpshell
{
    meta:
        description = "Obfuscated PHP eval statements"
    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/
    condition:
        all of them
}

rule FOPO_Obfuscated: phpshell malicious
{
    meta:
        description = "FOPO - Free Online PHP Obfuscator"
        readme = "https://github.com/Antelox/FOPO-PHP-Deobfuscator"
    strings:
        $ = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/
    condition:
        all of them
}

rule MoreChars_malicious_php: phpshell malicious
{
  meta:
      description = "Детект большого количесства \t и \n"
      author = "delyee"
      date = "07.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      $tabs = /[\n]{50}/
      $newlines = /;[\t]{10}[\w_\W\s\S\d\D](;)*\n/
  condition:
      $tabs or $newlines
}
