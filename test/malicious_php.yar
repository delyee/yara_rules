/*
Пишу правило для детекта malicious контента в PHP скриптах

grep -RPn "(passthru|shell_exec|system|base64_decode|fopen|fclose|eval)" /var/www/ > /var/www/backlist.txt
--> "eval, base64_decode, str_rot13, gzinflate, gzuncompress, strrev, gzdecode"
==> "passthru, shell_exec, system, fopen, fclose"

*/

/*
rule MoreChars_malicious_php: phpshell malicious
{
  meta:
      description = "Детект большого количества \t и \n"
      author = "delyee"
      date = "07.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      $tabs = /[\n]{50}/
      $newlines = /;[\t]{10}[\w_\W\s\S\d\D](;)*\n/
  condition:
      $tabs or $newlines
}
*/
