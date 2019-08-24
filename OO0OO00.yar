rule Obfuscated_PHP_manyZeros: phpshell
{

  meta:
      description = "Malware vars - $0O00_0O"
      author = "delyee"
      date = "06.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      $strange_var = /\$[0O_]{10}\=/
  condition:
      #strange_var > 5

}


rule MALWARE_PHP_SHELL_StrangeVar: phpshell
{
    meta:
        description = "[MALWARE][PHP][SHELL] - $0O00_0O"
        author = "delyee"
        date = "06.08.2019"
        sha256sum = "00528ff153cb5a300cd3a9d779ec66f39a2b59e197e683d7cfdb80384edac31b" // /licey80.ru/docs/images/js/photogallery/best.php
        example = "$O__00OO0O_=base64_decode('LTQ2bnFhX2U4OWR5cmJpa2hqZnB3eGN0em1sMnNvdjdndTAzNTE=')"
    strings:
        $php = /^\<\?php/
        $debug = /\$[0O_]{10}\='1';/
    condition:
        all of them
}
