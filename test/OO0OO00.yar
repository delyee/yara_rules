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
