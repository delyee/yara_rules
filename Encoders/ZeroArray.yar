// данное правило существенно тормозит процесс сканирования, его нужно срочно переписать

rule ZeroArray_Obfuscated: malicious obfuscated
{
  meta:
      description = "Детект обф. переменных следующего вида - '$0O00_0O'"
      author = "delyee"
      date = "07.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      $strange_var = /\$[0O_]{10}\=/
  condition:
      #strange_var > 5
}
