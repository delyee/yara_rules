rule MoreChars_malicious_php: phpshell malicious
{
  meta:
      description = "Детект большого количесства \t и \n"
      author = "delyee"
      date = "07.08.2019"
      example = "$O0_0__0OOO=$O__00OO0O_{28}.$O__00OO0O_{23}.$O__00OO0O_{12}.$O__00OO0O_{7}.$O__00OO0O_{5}..."
  strings:
      //$tabs = /[\n]{50}/
      $newlines = /;(\t){10,}[a-zA-Z0-9_]/
  condition:
      //$tabs or
      $newlines
}
