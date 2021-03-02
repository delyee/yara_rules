private rule EvilFuncs
 {
     strings:
         $ = "base64_decode" nocase fullword
         $ = "eval" nocase fullword
         $ = { 69 6e 63 6c 75 64 65 20 27 68 74 74 (70 | 70 73) 3a 2f 2f }
         $ = "php://input"
     condition:
         any of them
 }

/*
private rule Vars
{
    strings:
        $ = "$GLOBALS["
        $ = "]=Array"
        $ = "$_POST"
        $ = "$_GET"
        $ = "$_SESSION"
        $ = "$_SERVER"
        $ = "$_REQUEST"
        $ = "$_FILES"
        $ = "$_ENV"
        $ = "$_COOKIE"
    condition:
         any of them
}
*/

private rule DangerFuncs: generic
 {
     strings:
        //$ = "" nocase fullword
        $ = "ob_get_contents" nocase fullword
        $ = "ob_end_flush" nocase fullword
        $ = "ob_end_clean" nocase fullword
        $ = "ob_gzhandler" nocase fullword
        $ = "file_get_contents" nocase fullword
        $ = "str_replace" nocase fullword
        $ = "str_rot13" nocase fullword
        $ = "error_reporting" nocase fullword
        $ = "chr" nocase fullword
        $ = "strrev" nocase fullword
        $ = "preg_replace(" nocase fullword
        $ = "assert" nocase fullword
        $ = "stripslashes" nocase fullword
        $ = "ini_set" nocase fullword
        $ = "function_exists" nocase fullword
        $ = "stripslashes" nocase fullword
        $ = "gzinflate" nocase fullword
        $ = "gzuncompress" nocase fullword
        $ = "define" nocase fullword
        $ = "gzipinflate" nocase fullword
        $ = "basename" nocase fullword
        $ = "gzdecode" nocase fullword
     condition:
         //not IsELF and 
         //(IsPHP and EvilFuncs) or (any of them and Vars)
         any of them
 }


rule Generic: EvilFuncs DangerFuncs PHPVars generic
 {
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "1.12.2020"
    condition:
        not IsELF and (IsPHP and EvilFuncs and DangerFuncs)
        // and Vars and OtherFuncs))
 }
 


        