private rule EvilFuncs
 {
     strings:
         $ = "base64_decode" nocase fullword
         $ = "eval" nocase fullword
     condition:
         all of them
 }


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

rule DangerFuncs: generic
 {
     strings:
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
     condition:
         IsPHP and EvilFuncs and 2 of them and Vars and not IsELF
 }


// rule Generic: EvilFuncs DangerFuncs PHPVars generic
// {
//     meta:
//         description = "Неизвестная версия"
//         author = "delyee"
//         date = "28.09.2019"
//     condition:
//      DefaultShell or DangerFuncs //and PHPVars
// }


/* 
private rule other_funcs
{
    meta:
        description = "funcs for Generic rule"
        author = "delyee"
        date = "10.03.2020"
    strings:
        $ = "gzinflate"
        $ = "gzuncompress"
        $ = "define"
        $ = "stripslashes"
        $ = "gzipinflate"
        $ = "basename"
        $ = "gzdecode"
    condition:
        any of them
*/
        