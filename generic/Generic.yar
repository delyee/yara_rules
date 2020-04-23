private rule EvilFuncs
 {
     strings:
         $ = "base64_decode(" nocase
         $ = "eval(" nocase
     condition:
         all of them
 }

rule DangerFuncs: generic
 {
     strings:
         $ = "str_rot13(" nocase
         $ = "error_reporting(" nocase
         $ = "chr(" nocase
         $ = "strrev(" nocase
         $ = "preg_replace(" nocase
         $ = "assert(" nocase
         $ = "stripslashes(" nocase
         $ = "ini_set(" nocase
         $ = "function_exists(" nocase 
         $ = "stripslashes(" nocase
     condition:
         EvilFuncs and 2 of them
 }

// private rule PHPVars
// {
//     strings:
//         $ = "$GLOBALS["
//         $ = "]=Array"
//         $ = "$_POST"
//         $ = "$_GET"
//         $ = "$_SESSION"
//         $ = "$_SERVER"
//         $ = "$_REQUEST"
//         $ = "$_FILES"
//         $ = "$_ENV"
//         $ = "$_COOKIE"
//     condition:
//          any of them
// }

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
        