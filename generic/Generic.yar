private rule EvilFuncs
 {
     strings:
         $ = "base64_decode(" nocase fullword
         $ = "eval(" nocase fullword
         $ = { 69 6e 63 6c 75 64 65 20 27 68 74 74 (70 | 70 73) 3a 2f 2f }
         $ = "php://input"
         $ = "exec(" nocase fullword        // https://www.php.net/manual/ru/function.exec
         $ = "system(" nocase fullword      // https://www.php.net/manual/ru/function.system.php
         $ = "passthru(" nocase fullword    // https://www.php.net/manual/ru/function.passthru.php
         // $ = ""
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
        $ = "ob_get_contents(" nocase fullword      // https://www.php.net/manual/ru/function.ob-get-contents.php
        $ = "ob_end_flush(" nocase fullword         // https://www.php.net/manual/ru/function.ob-end-flush.php
        $ = "ob_end_clean(" nocase fullword         // https://www.php.net/manual/ru/function.ob-end-clean.php
        $ = "ob_gzhandler(" nocase fullword         // https://www.php.net/manual/ru/function.ob-gzhandler.php
        
        $ = "file_get_contents(" nocase fullword    // https://www.php.net/manual/ru/function.file-get-contents.php
        $ = "curl_exec(" nocase fullword            // https://www.php.net/manual/ru/function.curl-exec.php
        $ = "move_uploaded_file(" nocase fullword   // https://www.php.net/manual/ru/function.move-uploaded-file.php

        
        $ = "str_replace(" nocase fullword          // https://www.php.net/manual/ru/function.str-replace.php
        $ = "str_rot13(" nocase fullword            // https://www.php.net/manual/ru/function.str-rot13.php
        $ = "chr(" nocase fullword                  // https://www.php.net/manual/ru/function.chr
        $ = "strrev(" nocase fullword               // https://www.php.net/manual/ru/function.strrev.php
        $ = "preg_replace(" nocase fullword         // https://www.php.net/manual/ru/function.preg-replace.php
        $ = "stripslashes(" nocase fullword         // https://www.php.net/manual/ru/function.stripslashes.php


        $ = "assert(" nocase fullword               // https://www.php.net/manual/ru/function.assert.php
        $ = "assert_options(" nocase fullword       // https://www.php.net/manual/ru/function.assert-options.php
        $ = "define(" nocase fullword               // https://www.php.net/manual/ru/function.define.php

        
        $ = "ini_set(" nocase fullword              // https://www.php.net/manual/ru/function.ini-set.php
        $ = "error_reporting(" nocase fullword      // https://www.php.net/manual/ru/function.error-reporting.php

        $ = "basename(" nocase fullword             // https://www.php.net/manual/ru/function.basename.php
        
        $ = "gzinflate(" nocase fullword            // https://www.php.net/manual/ru/function.gzinflate.php
        $ = "gzuncompress(" nocase fullword         // https://www.php.net/manual/ru/function.gzuncompress.php
        $ = "gzipinflate(" nocase fullword
        $ = "gzdecode(" nocase fullword             // https://www.php.net/manual/ru/function.gzdecode.php

        $ = "create_function(" nocase fullword      // https://www.php.net/manual/ru/function.create-function.php
        $ = "function_exists(" nocase fullword      // https://www.php.net/manual/ru/function.function-exists.php

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
 


        