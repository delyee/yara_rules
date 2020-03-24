private rule Generic_funcs
{
    meta:
        description = "funcs for Generic rule"
        author = "delyee"
        date = "10.03.2020"
    strings:
        $base64_decode = "base64_decode" nocase
        $eval = "eval" nocase
        $ = "urldecode"
        $ = "str_rot13"
		$ = "chr"
		$ = "strrev"
		$ = "error_reporting"
		$ = "ini_set"
		$ = "gzinflate"
		$ = "gzuncompress"
		$ = "function_exists"
		$ = "define"
		$ = "stripslashes"
		$ = "gzipinflate"
		$ = "basename"
		$ = "gzdecode"
    condition:
    	$eval and ($base64_decode or 2 of them)
}
