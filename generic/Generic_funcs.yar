private rule Generic_funcs
{
    meta:
        description = "funcs for Generic rule"
        author = "delyee"
        date = "10.03.2020"
    strings:
        $ = "base64_decode"
		$ = "chr"
		$ = "eval"
		$ = "strrev"
		$ = "error_reporting"
		$ = "ini_set"
		$ = "urldecode"
		$ = "gzinflate"
		$ = "gzuncompress"
		$ = "function_exists"
		$ = "define"
		$ = "stripslashes"
		$ = "str_rot13"
		$ = "gzipinflate"
		$ = "basename"
		$ = "gzdecode"
    condition:
        2 of them
}
