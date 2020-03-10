private rule Generic_funcs
{
    meta:
        description = "funcs for Generic rule"
        author = "delyee"
        date = "10.03.2020"
    strings:
        $g1 = "base64_decode"
		$g2 = "chr"
		$g3 = "eval"
		$g4 = "strrev"
		$g5 = "error_reporting"
		$g6 = "ini_set"
		$g7 = "urldecode"
		$g8 = "gzinflate"
		$g9 = "gzuncompress"
		$g10 = "function_exists"
		$g11 = "define"
		$g12 = "stripslashes"
		$g13 = "str_rot13"
		$g14 = "gzipinflate"
		$g15 = "basename"
		$g16 = "gzdecode"
    condition:
        2 of them
}
