rule Generic_v2: malicious
{
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "28.09.2019"
    strings:
        $s1 = "$GLOBALS["
        $s2 = "]=Array(base64_decode("
        $s3 = "$_POST[\"to_address\"]"
	$s4 = "FilesMan"
	$s5 = "getDomainFromEmail"
	$s6 = "back_connect"
	$s7 = "function error_404"
	$s8 = "DDoS Perl IrcBot"
	$s9 = "SBCID_BOT_VERSION"
	$s10 = "wp__theme_icon"
	$s11 = "md5_brute"
	
	// funcs
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
         any of ($s*) or 2 of ($g*)
}
