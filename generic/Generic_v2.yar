rule Generic_v2: malicious obfuscated
{
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "28.09.2019"
    strings:
        $s1 = "]=Array(base64_decode("
        $s2 = "define"
        $s3 = "function_exists"
        $g1 = "base64_decode"
        $globals = "$GLOBALS["
    condition:
         #globals > 10 and (1 of s*) or $g1

}
