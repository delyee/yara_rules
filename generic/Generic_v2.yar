rule Generic_v2: malicious obfuscated
{
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "28.09.2019"
    strings:
        $s1 = "]=Array(base64_decode("
        $globals = "$GLOBALS["
    condition:
        $s1 or #globals > 10

}
