rule Generic_v2: malicious obfuscated
{
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "28.09.2019"
    strings:
        $globals_array = "]=Array(base64_decode("
        $globals = "$GLOBALS["
    condition:
        1 of ($globals*) and Generic_Eval

}
