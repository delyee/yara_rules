rule Hex_Obfuscated: malicious obfuscated
{
    meta:
        description = "hex encoded"
        author = "delyee"
        date = "14.02.2020"
    strings:
        $eval = "\\x65\\x76\\x61\\x6C"
        $gzinflate = "\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65"
        $base64_decode = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5F\\x64\\x65\\x63\\x6F\\x64\\x65"
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53"
        //todo: eVaL, EvAl, evAL, ...
    condition:
        any of them
}
