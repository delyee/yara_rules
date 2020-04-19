rule EddieKidiw: Encoders obfuscated malicious 
{
    meta:
        description = "Obfuscator by Eddie Kidiw, indoxploit/indosec"
        author = "delyee"
        date = "20.02.2020"
    strings:
        $title = "Obfuscator by Eddie Kidiw"
        $start = "eval(\"\x65\x76\x61\x6C\x28\x67\x7A\x69\x6E\x66\x6C\x61\x74\x65\x28\x62\x61\x73\x65\x36\x34\x5F\x64\x65\x63\x6F\x64\x65\x28"
        $end = "\x29\x29\x29\x3B"
    condition:
        $title or ($start and $end)
}
