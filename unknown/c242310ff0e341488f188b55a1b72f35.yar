rule c242310ff0e341488f188b55a1b72f35: phpshell
{
    meta:
        description = "bloodninja"
        author = "delyee"
        date = "30.09.2019"
        sha256sum = "1e4272a6f5b190c5218b324a717bc0905e56bea5b00556fa09607ae72ac42c6a" // sha256sum shell.php
    strings:
        $ = "eval(gzuncompress(base64_decode(\"\\145\\x4e\\x6f\\61\\x76\\145\\x65\\171\\x71\\61\\x69\\172\\114\\x66\\x67\\x71\\130\\x39\\x78\\146\\x35"
    condition:
        any of them
}
