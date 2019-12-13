/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule sample_3b341cbb3cdc4318877bb9408eb0f2fa: tr inj indexaQ0O010O
{
    meta:
        description = ""
        author = "delyee"
        date = "14.12.2019"
        sha256sum = "bfa990b6abd03ee918101285f13673c1c751ce0a507558024b814f3007ced94b"
    strings:
        $ = "$Remote_server = \"https://dm.ymzdrp.cn\""
        $ = "$context = stream_context_create($opts);"
        $ = "$html = @file_get_contents($url, false, $context)"
    condition:
        all of them
}
