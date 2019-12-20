/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule rulename: tag
{
    meta:
        description = "RSFirewall! 1.4.0"
        author = "delyee"
        date = "21.12.2019"
        sha256sum = ""
    strings:
        $ = "if (strpos($contents, 'eval(gzinflate(base64_decode') !== false)"
        $ = "@package RSFirewall!"
        $ = "function getJUMIVulnerable()"
    condition:
        all of them
}
