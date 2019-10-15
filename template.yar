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
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = ""
    strings:
        $ = ""
        $ = ""
        $ = ""
        $ = ""
    condition:
        all of them
}
