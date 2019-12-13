/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule test_eval_evasion: test
{
    meta:
        description = "видел такое при разборе кода"
        author = "delyee"
        date = "14.12.2019"
    strings:
        $ = "eval/**/" nocase
    condition:
        all of them
}
