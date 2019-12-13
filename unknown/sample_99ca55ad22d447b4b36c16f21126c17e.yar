/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule sample_99ca55ad22d447b4b36c16f21126c17e: tr inj mjk v2
{
    meta:
        description = ""
        author = "delyee"
        date = "14.12.2019"
        sha256sum = "1c27a38537e44aea98db227207d904eefb868d0a82034b53be7b76f535371dc6"
    strings:
        $ = "$avj(\"k\",\"\",\"crkekatkek_kfkukncktkikon\");"
        $ = "$qu = $avj(\"i\", \"\", \"ibiaisie6i4i_dieicoide\");"
    condition:
        all of them
}
