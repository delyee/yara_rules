/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule sample_74343f47df504bbe9065a75aa41a5817: tr inj mjk
{
    meta:
        description = ""
        author = "delyee"
        date = "14.12.2019"
        sha256sum = "54c010758b76d0ca9fd8e513742536838eb2cb9a9047b0a0801e952fff2d1214"
    strings:
        $ = "$mjk = $fkh('', $lbk($dqi(\"nw\", \"\", $ak.$qa.$di.$ip))); $mjk();"
        $ = "$dqi = str_replace(\"x\",\"\",\"xstrx_xrxeplxaxcxe\");"
        $ = "$mjk();"
    condition:
        all of them
}
