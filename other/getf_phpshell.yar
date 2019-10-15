/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule getf_phpshell: phpshell
{
    meta:
        description = ""
        author = "delyee"
        date = "15.10.2019"
        sha256sum = "1ac95c9aff7e9babc13ea15c725df383a389cb54b39927338464ee1825d98822"
    strings:
        $ = "$_getf=file(__FILE__)"
        $ = "eval(returnmal(getmal($_getf,2),getmal($_getf,1)))"
    condition:
        all of them
}
